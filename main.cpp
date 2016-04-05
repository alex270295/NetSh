#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <sys/epoll.h>
#include <errno.h>
#include <cstring>
#include <csignal>
#include <fcntl.h>
#include <wait.h>
#include <sys/stat.h>

#include <fstream>
#include <map>
#include <vector>


using namespace std;

typedef char **execargs_t;

#define CHK(_res)                               \
  if (_res == -1) {                             \
    exit(EXIT_FAILURE);                         \
  }

int set_nonblock(int fd) {
    int flags;
#if defined(O_NONBLOCK)
    if (-1 == (flags = fcntl(fd, F_GETFL, 0)))
        flags = 0;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#else
    flags = 1;
    return ioctl(fd, FIONBIO, &flags);
#endif
}

int set_block(int fd) {
    int flags;
#if defined(O_NONBLOCK)
    if (-1 == (flags = fcntl(fd, F_GETFL, 0)))
        flags = 0;
    return fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
#else
    flags = 1;
    return ioctl(fd, FIONBIO, &flags);
#endif
}


void killall(vector<pid_t> &pids, sigset_t &mask) {
    for (size_t i = 0; i < pids.size(); i++) {
        if (pids[i]) {
            kill(pids[i], SIGKILL);
            waitpid(pids[i], 0, 0);
        }
    }
    sigprocmask(SIG_SETMASK, &mask, 0);
}

int runpiped(vector<execargs_t> cmds) {
    size_t n = cmds.size();
    int pipes[2 * n - 2];
    for (size_t i = 1; i < n; i++) {
        int res = pipe2(pipes + 2 * (i - 1), O_CLOEXEC);
        if (res) {
            for (int j = 1; j < i; j++) {
                close(pipes[j * 2 - 2]);
                close(pipes[j * 2 - 1]);
            }
            return -1;
        }
    }


    sigset_t mask;
    sigset_t orig_mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &mask, &orig_mask);

    vector<pid_t> pids(n);

    bool fork_failed = false;
    for (size_t i = 0; i < n && !fork_failed; i++) {
        int pid = fork();
        if (pid < 0) {
            fork_failed = 1;
        } else if (pid) {
            pids[i] = pid;
        } else {
            if (i > 0)
                dup2(pipes[i * 2 - 2], STDIN_FILENO);
            if (i < n - 1)
                dup2(pipes[i * 2 + 1], STDOUT_FILENO);
            sigprocmask(SIG_SETMASK, &orig_mask, 0);
            exit(execvp(*cmds[i], cmds[i]));
        }
    }

    for (size_t i = 1; i < n; i++) {
        close(pipes[i * 2 - 2]);
        close(pipes[i * 2 - 1]);
    }

    if (fork_failed) {
        killall(pids, orig_mask);
        return -1;
    }

    siginfo_t info;
    int killed_procs = 0;
    while (true) {
        sigwaitinfo(&mask, &info);
        if (info.si_signo == SIGINT)
            break;
        if (info.si_signo == SIGCHLD) {
            int child;
            while ((child = waitpid(-1, 0, WNOHANG)) > 0) {
                for (int i = 0; i < n; i++) {
                    if (pids[i] == child) {
                        pids[i] = 0;
                        break;
                    }
                }
                killed_procs++;
                if (killed_procs == n) {
                    killall(pids, orig_mask);
                    return 0;
                }
            }
        }
    }
    killall(pids, orig_mask);
    return 0;
}

int string_to_command(string line, vector<execargs_t> &commands) {
    if (line.empty())
        return -1;
    line[line.size() - 1] = '|';
    vector<string> command;
    string temp;
    int i = 0;
    while (i < line.size()) {
        while (line[i] == ' ')
            i++;
        while (i < line.size() && line[i] != ' ' && line[i] != '\'' && line[i] != '\"' && line[i] != '|') {
            temp += line[i];
            i++;
        }
        if (!temp.empty()) {
            command.push_back(temp);
            temp.clear();
            continue;
        }

        if (line[i] == '\'') {
            i++;
            while (!(line[i] == '\'' && line[i - 1] != '\\')) {
                temp += line[i];
                i++;
                if (i == line.size() - 1)
                    return -1;
            }
            command.push_back(temp);
            temp.clear();
            i++;
            continue;
        }
        if (line[i] == '\"') {
            i++;
            while (!(line[i] == '\"' && line[i - 1] != '\\')) {
                temp += line[i];
                i++;
                if (i == line.size() - 1)
                    return -1;
            }
            command.push_back(temp);
            temp.clear();
            i++;
            continue;
        }
        if (line[i] == '|') {
            if (command.empty())
                return -1;
            execargs_t ans = (execargs_t) malloc(sizeof(char *) * command.size() + 1);
            for (int i = 0; i < command.size(); i++) {
                ans[i] = (char *) malloc(command[i].size() + 1);
                memcpy(ans[i], command[i].c_str(), command[i].size());
                ans[i][command[i].size()] = 0;
            }
            ans[command.size()] = 0;

            commands.push_back(ans);
            command.clear();
            i++;
        }
    }
    return 0;
}

void daemon() {
    pid_t pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    } else if (pid > 0)
        exit(EXIT_SUCCESS);

    if (setsid() < 0)
        exit(EXIT_FAILURE);

    pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    } else if (pid > 0) {
        ofstream log;
        log.open("/tmp/netsh.pid");
        log << pid;
        log.close();
        exit(EXIT_SUCCESS);
    }

    umask(0);

    chdir("/");

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
}

int main(int argc, char **argv) {
    map<int, string> map;
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1) {
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in sockAddress;
    sockAddress.sin_family = AF_INET;
    sockAddress.sin_port = htons((uint16_t) atoi(argv[1]));
    sockAddress.sin_addr.s_addr = htonl(INADDR_ANY);
    CHK(bind(serverSocket, (struct sockaddr *) (&sockAddress), sizeof(sockAddress)));

    CHK(set_nonblock(serverSocket));

    CHK(listen(serverSocket, SOMAXCONN));

    daemon();

    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        exit(EXIT_FAILURE);
    }
    struct epoll_event event;
    event.data.fd = serverSocket;
    event.events = EPOLLIN | EPOLLET;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, serverSocket, &event);

    while (true) {
        int max_events = map.size() + 1;
        struct epoll_event events[max_events];
        int n = epoll_wait(epoll_fd, events, max_events, -1);

        for (int i = 0; i < n; i++) {
            if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP) || (events[i].events & EPOLLRDHUP)) {
                if (serverSocket != events[i].data.fd) {
                    map.erase(map.find(events[i].data.fd));
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, &events[i]);
                    shutdown(events[i].data.fd, SHUT_RDWR);
                    close(events[i].data.fd);
                }
            } else if (events[i].data.fd == serverSocket) {
                int childSocket = accept(serverSocket, 0, 0);
                set_nonblock(childSocket);
                struct epoll_event event;
                event.data.fd = childSocket;
                event.events = EPOLLIN | EPOLLET;
                epoll_ctl(epoll_fd, EPOLL_CTL_ADD, childSocket, &event);
                map[childSocket] = "";
            } else {
                static char buf[1];// not good but very simple
                bool command_readed = false;
                while (!command_readed) {
                    ssize_t readed = read(events[i].data.fd, buf, 1);
                    if (readed == 0) {
                        map.erase(map.find(events[i].data.fd));
                        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, &events[i]);
                        shutdown(events[i].data.fd, SHUT_RDWR);
                        close(events[i].data.fd);
                        break;
                    } else if (readed == -1) {
                        if (errno != EAGAIN) {
                            map.erase(map.find(events[i].data.fd));
                            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, &events[i]);
                            shutdown(events[i].data.fd, SHUT_RDWR);
                            close(events[i].data.fd);
                        }
                        break;
                    } else {
                        map[events[i].data.fd].append(buf);
                        if (buf[0] == '\n') {
                            command_readed = true;
                        }
                    }
                }
                if (command_readed) {
                    vector<execargs_t> prog;
                    if (string_to_command(map[events[i].data.fd], prog) >= 0) {
                        map.erase(map.find(events[i].data.fd));
                        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, &events[i]);
                        if (set_block(events[i].data.fd) < 0)
                            return -1;
                        int pid = fork();
                        if (pid < 0) {
                        } else if (pid) {
                            for (int j = 0; j < prog.size(); j++) {
                                for (int k = 0; prog[j][k] != 0; k++)
                                    free(prog[j][k]);
                                free(prog[j]);
                                prog[j] = 0;
                            }
                            prog.clear();
                            close(events[i].data.fd);
                        } else {
                            dup2(events[i].data.fd, STDIN_FILENO);
                            dup2(events[i].data.fd, STDOUT_FILENO);
                            int res = runpiped(prog);
                            close(events[i].data.fd);
                            close(STDIN_FILENO);
                            close(STDOUT_FILENO);
                            exit(res);
                        }
                    } else {
                        map.erase(map.find(events[i].data.fd));
                        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, &events[i]);
                        close(events[i].data.fd);
                    }
                }
            }
        }
    }
}