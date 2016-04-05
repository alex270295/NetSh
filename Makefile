all: build
build:
	g++ -std=c++11 main.cpp -o netsh
clean:
	rm netsh