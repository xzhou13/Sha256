all:
	g++ *.cpp -std=c++11 -Wall -o sha256

clean:
	rm sha256
