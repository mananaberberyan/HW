all: signal-echo

signal-echo: signal-echo.cpp
	g++ -o signal-echo signal-echo.cpp

clean:
	rm -f signal-echo
