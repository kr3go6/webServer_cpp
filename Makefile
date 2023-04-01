CC=g++
CFLAGS=-std=c++17
LDFLAGS=-lsqlite3 -lpthread
SOURCES=main.cpp
EXECUTABLE=main

all: 
	$(CC) $(SOURCES) $(CFLAGS) $(LDFLAGS) -o $(EXECUTABLE)