CXX = g++
CXXFLAGS = -std=c++17 -Wall

SRC = src/awilix.cpp
TARGET = bin/awilix

all: $(TARGET)

$(TARGET):
	mkdir -p bin
	$(CXX) $(CXXFLAGS) $(SRC) -o $(TARGET)

clean:
	rm -fr bin