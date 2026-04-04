CXX = g++
CXXFLAGS = -std=c++17 -Wall

SRC = src/awilix.cpp
TARGET = bin/awilix
BPF_SRC = ebpf/probes.bpf.c
BPF_OBJ = ebpf/probes.bpf.o

BPF_SKEL = ebpf/probes.skel.h


all: $(BPF_OBJ) $(BPF_SKEL) $(TARGET)

$(BPF_SKEL) : $(BPF_OBJ)
	bpftool gen skeleton $(BPF_OBJ) > $(BPF_SKEL)

$(BPF_OBJ) : $(BPF_SRC)
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86 \
	-I /usr/include/bpf \
	-I ebpf/ \
	-c $(BPF_SRC) -o $(BPF_OBJ)

$(TARGET):
	mkdir -p bin
	$(CXX) $(CXXFLAGS) -I. $(SRC) -o $(TARGET) -lbpf -lelf -lz

clean:
	rm -rf bin
	rm -f $(BPF_OBJ)