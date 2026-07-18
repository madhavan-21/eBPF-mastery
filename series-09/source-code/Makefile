CLANG ?= clang
CFLAGS ?= -O2 -g -target bpf -D__TARGET_ARCH_x86

.PHONY: all clean

all: main.bpf.o loader

main.bpf.o: main.bpf.c
	$(CLANG) $(CFLAGS) -c $< -o $@

loader: main.go
	go build -o loader main.go

clean:
	rm -f main.bpf.o loader
