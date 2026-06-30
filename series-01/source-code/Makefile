CLANG ?= clang
CFLAGS ?= -O2 -g -target bpf -Wall

# Path to system kernel headers and libbpf headers
INCLUDES ?= -I/usr/include -I/usr/include/bpf

.PHONY: all clean run

all: main.bpf.o loader

main.bpf.o: main.bpf.c
	$(CLANG) $(CFLAGS) $(INCLUDES) -c $< -o $@

loader: main.go
	go build -o loader main.go

clean:
	rm -f main.bpf.o loader

run: all
	@echo "Running loader (requires root privileges)..."
	sudo ./loader -iface lo
