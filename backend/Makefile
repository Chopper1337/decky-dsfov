CC ?= cc
CFLAGS ?= -Wall -Wextra -O2
LDFLAGS ?=

.PHONY: all clean

all: dsr-fov-patcher

dsr-fov-patcher:
	mkdir -p ./out
	$(CC) $(CFLAGS) -o ./out/dsr-fov-patcher ./src/dsr-fov-patcher.c $(LDFLAGS)

clean:
	rm -f ./out/dsr-fov-patcher
