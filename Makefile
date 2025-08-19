CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -std=c11
LDFLAGS ?= -lsodium
INC ?=

# If cross compiling for Alpine 32-bit: add e.g. CC=musl-gcc CFLAGS="-m32 -O2 -Wall -Wextra -std=c11".

SRC = \
 src/main.c \
 src/crypto.c \
 src/blake2s.c \
 src/wireguard.c \
 src/state.c \
 src/ip_handler.c \
 src/util.c

OBJ = $(SRC:.c=.o)

all: c-vpn

c-vpn: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS)

clean:
	rm -f $(OBJ) c-vpn

.PHONY: all clean
