CC=gcc
CFLAGS=-std=c11 -O2 -Wall -Wextra -pedantic -pthread
LDFLAGS=
OBJS=main.o util.o crypto_aes.o crypto_hmac.o x25519.o ikev2.o ipv4.o esp.o crypto_core.o message.o ikev2_sa.o blake2s.o chacha20poly1305.o wg.o

all: pvpn_c

pvpn_c: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

clean:
	rm -f $(OBJS) pvpn_c
