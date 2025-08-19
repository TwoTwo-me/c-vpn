# C-VPN (Minimal WireGuard parity with python-vpn)

This project aims to reproduce the simplified WireGuard subset implemented in `python-vpn/pvpn/server.py` (class `WIREGUARD`) for Alpine Linux x86 (32-bit). Security robustness is NOT the target; functional parity is.

## Status
- [x] goal.md imported
- [ ] Basic crypto wrappers (blake2s, hmac-blake2s, x25519, chacha20poly1305)
- [ ] Packet structs
- [ ] Handshake (Type 1 -> Type 2)
- [ ] Transport (Type 4) encrypt/decrypt loopback

## Build (placeholder)
```
make
```

## Run (placeholder)
```
./c-vpn -p test -l 51820
```

## Notes
This is an educational parity implementation. Do NOT use in production.
