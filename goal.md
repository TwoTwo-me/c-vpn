# 목표 정의 (python-vpn WireGuard 구현 수준 분석)

본 문서는 Python-VPN 저장소(pvpn/server.py 등)에 포함된 WireGuard 서버 구현의 실제 기능 범위를 정리하고, 동등 수준의 C 구현(C‑VPN)을 Alpine Linux x86 (32-bit) 환경에서 재현하기 위한 구체적인 목표를 정의한다. 핵심 초점은 "보안 강건성"이 아니라 "동일 동작/연결성 재현"이다. 즉, 원본이 갖는 단순화 / 취약한 부분도 그대로 이해하고 동일 수준으로 이식한다. (필요 시 후속 단계에서 강화 가능.)

---
## 1. 전체 레포 구성 중 WireGuard 관련 부분
Python-VPN 은 IKEv1/IKEv2, L2TP, 단순 TCP 스택, DNS 캐시 등을 포함하지만 WireGuard 관련 코드는 `pvpn/server.py` 의 `WIREGUARD` 클래스(≈ 120줄 정도)와 `pvpn/crypto.py` 내 ChaCha20-Poly1305 / BLAKE2s / X25519 구현 및 헬퍼에 한정된다.

WireGuard 처리 경로:
1. UDP 수신 (지정 포트: `-wg <port>` 인자) → `WIREGUARD.datagram_received`
2. 메시지 타입 분기: Initiation(1), Response(2) 송신, Transport Data(4) 수신/송신
3. Handshake 로 키/인덱스 생성 후 IP 패킷(IPv4) 평문을 ChaCha20-Poly1305 로 암복호화
4. 복호화된 IPv4 패킷을 사용자 공간 IP 처리기(`ip.IPPacket.handle_ipv4`)에 전달

Tun/Tap 디바이스 미사용: 사용자 공간에서 직접 IPv4 패킷 파싱/재조립 후 원격(프록시 / 직접)으로 중계.

---
## 2. 현재 WireGuard Handshake 구현 상세
구현은 WireGuard 공식 사양의 최소 부분 Noise_IKpsk2 흐름을 간략화하여 재현:

### 2.1 사용 메시지 종류
- 지원/처리: Type 1 (Initiation), Type 2 (Response) 생성, Type 4 (Transport Data)
- 미구현: Type 3 (Cookie Reply), 재핸드셰이크(rekey), Keepalive, Roaming, Multi-peer 고급 기능

### 2.2 Initiation(Message Type 1) 파싱 (길이 고정 148바이트 기대)
구조 (리틀엔디안):
```
u32 type (=1)
u32 sender_index_peer
u8  ephemeral_pub[32]
u8  encrypted_static[32+16]  (ChaCha20-Poly1305)
u8  encrypted_timestamp[12+16]
u8  mac1[16]
u8  mac2[16]
```
코드 상 처리:
1. `mac1` 검증: mac1 = MAC(key = HASH("mac1----" + self.public_key), msg = 앞 116바이트) (BLAKE2s 16바이트)
2. `mac2` 는 **항상 0x00 16바이트인지 assert** (실제 DoS 대응 Cookie 미구현)
3. 고정 pre-shared key: 32바이트 0 (`self.preshared_key = b'\x00'*32`)
4. 정적 서버 키: private = BLAKE2s(password), public = X25519(private, basepoint=9)
5. 노이즈 체인/해시 변수 계산 (간략화, HMAC = BLAKE2s 기반) 순서:
   - 초기 chaining_key = HASH("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s")
   - transcript hash(hash0) 누적: 라벨 → server static public → peer ephemeral 등
   - ECDH1: X25519(server_priv, peer_ephemeral)
   - decrypt peer static (encrypted_static)
   - ECDH2: X25519(server_priv, peer_static)
   - decrypt timestamp (encrypted_timestamp) (검증/재생 방지 로직 없음)
   - 서버 ephemeral 생성 (랜덤 32B) + ECDH 3,4 (server_ephemeral with peer_ephemeral, peer_static)
   - Pre-Shared Key 혼입 후 최종 응답용 key 도출

### 2.3 Response(Message Type 2) 생성
구조(코드):
```
u32 type (=2)
u32 sender_index_server   (index 변수)
u32 receiver_index_peer   (peer sender index 복사)
u8  ephemeral_public[32]
u8  encrypted_empty[0+16]
u8  mac1[16]
u8  mac2[16] (0)
```
`sender_index_server` 는 `itertools.count()` 로 0부터 순차 증가 (보안적 무작위 없음).
`encrypted_empty` 는 빈 payload 를 AEAD 로 암호화 (인증태그만 존재). hash 누적 갱신 일부 스킵(주석).

### 2.4 키 확장
Response 직후:
```
temp = HMAC(chaining_key, "")
receiving_key = HMAC(temp, b"\x01")
sending_key   = HMAC(temp, receiving_key + b"\x02")
```
서버 측 딕셔너리: `self.keys[index] = (sender_index, receiving_key, sending_key)`

### 2.5 Timestamp / 재전송 / 재키갱신
- 수신 timestamp 복호화만 하고 유효성/재생 공격 차단 전혀 하지 않음.
- 재핸드셰이크, 키 로테이션, Keepalive, Cookie, Roaming 모두 미구현.

---
## 3. Transport Data(Message Type 4) 처리
구조 (수신):
```
u32 type (=4)
u32 receiver_index_server (키 딕셔너리 lookup 키)
u64 counter  (nonce, 재생 검사 미구현)
u8  ciphertext[...] + tag(16)
```
절차:
1. 인덱스로 (peer_sender_index, recv_key, send_key) 조회
2. nonce = 4 zero bytes + little-endian counter (표준과 동일 형식)
3. ChaCha20-Poly1305 복호화(auth_text = empty)
4. 복호 평문은 **그 자체가 IPv4 패킷**이라 가정 → `ippacket.handle_ipv4()` 호출
5. 응답 시:
   - counter = `next(self.index_generators[index])` (로컬 송신 증가)
   - 평문 IPv4 패킷 뒤에 16바이트 정렬 되도록 0 패딩(`((-len)%16)`), (WireGuard 요구 사항 아님, 단순 구현 선택)
   - 암호화 후 Type=4, peer_sender_index, counter 붙여 송신

제한:
- 재생(anti-replay) 윈도우 없음
- 최대 전달/MTU 조정 없음
- 다중 peer 지원은 논리상 가능하나 상태 관리 단순 (딕셔너리 인덱스만 저장, peer 구분 약함)

---
## 4. 사용 암호 primitive 구현 수준
| 구성요소 | 구현 위치 | 특징 / 차이 |
|---------|-----------|-------------|
| X25519  | `crypto.py` (직접 작성) | scalar clamping 수행, 외부 라이브러리 미사용 |
| ChaCha20-Poly1305 | PyCryptodome 모듈 | 표준 96비트 nonce (4 zero + 8 counter) |
| BLAKE2s | hashlib.blake2s | MAC1 (16바이트) 및 H()/HMAC 유사 용도 |
| HMAC(BLAKE2s) | `hmac.digest(key, msg, hashlib.blake2s)` | 공식 Noise 구현과 호출 패턴 차이 있음 |
| Pre-Shared Key | 고정 32바이트 0 | psk2 패턴이지만 실질 효과 없음 |

보안 측면 주요 결함(단순화):
- MAC2 / Cookie (DoS) 미구현
- Timestamp / replay 검증 없음
- Index 예측 가능 (순차)
- 비밀번호 기반 private key (사전 공격 가능)
- 키 재교환/만료 없음
- Anti-replay window 없음

C 포팅 1단계에서는 이 결함을 **수정하지 않고 동일 동작** 재현.

---
## 5. IPv4 페이로드 처리 경로 (WireGuard 경유)
1. 복호 IPv4 → `ip.IPPacket.handle_ipv4()`
2. 내부 TCP/UDP/DNS 등 사용자 공간 처리 (TUN 미사용)
3. 응답은 callback → 암호화 → Type 4 송신

---
## 6. C 구현 시 포함 필수 항목 (동등 기능)
1. UDP 서버: Type 1/4 처리, Type 2/4 생성
2. Initiation 길이 148 고정 + MAC1 검증 + MAC2=0
3. Handshake 파생 순서 & 키 도출 동일
4. Pre-shared key = 32바이트 0
5. Private=blake2s(password UTF-8), Public=X25519(priv, 9)
6. Response 포맷(빈 암호문 + index 증가) 동일
7. Transport ChaCha20-Poly1305 (nonce = 4 zero + LE counter)
8. 카운터 기반 nonce, replay window 없음
9. IPv4 평문 콜백 구조 유지 (초기 버전: 로그 또는 dump)
10. 16바이트 정렬 패딩 유지
11. PublicKey base64 출력

선택(초기 생략 가능): 내부 TCP/DNS/L2TP 재구현 → 추후 단계.

---
## 7. 미구현 / 비목표 (강화 후보)
| 항목 | Python | C 1단계 | 향후 |
|------|--------|---------|------|
| Cookie(MAC2) | 없음 | 제외 | 추가 |
| 재핸드셰이크 | 없음 | 제외 | 추가 |
| Keepalive | 없음 | 제외 | 추가 |
| Replay window | 없음 | 제외 | 추가 |
| 키 만료/로테이션 | 없음 | 제외 | 추가 |
| 멀티 peer 고급 관리 | 단순 dict | 동일 | 확장 |

---
## 8. C 구현 기술 사양 제안
### 8.1 환경
- Alpine Linux x86 (32-bit)
- gcc/musl-gcc, `-O2 -Wall`

### 8.2 라이브러리
- 권장: libsodium (X25519, ChaCha20-Poly1305, BLAKE2s 지원) → HMAC(BLAKE2s) 는 별도 래퍼
- 대안: 전부 자체 구현 (개발 비용↑)

### 8.3 디렉터리 초안
```
src/
  main.c
  wireguard.c/.h
  crypto.c/.h
  state.c/.h
  ip_handler.c/.h
  util.c/.h
```

### 8.4 peer_state 구조체
```
struct peer_state {
  uint32_t local_index;
  uint32_t peer_index;
  uint8_t  recv_key[32];
  uint8_t  send_key[32];
  uint64_t send_counter;
};
```

### 8.5 Handshake 검증 전략
- Python 난수 고정 후 key 벡터 추출 → C 비교
- (receiving_key, sending_key) hex 일치 테스트

### 8.6 최소 테스트
1. Python Initiation → C Response diff=0
2. Transport 왕복 (ping 패킷) 성공
3. 잘못된 MAC1 드롭
4. encrypted_static 변조 시 조용히 무시

---
## 9. 동등성 유지 포인트
| 항목 | Python | C 지침 |
|------|--------|--------|
| server index | 0부터 순차 | 동일 |
| PSK | 0x00 *32 | 동일 |
| password->priv | blake2s | 동일 |
| MAC1 key | HASH("mac1----" + pub) | 동일 |
| HMAC | hmac(blake2s) | 동일 결과 강제 |
| 패딩 | %16 0패딩 | 동일 |
| nonce | 4 zero + LE counter | 동일 |
| timestamp 검증 | 없음 | 없음 |
| MAC2 | zero assert | 동일 |

---
## 10. 리스크 & 검증
- HMAC(blake2s) 결과 불일치 가능 → 테스트 벡터 확보
- X25519 clamp/엔디안 실수 → 교차 테스트
- AEAD nonce / AD 파라미터 순서 오류 위험 → 라운드트립 테스트

---
## 11. 완료 정의 (C 1단계)
1. PublicKey base64 출력
2. Type1→Type2 핸드셰이크 상호호환
3. IPv4 Transport 왕복
4. 비정상 패킷 드롭 안정성
5. 메모리 릭 없음 (ASAN)

---
## 12. 요약
현 구현은 학습용 축소판 WireGuard 로, 다수 보안 기능이 비활성/생략. C-VPN 1단계 목표는 이 축소된 동작을 있는 그대로 재현하고, 구조를 후속 강화(재핸드셰이크/Replay/Cookie 등)가 용이하게 분리하는 것.

---
## 13. 다음 액션 To-Do
1. Python 난수 고정 + 핸드셰이크 키 벡터 수집 스크립트 작성
2. C 프로젝트 스캐폴딩 (Makefile 등)
3. crypto 모듈 (libsodium 래퍼 + HMAC blake2s) 구현
4. 패킷 구조체/직렬화 파서 작성
5. Handshake 상태머신 구현 후 벡터 검증
6. Transport 암복호 + IPv4 dump
7. Python↔C 상호 테스트
8. (선택) TUN 연계

