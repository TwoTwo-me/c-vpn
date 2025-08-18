# c-vpn

Python 기반 `python-vpn` 레포지토리의 기능을 32비트 Linux 환경용 C로 단계적으로 포팅하는 프로젝트입니다. (현재는 부분 구현 상태)

## 현재 상태 (Progress)

- [x] 빌드 시스템 (Makefile)
- [x] 기본 유틸 (엔디언 read/write, IPv4 체크섬)
- [x] IPv4 패킷 생성 유틸 (`ipv4_make`)
- [x] IKEv2 헤더 파싱 (`ikev2.c`)
- [x] IKEv2 Payload 순회 스켈레톤 (`message.c`)
- [x] IKEv2 SA/Proposal/Transform 파서 (`ikev2_sa.c`)
- [x] AES-128-CBC 암/복호화 (라운드 자체 구현)
- [x] HMAC-SHA256 / PRF / PRF+ (내장 구현)
- [x] ESP AES-CBC + HMAC-SHA256 암/복호화 (단순화, 재생공격/윈도우 미구현)
- [ ] Diffie-Hellman MODP 그룹
- [ ] X25519 실제 구현 (현재 placeholder)
- [ ] IKEv2 Key Derivation (SKEYSEED, SK_*)
- [ ] IKEv2 전체 상태 머신 (INIT / AUTH / CREATE_CHILD / INFORMATIONAL)
- [ ] IKEv1 지원
- [ ] WireGuard Handshake 및 패킷 암호화
- [ ] ChaCha20-Poly1305 (AEAD) 지원
- [ ] DNS 파서 & 캐시
- [ ] 간이 TCP 스택 / L2TP 처리
- [ ] 재전송 타이머/스케줄러
- [ ] 구성/옵션 파서 & 로그 체계

## 빌드

```bash
cd c-vpn
make
./pvpn_c
```

## 디렉터리 구조

```text
Makefile              # 빌드 스크립트
README.md             # 현재 문서
README_C_PORTING.md   # 초기 포팅 메모 (점차 본 README로 통합 예정)
crypto_aes.c/.h       # AES-128 CBC (encrypt/decrypt)
crypto_hmac.c/.h      # SHA256 + HMAC
crypto_core.c/.h      # PRF / PRF+
enums.h               # 부분 IKEv2 열거형 (점진 확대)
esp.c/.h              # ESP 암/복호화 (단순)
ikev2.c/.h            # IKEv2 헤더 처리
ikev2_sa.c/.h         # IKEv2 SA/Proposal/Transform 파서
message.c/.h          # Payload 순회기
ipv4.c/.h             # IPv4 패킷 생성
util.c/.h             # 공용 매크로/엔디언/체크섬
x25519.c/.h           # X25519 placeholder (미구현)
main.c                # 데모 실행 파일 엔트리
```

## 보안 주의 (Security Caveats)

본 코드는 학습/포팅 진행 중인 실험용으로 다음 사항들이 미비합니다:

- 타이밍/사이드채널 완화 미적용
- 고급 에러 처리/Fail-safe 부족
- 입력 길이/경계 검증 일부 단순화
- 재전송/윈도우/시퀀스 관리 미구현 (ESP)
- 미완성/placeholder 알고리즘 (X25519 등)

실제 운영 환경 사용 금지. 검증된 라이브러리(예: strongSwan, WireGuard, OpenVPN)를 사용하십시오.

## 코드 스타일

- C11 표준
- 경고 최대화: `-Wall -Wextra -pedantic`
- 포맷 제안: `clang-format` (구성은 아직 미포함)

## 향후 로드맵 (Next Steps)

1. X25519 구현 또는 libsodium 연동 (옵션 플래그)
2. DH MODP 그룹 (RFC 3526) big integer 연산 (montgomery exp)
3. SKEYSEED / SK_d / SK_ai/ar / SK_ei/er / SK_pi/pr 파생 로직
4. SK Payload 암/복호화 + ICV 검증 통합
5. IKEv2 INIT/AUTH 상태 머신 골격 + 재전송 타이머
6. Notify / Transform 전체 enum 확장 자동 생성 스크립트
7. ChaCha20-Poly1305 AEAD 추가 (WireGuard & IKEv2 AEAD 용)
8. ESP 시퀀스 재생 방지 윈도우 & 패딩 고급 처리
9. DNS / TCP / L2TP 모듈 포팅
10. 통합 테스트 (pcap 캡처 기반 벡터) & Fuzzing (libFuzzer/AFL++)

## 라이선스

원본 `python-vpn`의 LICENSE(동일 적용). 필요 시 LICENSE 파일 동기화.

## 기여 (Contributing)

아직 초기 단계입니다. Issue/PR로 기능 우선순위 제안 환영.

---
문의나 다음 단계 요청은 자유롭게 남겨주세요.
