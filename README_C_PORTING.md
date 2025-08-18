이 디렉토리는 python-vpn 프로젝트의 핵심 기능을 32비트 Linux 환경용 C 코드로 포팅하기 위한 초안입니다.

목표 (1차):
- 기본적인 IKEv2 메시지 파싱 (Header + Payload stub)
- AES-CBC + HMAC-SHA256 기반 ESP 암복호화 최소 구현
- X25519 (Curve25519) DH 교환
- IPv4 패킷 (간단한 Header 조립/체크섬) 유틸

주의: 아직 Python 원본과 완전 동일한 기능/프로토콜 커버리지를 제공하지 않습니다. 점진적으로 확장 예정.
