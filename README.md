# 🛡️ PacketInside: CVE Analysis & Network Forensics

[![License: CC BY-NC 4.0](https://img.shields.io/badge/License-CC%20BY--NC%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by-nc/4.0/)
[![Website](https://img.shields.io/website?url=https%3A%2F%2Fpacketinside.github.io&label=packetinside.github.io)](https://packetinside.github.io)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)

> **주요 CVE 취약점 분석, PCAP 패킷 캡처 파일, Nuclei 템플릿 및 Snort 탐지 규칙을 제공하는 보안 리서치 저장소입니다.**

## 📌 소개 (Introduction)
이 저장소는 최신 보안 취약점(CVE)에 대한 기술적인 분석 정보와 실제 공격 시나리오를 재현한 데이터를 제공합니다. 보안 연구원, 네트워크 분석가, 그리고 학생들의 학습과 연구를 돕기 위해 운영됩니다.

👉 **웹사이트 바로가기:** [https://packetinside.github.io](https://packetinside.github.io)

## 📂 제공 콘텐츠 (Contents)

이 저장소에서는 다음과 같은 리소스를 찾을 수 있습니다:

* **📊 CVE Analysis**: 주요 취약점의 원인과 영향도 분석
* **🦈 PCAP Files**: 공격 트래픽이 포함된 패킷 캡처 파일 (교육/테스트용)
* **☢️ Nuclei Templates**: 취약점 스캐닝을 위한 최적화된 Nuclei 템플릿
* **🛡️ Snort Rules**: 네트워크 침입 탐지 시스템(IDS/IPS)을 위한 Snort 2/3 탐지 규칙

## 📁 디렉터리 구조 (Directory Structure)

```bash
packetinside.github.io/
├── _cves/              # CVE 분석 리포트 (Markdown)
├── pcaps/              # 공격 패킷 파일 (.pcap)
├── nuclei-templates/   # Nuclei 템플릿 (.yaml)
└── snort-rules/        # Snort 탐지 규칙 (.rules)
