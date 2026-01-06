## 📝 README.md

# 🛡️ Static Log4Shell Scanner

> **Log4Shell 취약점을 탐지하는 전문적인 보안 스캐너**

Java 프로젝트에서 Log4Shell(CVE-2021-44228) 취약점을 신속하고 정확하게 탐지하는 CLI 도구입니다. 실무 환경에서 사용할 수 있도록 개발된 스캐너로, 개발팀의 보안 워크플로우에 쉽게 통합할 수 있습니다.

## 🎯 주요 특징

### ⚡ 빠르고 효율적인 스캔
- **대용량 프로젝트 지원**: 수천 개 파일을 빠르게 처리
- **실시간 진행상황**: 스캔 중인 파일을 실시간으로 표시
- **정적 분석 방식**: 실행 없이 코드와 설정 파일만으로 안전하게 검사

### 🔍 정밀한 취약점 탐지
- **다중 탐지 방식**: JAR 파일, 소스코드, 빌드 파일 동시 검사
- **정확한 버전 분석**: Log4j 버전 자동 탐지 및 취약점 여부 정확히 판단
- **컨텍스트 분석**: 위험한 로깅 패턴까지 상세 검사

### 📊 명확한 결과 리포트
- **간단명료한 판정**: 안전/위험 두 가지로 명확하게 표시
- **맞춤형 조치방안**: Log4j 버전별 최적화된 해결 방법 제시
- **JSON 출력 지원**: 자동화 도구 연동 가능

## 🚀 빠른 시작

### 설치

```bash
# PyPI에서 설치
pip install static-log4shell

# pipx로 설치 (권장 - 칼리 리눅스 등)
pipx install static-log4shell
```

### 기본 사용법

```bash
# 현재 디렉토리 스캔
static-log4shell .

# 특정 프로젝트 스캔
static-log4shell /path/to/java-project

# 짧은 명령어 (별칭)
slog4j ~/workspace/spring-app
```

### 고급 옵션

```bash
# 결과를 JSON 파일로 저장
static-log4shell ./project --output security-report.json

# 간단한 출력만 표시
static-log4shell ./project --quiet

# 버전 정보 확인
static-log4shell --version
```

## 📋 스캔 결과 예시

### 🔴 취약한 프로젝트 예시
```
🔍 Log4Shell 보안 스캔 시작: ./vulnerable-spring-app
============================================================
📂 파일 스캔 진행 중...
    > build.gradle                            
    🚨 위험 발견: build.gradle
    > MainController.java                      
✅ 스캔 완료: 1,679개 파일 검사

📊 스캔 결과 요약
----------------------------------------
  📅 스캔 시간: 2026-01-06 16:30:46
  📁 스캔 파일: 1,679개
  ☕ Java 버전: 1.8
  📚 Log4j 버전: 2.14.1
  🛡️  보안 상태: 🔴 위험
  🔍 발견사항: 1개

⚠️ 발견된 위험 (1개):
  1. MainController.java
     Log4j 2.x 라이브러리 import + 문자열 연결을 통한 위험한 로깅

🚨 긴급 조치사항:
  1. 📦 Log4j 업그레이드 (최우선)
     Log4j를 2.17.1 이상 또는 2.12.2, 2.3.1(보안 릴리즈)로 업그레이드
  2. ⚡ JVM 옵션 적용 (2.10.0 이상용)
     java -Dlog4j2.formatMsgNoLookups=true -jar myapp.jar
  3. 🗑️ JndiLookup 클래스 제거 (2.10.0 미만용)
     zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class
```

### ✅ 안전한 프로젝트 예시
```
🔍 Log4Shell 보안 스캔 시작: ./safe-java-project
============================================================
📂 파일 스캔 진행 중...
    > pom.xml                                 
✅ 스캔 완료: 523개 파일 검사

📊 스캔 결과 요약
----------------------------------------
  📅 스캔 시간: 2026-01-06 16:45:12
  📁 스캔 파일: 523개
  ☕ Java 버전: 17
  📚 Log4j 버전: 2.17.2
  🛡️  보안 상태: ✅ 안전
  🔍 발견사항: 0개

✨ 축하합니다! 프로젝트가 Log4Shell 취약점으로부터 안전합니다.
```

## 🛠️ 스캔 범위 및 탐지 항목

| 스캔 유형 | 탐지 대상 | 설명 |
|----------|----------|------|
| **JAR 파일 검사** | log4j-core-*.jar, log4j-api-*.jar | 취약한 Log4j 라이브러리 직접 탐지 |
| **소스코드 분석** | .java 파일 | 위험한 로깅 패턴 및 외부 입력 사용 감지 |
| **빌드 파일 분석** | pom.xml, build.gradle | 의존성 설정 및 버전 정보 추출 |
| **버전 호환성** | Java-Log4j 매칭 | 호환성 및 권장 업그레이드 경로 제시 |

## 🔧 시스템 요구사항

- **Python**: 3.7 이상
- **운영체제**: Windows, macOS, Linux
- **메모리**: 최소 512MB RAM 권장
- **저장공간**: 스캔 대상 프로젝트 크기의 10% 여유공간

## 📖 상세 사용 가이드

### 전체 명령어 옵션

```
usage: static-log4shell [-h] [-o OUTPUT] [--version] [-q] path

positional arguments:
  path                 스캔할 프로젝트 경로

options:
  -h, --help           도움말 표시
  -o, --output OUTPUT  결과 저장 파일 (JSON 형식)
  --version            버전 정보 표시  
  -q, --quiet          간단한 출력만 표시
```

### 사용 예시

```bash
# 홈 디렉토리의 Java 프로젝트 스캔
static-log4shell ~/Documents/JavaProjects/MyApp

# 회사 프로젝트 전체 스캔 후 결과 저장
static-log4shell /workspace/enterprise-app -o security-audit.json

# CI/CD 파이프라인에서 간단히 사용
slog4j . --quiet && echo "보안 검사 통과"
```

## ⚠️ 중요 참고사항

### Log4Shell 취약점이란?
- **CVE-2021-44228**: CVSS 10점 만점의 치명적 취약점
- **영향 범위**: Log4j 2.2.0-beta9 ~ 2.15.0 (일부 보안 릴리즈 제외)
- **공격 원리**: JNDI Injection을 통한 원격 코드 실행
- **발생 시점**: 2021년 12월, 전 세계 Java 시스템에 대대적 영향

### 왜 정적 스캐너인가?
- **안전성**: 실제 공격을 수행하지 않아 시스템에 무해
- **효율성**: 빠른 속도로 대량의 코드베이스 검사 가능
- **실용성**: 개발 환경에서 부담 없이 정기적 검사 수행

## 🎓 프로젝트 배경

2021년 Log4Shell 취약점이 전 세계 수많은 시스템에 영향을 미친 것을 보고, 개발자들이 쉽게 사용할 수 있는 탐지 도구의 필요성을 느껴 개발하게 되었습니다.

### 개발 과정에서 학습한 내용
- 보안 취약점 분석 및 탐지 알고리즘 구현
- Python 패키지 개발 및 CLI 도구 설계
- 정규표현식을 활용한 정교한 패턴 매칭
- PyPI 배포 및 오픈소스 프로젝트 관리
- 실무에서 사용 가능한 도구 설계 원칙

### 개발 환경 설정

```bash
# 저장소 복제
git clone https://github.com/vanillacustardcream/static-log4shell.git
cd static-log4shell

# 가상환경 생성 및 활성화
python -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

# 개발 모드 설치
pip install -e .

# 테스트 실행
static-log4shell --help
```

## 📄 라이선스

이 프로젝트는 [MIT 라이선스](LICENSE) 하에 배포되어 자유롭게 사용, 수정, 배포할 수 있습니다.