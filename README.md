## 📝 README.md

# 🛡️ Static Log4Shell Scanner

> **Log4Shell 취약점을 탐지하는 전문적인 보안 스캐너**

Java 프로젝트에서 Log4Shell(CVE-2021-44228) 취약점을 신속하고 정확하게 탐지하는 CLI 도구입니다. 실무 환경에서 사용할 수 있도록 개발된 스캐너로, 개발팀의 보안 워크플로우에 쉽게 통합할 수 있습니다.

## 🎯 주요 특징

### ⚡ 빠르고 효율적인 스캔
- **대용량 프로젝트 지원**: 수천 개 파일을 빠르게 처리
- **실시간 진행상황**: 스캔 중인 파일을 실시간으로 표시
- **중복 방지**: 이미 검사한 파일은 건너뛰어 효율성 증대

### 🔍 정밀한 취약점 탐지
- **다중 탐지 방식**: JAR 파일, 소스코드, 빌드 파일 동시 검사
- **버전 분석**: Log4j 버전 자동 탐지 및 취약점 여부 판단
- **컨텍스트 분석**: 정교한 패턴 매칭으로 정확도 향상

### 📊 직관적인 결과 리포트
- **상세한 분석**: 파일별 취약점 정보 및 위험도 평가
- **JSON 출력**: 자동화 도구 연동을 위한 구조화된 데이터
- **실행 가능한 권장사항**: 구체적인 해결 방법 제시

## 🚀 빠른 시작

### 설치

# PyPI에서 설치
pip install static-log4shell

# 테스트 버전 (개발 중)
pip install -i https://test.pypi.org/simple/ static-log4shell
```

### 기본 사용법

# 현재 디렉토리 스캔
static-log4shell .

# 특정 프로젝트 스캔
static-log4shell /path/to/java-project

# 짧은 명령어 (별칭)
slog4j ~/workspace/spring-app
```

### 고급 옵션

# 결과를 JSON 파일로 저장
static-log4shell ./project --output security-report.json

# 간단한 출력만 표시
static-log4shell ./project --quiet

# 버전 정보 확인
static-log4shell --version
```

## 📋 스캔 결과 예시

🔍 Log4Shell 보안 스캔 시작: ./spring-boot-project
============================================================
📂 파일 스캔 진행 중...
    > 분석 중: UserController.java...

✅ 스캔 완료: 847개 파일 검사

📊 스캔 결과 요약
----------------------------------------
  📅 스캔 시간: 2024-12-31 15:30:25
  📁 스캔 파일: 847개
  ☕ Java 버전: 11
  📚 Log4j 버전: 2.14.1 (취약함)
  🛡️  방어 점수: 25/100점
  ⚠️  위험도: 🔴 높음 (즉시 조치 필요)
  🔍 발견사항: 3개

📋 발견된 취약점:
1. [🔴 HIGH] JAR 파일 취약점
   📁 /lib/log4j-core-2.14.1.jar
   📋 Log4Shell 취약 버전 탐지

2. [🟠 MEDIUM] 소스코드 위험 패턴  
   📁 /src/UserController.java
   📋 외부 입력이 로거로 직접 전달됨

3. [🟡 LOW] 빌드 설정 개선 필요
   📁 /pom.xml  
   📋 Log4j 의존성 버전 명시 권장

💡 권장 조치사항:
  1. 🔥 긴급: Log4j를 2.17.1 이상으로 업그레이드
  2. ⚡ 임시조치: JVM 옵션 -Dlog4j2.formatMsgNoLookups=true 적용
  3. 🔧 보완: 입력값 검증 로직 추가
  4. 📋 모니터링: 정기적인 보안 스캔 수행
```

## 🛠️ 스캔 범위 및 탐지 항목

| 스캔 유형 | 탐지 대상 | 위험도 | 설명 |
|----------|----------|--------|------|
| **JAR 파일 검사** | log4j-core-*.jar, log4j-api-*.jar | 🔴 Critical | 취약한 Log4j 라이브러리 직접 탐지 |
| **소스코드 분석** | .java 파일 | 🟠 High | 위험한 로깅 패턴 및 외부 입력 사용 |
| **빌드 파일 분석** | pom.xml, build.gradle | 🟡 Medium | 의존성 설정 및 버전 정보 |
| **버전 호환성** | Java 버전 매칭 | 🟢 Info | 호환성 및 권장 업그레이드 경로 |

## 🔧 시스템 요구사항

- **Python**: 3.7 이상
- **운영체제**: Windows, macOS, Linux
- **메모리**: 최소 512MB RAM 권장
- **저장공간**: 스캔 대상 프로젝트 크기의 10% 여유공간

## 📖 상세 사용 가이드

### 전체 명령어 옵션

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

# 홈 디렉토리의 Java 프로젝트 스캔
static-log4shell ~/Documents/JavaProjects/MyApp

# 회사 프로젝트 전체 스캔 후 결과 저장
static-log4shell /workspace/enterprise-app -o security-audit.json

# CI/CD 파이프라인에서 간단히 사용
slog4j . --quiet && echo "보안 검사 통과"
```

## 🎓 프로젝트 배경

2021년 Log4Shell 취약점이 전 세계 수많은 시스템에 영향을 미친 것을 보고, 개발자들이 쉽게 사용할 수 있는 탐지 도구의 필요성을 느껴 개발하게 되었습니다.

### 개발 과정에서 학습한 내용
- 보안 취약점 분석 및 탐지 알고리즘
- Python 패키지 개발 및 CLI 도구 설계
- 정규표현식을 활용한 패턴 매칭
- PyPI 배포 및 오픈소스 프로젝트 관리
- 실무에서 사용 가능한 도구 설계 원칙

### 개발 환경 설정

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