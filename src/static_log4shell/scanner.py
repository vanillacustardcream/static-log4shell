#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import json
import argparse
from datetime import datetime
from pathlib import Path

class Log4ShellScanner:
    def __init__(self):
        self.results = []
        self.scanned_files = set()
        self.java_version = "감지되지 않음"
        self.log4j_version = "감지되지 않음"
        self.file_count = 0
        
        # 취약한 Log4j 버전 패턴 (2.2.0-beta9 ~ 2.15.0, 보안 릴리즈 제외)
        self.vulnerable_versions = [
            # 2.x 취약 버전들
            r'2\.([2-9]|1[0-4])\.',  # 2.2.x ~ 2.14.x
            r'2\.15\.0',              # 2.15.0 (취약)
            r'2\.0\.',                # 2.0.x
            r'2\.1\.',                # 2.1.x
            # 1.x 버전들 (모두 취약)
            r'1\.',
        ]
        
        # 안전한 버전들
        self.safe_versions = [
            r'2\.17\.[1-9]',    # 2.17.1+
            r'2\.1[8-9]\.',     # 2.18.x+
            r'2\.[2-9][0-9]\.',  # 2.20.x+
            r'2\.12\.[2-4]',    # 2.12.2-2.12.4 (보안 릴리즈)
            r'2\.3\.1',         # 2.3.1 (보안 릴리즈)
        ]

    def is_vulnerable_version(self, version):
        """버전이 취약한지 확인"""
        if not version or version == "감지되지 않음":
            return False
            
        # 안전한 버전 먼저 체크
        for safe_pattern in self.safe_versions:
            if re.search(safe_pattern, version):
                return False
                
        # 취약한 버전 체크
        for vuln_pattern in self.vulnerable_versions:
            if re.search(vuln_pattern, version):
                return True
                
        return False

    def scan_directory(self, directory_path):
        """디렉토리 스캔"""
        print("📂 파일 스캔 진행 중...")
        
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                file_path = Path(root) / file
                
                if str(file_path.resolve()) in self.scanned_files:
                    continue
                    
                self.scanned_files.add(str(file_path.resolve()))
                self.file_count += 1
                
                # 실시간 파일 표시
                print(f"    > {file[:40]:<40}", end='\r')
                
                # 파일 타입별 스캔
                if file.endswith(('.jar', '.war')):
                    self.scan_jar_file(file_path)
                elif file.endswith('.java'):
                    self.scan_java_source(file_path)
                elif file.endswith(('pom.xml', 'build.gradle', 'build.gradle.kts')):
                    self.scan_build_file(file_path)

    def scan_build_file(self, file_path):
        """빌드 파일 스캔 - 향상된 버전 감지"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            print(f"\n[DEBUG] 빌드 파일 스캔: {file_path}")
            
            # Java 버전 추출 (더 많은 패턴)
            java_patterns = [
                # Gradle 패턴들
                r'sourceCompatibility\s*=\s*["\']?(\d+(?:\.\d+)?)',
                r'targetCompatibility\s*=\s*["\']?(\d+(?:\.\d+)?)',
                r'JavaVersion\.VERSION_(\d+)',
                r'java\s*{\s*sourceCompatibility\s*=\s*["\']?(\d+(?:\.\d+)?)',
                r'compileOptions\s*{\s*sourceCompatibility\s+JavaVersion\.VERSION_(\d+)',
                # Maven 패턴들
                r'<maven\.compiler\.source>(\d+(?:\.\d+)?)</maven\.compiler\.source>',
                r'<maven\.compiler\.target>(\d+(?:\.\d+)?)</maven\.compiler\.target>',
                r'<java\.version>(\d+(?:\.\d+)?)</java\.version>',
                r'<source>(\d+(?:\.\d+)?)</source>',
                r'<target>(\d+(?:\.\d+)?)</target>',
                # 일반 패턴들
                r'jdk["\s]*[:=]\s*["\']?(\d+(?:\.\d+)?)',
                r'java["\s]*[:=]\s*["\']?(\d+(?:\.\d+)?)',
            ]
            
            for pattern in java_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                if matches:
                    # 가장 높은 버전 선택
                    version = max(matches, key=lambda x: float(x) if '.' in x else float(x))
                    self.java_version = version
                    print(f"[DEBUG] Java 버전 발견: {version}")
                    break
                    
            # Log4j 버전 추출 (더 정확한 패턴들)
            log4j_patterns = [
                # 직접적인 Log4j 의존성
                r'["\']org\.apache\.logging\.log4j:log4j-core:(\d+\.\d+\.\d+)',
                r'["\']org\.apache\.logging\.log4j:log4j-api:(\d+\.\d+\.\d+)',
                # Spring Boot Log4j2 스타터
                r'["\']org\.springframework\.boot:spring-boot-starter-log4j2:(\d+\.\d+\.\d+)',
                # Gradle 스타일
                r'implementation\s+["\']org\.apache\.logging\.log4j:log4j-[^:]+:(\d+\.\d+\.\d+)',
                r'compile\s+["\']org\.apache\.logging\.log4j:log4j-[^:]+:(\d+\.\d+\.\d+)',
                # Maven 스타일
                r'<groupId>org\.apache\.logging\.log4j</groupId>\s*<artifactId>[^<]+</artifactId>\s*<version>(\d+\.\d+\.\d+)</version>',
                r'<artifactId>log4j-[^<]+</artifactId>\s*<version>(\d+\.\d+\.\d+)</version>',
                # 일반 패턴들
                r'log4j["\'\s]*[:\-]\s*["\']?(\d+\.\d+\.\d+)',
                r'log4j.*?version["\'\s]*[:\-=]\s*["\']?(\d+\.\d+\.\d+)',
            ]
            
            for pattern in log4j_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)
                if matches:
                    # Spring Boot 버전에서 Log4j 버전 추정
                    if 'spring-boot-starter-log4j2' in pattern:
                        spring_version = matches[0]
                        log4j_version = self.estimate_log4j_from_spring(spring_version)
                        print(f"[DEBUG] Spring Boot 버전: {spring_version} → 실제 Log4j: {log4j_version}")
                    else:
                        log4j_version = matches[0]
                        print(f"[DEBUG] Log4j 버전 발견: {log4j_version}")
                    
                    self.log4j_version = log4j_version
                    break
                    
            # 특별 케이스: build.gradle에서 Log4j 포함 라인 찾기
            if 'log4j' in content.lower():
                for line in content.split('\n'):
                    if 'log4j' in line.lower() and any(char.isdigit() for char in line):
                        print(f"[DEBUG] Log4j 포함된 라인: {line.strip()}")
                        
        except Exception as e:
            print(f"[DEBUG] 빌드 파일 스캔 오류: {e}")
            pass

    def estimate_log4j_from_spring(self, spring_version):
        """Spring Boot 버전에서 Log4j 버전 추정 (실제 사용 버전)"""
        spring_to_log4j = {
            # 🔥 실제 Spring Boot에서 사용하는 Log4j 버전 (취약!)
            '2.6.1': '2.14.1',  # Spring Boot 2.6.1 → Log4j 2.14.1 (취약)
            '2.6.0': '2.14.1',  # Spring Boot 2.6.0 → Log4j 2.14.1 (취약)
            '2.5.6': '2.13.3',  # Spring Boot 2.5.6 → Log4j 2.13.3 (취약)
            '2.5.': '2.13.',    # Spring Boot 2.5.x → Log4j 2.13.x (취약)
            '2.4.': '2.12.',    # Spring Boot 2.4.x → Log4j 2.12.x (일부 취약)
            '2.3.': '2.11.',    # Spring Boot 2.3.x → Log4j 2.11.x (취약)
            '2.2.': '2.10.',    # Spring Boot 2.2.x → Log4j 2.10.x (취약)
            '2.1.': '2.9.',     # Spring Boot 2.1.x → Log4j 2.9.x (취약)
            '2.0.': '2.7.',     # Spring Boot 2.0.x → Log4j 2.7.x (취약)
        }
        
        for spring_prefix, log4j_version in spring_to_log4j.items():
            if spring_version.startswith(spring_prefix):
                return log4j_version
                
        # Spring Boot 2.7+ 는 보통 안전한 Log4j를 사용
        if spring_version.startswith('2.7') or spring_version.startswith('2.8') or spring_version.startswith('2.9'):
            return "2.17.1"  # 안전한 버전
            
        return "2.14.1"  # 기본값 (취약)

    def scan_java_source(self, file_path):
        """Java 소스코드 스캔"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            # 위험한 패턴들
            risk_patterns = [
                (r'import\s+org\.apache\.logging\.log4j', 'Log4j 2.x 라이브러리 import'),
                (r'logger\.(info|error|warn|debug|fatal)\s*\([^)]*\+[^)]*\)', '문자열 연결을 통한 위험한 로깅'),
                (r'(getParameter|getHeader|getPathInfo)\([^)]+\).*?logger\.', '외부 입력이 직접 로거에 전달'),
            ]
            
            found_issues = []
            for pattern, desc in risk_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    found_issues.append(desc)
                    
            if found_issues:
                self.results.append({
                    'file': file_path.name,
                    'path': str(file_path),
                    'issues': found_issues,
                    'type': 'source_code'
                })
                
        except Exception:
            pass

    def scan_jar_file(self, file_path):
        """JAR 파일 스캔"""
        filename = file_path.name.lower()
        
        # Log4j JAR 파일 패턴
        log4j_patterns = [
            r'log4j-core-(\d+\.\d+\.\d+)\.jar',
            r'log4j-api-(\d+\.\d+\.\d+)\.jar',
            r'log4j-(\d+\.\d+\.\d+)\.jar',
        ]
        
        for pattern in log4j_patterns:
            match = re.search(pattern, filename)
            if match:
                version = match.group(1)
                print(f"\n[DEBUG] JAR 파일에서 Log4j 버전 발견: {version}")
                
                # Log4j 버전이 아직 감지되지 않았다면 업데이트
                if self.log4j_version == "감지되지 않음":
                    self.log4j_version = version
                
                if self.is_vulnerable_version(version):
                    self.results.append({
                        'file': file_path.name,
                        'path': str(file_path),
                        'issues': [f'취약한 Log4j JAR 파일 (v{version})'],
                        'type': 'jar_file'
                    })
                break

    def get_security_status(self):
        """보안 상태 판정"""
        # 1. Log4j 버전이 취약한 경우 - 최우선 판정
        if self.log4j_version != "감지되지 않음":
            if self.is_vulnerable_version(self.log4j_version):
                return "🔴 위험"
            else:
                # Log4j가 안전한 버전이면 다른 위험 요소 무시
                return "🟢 안전"
        
        # 2. Log4j 버전 불명 + 취약점 발견 = 위험
        if self.results:
            return "🔴 위험"
            
        # 3. 기본: 안전
        return "🟢 안전"

    def get_recommendations(self):
        """권장 조치사항 (장점/단점 제거 버전)"""
        # Log4j가 안전한 버전이면 권장사항 없음
        if (self.log4j_version != "감지되지 않음" and 
            not self.is_vulnerable_version(self.log4j_version)):
            return []
        
        # 취약점이 없으면 권장사항 없음
        if not self.results and self.log4j_version == "감지되지 않음":
            return []
            
        recommendations = [
            "📦 Log4j 업그레이드 (최우선 - 근본적 해결)\n     Log4j를 2.17.1 이상 또는 2.12.2, 2.3.1(보안 릴리즈)로 업그레이드"
        ]
        
        # 버전별 임시 조치사항 추가
        if self.log4j_version != "감지되지 않음" and self.is_vulnerable_version(self.log4j_version):
            version_parts = self.log4j_version.split('.')
            if len(version_parts) >= 2:
                try:
                    major_minor = f"{version_parts[0]}.{version_parts[1]}"
                    minor_version = float(f"{version_parts[0]}.{version_parts[1]}")
                    
                    # Log4j 2.10.0 이상 → JVM 옵션 사용 가능
                    if minor_version >= 2.10:
                        recommendations.append(
                            "⚡ JVM 옵션 설정 (임시 조치 - 2.10.0+ 지원)\n" +
                            "     # Java 실행 시 옵션 추가:\n" +
                            "     java -Dlog4j2.formatMsgNoLookups=true -jar myapp.jar\n" +
                            "     \n" +
                            "     # 또는 환경변수 설정:\n" +
                            "     export LOG4J_FORMAT_MSG_NO_LOOKUPS=true"
                        )
                        
                    # Log4j 2.10.0 미만 → 클래스 제거 방법
                    if minor_version < 2.10:
                        recommendations.append(
                            "🗑️ JndiLookup 클래스 제거 (임시 조치 - 2.10.0 미만용)\n" +
                            "     # log4j-core JAR 파일에서 위험 클래스 삭제:\n" +
                            "     zip -q -d log4j-core-*.jar \\\n" +
                            "       org/apache/logging/log4j/core/lookup/JndiLookup.class"
                        )
                        
                except ValueError:
                    # 버전 파싱 실패 시 기본 권장사항만 제공
                    pass
                    
        return recommendations

    def generate_report(self):
        """리포트 생성"""
        return {
            'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'scanned_files': self.file_count,
            'java_version': self.java_version,
            'log4j_version': self.log4j_version,
            'security_status': self.get_security_status(),
            'total_issues': len(self.results),
            'vulnerabilities': self.results,
            'recommendations': self.get_recommendations()
        }

def main():
    parser = argparse.ArgumentParser(
        description='Static Log4Shell Scanner - Professional vulnerability scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''예시:
  %(prog)s ./my-java-project
  %(prog)s /path/to/project --output report.json
  slog4j ~/workspace/spring-app'''
    )
    
    parser.add_argument('path', help='스캔할 프로젝트 경로')
    parser.add_argument('-o', '--output', help='결과 저장 파일 (JSON 형식)')
    parser.add_argument('--version', action='version', version='%(prog)s 0.2.3')
    parser.add_argument('-q', '--quiet', action='store_true', help='간단한 출력만 표시')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.path):
        print(f"❌ 오류: 경로 '{args.path}'를 찾을 수 없습니다.")
        return 1
        
    # 스캔 시작
    scanner = Log4ShellScanner()
    
    print(f"🔍 Log4Shell 보안 스캔 시작: {args.path}")
    print("=" * 60)
    
    scanner.scan_directory(args.path)
    
    print(f"\n✅ 스캔 완료: {scanner.file_count:,}개 파일 검사")
    
    # 결과 출력
    report = scanner.generate_report()
    
    if not args.quiet:
        print(f"\n📊 스캔 결과 요약")
        print("-" * 40)
        print(f"  📅 스캔 시간: {report['scan_time']}")
        print(f"  📁 스캔 파일: {report['scanned_files']:,}개")
        print(f"  ☕ Java 버전: {report['java_version']}")
        print(f"  📚 Log4j 버전: {report['log4j_version']}")
        print(f"  🛡️  보안 상태: {report['security_status']}")
        print(f"  🔍 발견사항: {report['total_issues']}개")
        
        # 발견된 취약점 출력
        if report['vulnerabilities']:
            print(f"\n⚠️ 발견된 위험 ({len(report['vulnerabilities'])}개):")
            for i, vuln in enumerate(report['vulnerabilities'], 1):
                issues_text = " + ".join(vuln['issues'])
                print(f"  {i}. {vuln['file']}")
                print(f"     {issues_text}")
                
        # 권장 조치사항
        if report['recommendations']:
            print(f"\n🚨 긴급 조치사항:")
            for i, rec in enumerate(report['recommendations'], 1):
                print(f"  {i}. {rec}")
    
    # JSON 출력
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"\n💾 상세 결과 저장: {args.output}")
    
    return 0

if __name__ == '__main__':
    exit(main())