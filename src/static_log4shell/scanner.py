#!/usr/bin/env python3
import os
import re
import json
import argparse
from datetime import datetime
import sys

class Log4ShellScanner:
    def __init__(self):
        self.results = []
        self.scanned_files = set()
        self.java_version = "감지되지 않음"
        self.log4j_version = "감지되지 않음"
        self.has_vulnerable_log4j = False
        
        # CVE-2021-44228 취약한 버전 범위: 2.2.0-beta9 ~ 2.15.0
        self.vulnerable_versions = [
            r'2\.([2-9]|1[0-5])\..*',     # 2.2.x ~ 2.15.x
            r'2\.2\.0-beta[9]',           # 2.2.0-beta9
            r'2\.1[0-5]\..*',             # 2.10.x ~ 2.15.x  
            r'1\..*'                       # 1.x 전체 (더 위험)
        ]
        
        # 안전한 버전: 2.16.0 이상 (2.12.2, 2.12.3, 2.3.1 제외된 보안 릴리즈)
        self.safe_versions = [
            r'2\.1[6-9]\..*',             # 2.16.x ~ 2.19.x
            r'2\.[2-9][0-9]\..*',         # 2.20.x 이상
            r'2\.12\.[23]',               # 2.12.2, 2.12.3 (보안 릴리즈)
            r'2\.3\.1'                    # 2.3.1 (보안 릴리즈)
        ]

    def scan_directory(self, path):
        """디렉토리 스캔"""
        print(f"🔍 Log4Shell 보안 스캔 시작: {path}")
        print("=" * 60)
        print("📂 파일 스캔 진행 중...")
        
        file_count = 0
        for root, dirs, files in os.walk(path):
            for file in files:
                file_path = os.path.join(root, file)
                abs_path = os.path.abspath(file_path)
                
                if abs_path in self.scanned_files:
                    continue
                    
                self.scanned_files.add(abs_path)
                file_count += 1
                
                # 실시간 진행상황 표시
                sys.stdout.write(f"    > {file[:30]:<30}\r")
                sys.stdout.flush()
                
                try:
                    if file.endswith(('.jar', '.war')):
                        self.scan_jar_file(file_path, file)
                    elif file.endswith('.java'):
                        self.scan_java_source(file_path)
                    elif file.endswith(('pom.xml', 'build.gradle')):
                        self.scan_build_file(file_path)
                except:
                    continue
        
        print(f"\n✅ 스캔 완료: {file_count}개 파일 검사\n")

    def is_vulnerable_version(self, version):
        """버전이 취약한지 확인"""
        return any(re.match(pattern, version) for pattern in self.vulnerable_versions)
    
    def is_safe_version(self, version):
        """버전이 안전한지 확인"""
        return any(re.match(pattern, version) for pattern in self.safe_versions)

    def scan_jar_file(self, file_path, filename):
        """JAR 파일 스캔"""
        # log4j JAR 파일 패턴 체크
        log4j_jar_pattern = r'log4j-(?:core|api)-(\d+\.\d+(?:\.\d+)?(?:-\w+)?)'
        match = re.search(log4j_jar_pattern, filename, re.IGNORECASE)
        
        if match:
            version = match.group(1)
            if self.log4j_version == "감지되지 않음":
                self.log4j_version = version
            
            if self.is_vulnerable_version(version):
                self.has_vulnerable_log4j = True
                self.add_vulnerability(
                    'VULNERABLE_JAR',
                    file_path,
                    f'🚨 취약한 Log4j JAR 파일 (v{version}) - CVE-2021-44228 영향받음',
                    'CRITICAL'
                )
                print(f"\n    🚨 위험 발견: {filename}")
            elif self.is_safe_version(version):
                self.add_vulnerability(
                    'SAFE_JAR', 
                    file_path,
                    f'✅ 안전한 Log4j JAR 파일 (v{version}) - 패치된 버전',
                    'SAFE'
                )

    def scan_java_source(self, file_path):
        """Java 소스코드 스캔"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Log4j 사용 패턴 검사
            log4j_patterns = [
                (r'import\s+org\.apache\.logging\.log4j', 'Log4j 2.x 라이브러리 import'),
                (r'import\s+org\.apache\.log4j', 'Log4j 1.x 라이브러리 import (더 위험)'),
                (r'LogManager\.getLogger', 'LogManager 사용'),
                (r'Logger\s+logger\s*=.*LogManager', 'Logger 인스턴스 생성'),
            ]
            
            for pattern, description in log4j_patterns:
                if re.search(pattern, content):
                    # 위험한 로깅 패턴 추가 검사
                    dangerous_patterns = [
                        (r'logger\.(info|error|warn|debug)\s*\([^)]*\+[^)]*\)', '문자열 연결을 통한 위험한 로깅'),
                        (r'logger\.(info|error|warn|debug)\s*\(\s*[^"]*\$\{[^}]*\}', '직접적인 ${} 패턴 사용'),
                        (r'request\.getParameter.*logger\.(info|error|warn|debug)', '사용자 입력을 직접 로깅')
                    ]
                    
                    found_dangerous = False
                    for danger_pattern, danger_desc in dangerous_patterns:
                        if re.search(danger_pattern, content):
                            self.add_vulnerability(
                                'DANGEROUS_LOGGING',
                                file_path,
                                f'{description} + {danger_desc}',
                                'HIGH'
                            )
                            found_dangerous = True
                            break
                    
                    if not found_dangerous:
                        self.add_vulnerability(
                            'LOG4J_USAGE',
                            file_path,
                            f'{description} 감지',
                            'INFO'
                        )
                    break
        except:
            pass

    def scan_build_file(self, file_path):
        """빌드 파일 스캔 (pom.xml, build.gradle)"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Java 버전 추출
            java_patterns = [
                r'<maven\.compiler\.source>(\d+\.?\d*)<',
                r'<java\.version>(\d+\.?\d*)<', 
                r'sourceCompatibility\s*=\s*[\'"]?(\d+\.?\d*)[\'"]?',
                r'<source>(\d+\.?\d*)</source>',
                r'<target>(\d+\.?\d*)</target>'
            ]
            
            for pattern in java_patterns:
                match = re.search(pattern, content)
                if match and self.java_version == "감지되지 않음":
                    self.java_version = match.group(1)
                    break

            # Log4j 의존성 검사  
            log4j_dependency_patterns = [
                r'<artifactId>log4j-(?:core|api)</artifactId>.*?<version>(\d+\.\d+(?:\.\d+)?(?:-\w+)?)</version>',
                r'log4j-(?:core|api)[\'"]?\s*:\s*[\'"]?(\d+\.\d+(?:\.\d+)?(?:-\w+)?)',
                r'implementation.*log4j.*[\'"](\d+\.\d+(?:\.\d+)?(?:-\w+)?)[\'"]',
                r'compile.*log4j.*[\'"](\d+\.\d+(?:\.\d+)?(?:-\w+)?)[\'"]'
            ]
            
            for pattern in log4j_dependency_patterns:
                matches = re.findall(pattern, content, re.DOTALL | re.IGNORECASE)
                for version in matches:
                    if self.log4j_version == "감지되지 않음":
                        self.log4j_version = version
                    
                    if self.is_vulnerable_version(version):
                        self.has_vulnerable_log4j = True
                        self.add_vulnerability(
                            'VULNERABLE_DEPENDENCY',
                            file_path,
                            f'🚨 취약한 Log4j 의존성 (v{version}) - CVE-2021-44228 영향',
                            'CRITICAL'
                        )
                        print(f"\n    🚨 위험 발견: {os.path.basename(file_path)}")
                    elif self.is_safe_version(version):
                        self.add_vulnerability(
                            'SAFE_DEPENDENCY',
                            file_path,
                            f'✅ 안전한 Log4j 의존성 (v{version}) - 패치된 버전',
                            'SAFE'
                        )
                    else:
                        self.add_vulnerability(
                            'UNKNOWN_DEPENDENCY',
                            file_path,
                            f'⚠️ 확인 필요한 Log4j 의존성 (v{version})',
                            'MEDIUM'
                        )
                    break

        except:
            pass

    def add_vulnerability(self, vuln_type, file_path, description, severity):
        """취약점 추가"""
        self.results.append({
            'type': vuln_type,
            'file_path': file_path,
            'description': description,
            'severity': severity,
            'timestamp': datetime.now().isoformat()
        })

    def get_security_status(self):
        """보안 상태 평가"""
        if not self.results:
            return "🟡 정보없음 (Log4j 사용 감지되지 않음)", "정보없음"
        
        has_critical = any(v['severity'] == 'CRITICAL' for v in self.results)
        has_high = any(v['severity'] == 'HIGH' for v in self.results)
        has_safe = any(v['severity'] == 'SAFE' for v in self.results)
        
        if has_critical:
            return "🔴 매우 위험 (즉시 조치 필요)", "매우 위험"
        elif has_high:
            return "🟠 위험 (조치 권장)", "위험"
        elif has_safe:
            return "🟢 안전 (패치된 버전 사용)", "안전"
        else:
            return "🟡 확인 필요", "확인 필요"

    def print_results(self):
        """결과 출력"""
        security_display, security_level = self.get_security_status()
        
        # 취약점 분류
        critical = [v for v in self.results if v['severity'] == 'CRITICAL']
        high = [v for v in self.results if v['severity'] == 'HIGH']
        medium = [v for v in self.results if v['severity'] == 'MEDIUM']
        safe = [v for v in self.results if v['severity'] == 'SAFE']

        print("📊 스캔 결과 요약")
        print("-" * 40)
        print(f"  📅 스캔 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  📁 스캔 파일: {len(self.scanned_files):,}개")
        print(f"  ☕ Java 버전: {self.java_version}")
        print(f"  📚 Log4j 버전: {self.log4j_version}")
        print(f"  🛡️  보안 상태: {security_display}")
        print(f"  🔍 발견사항: {len(self.results)}개")

        # 상세 발견사항
        if critical:
            print(f"\n🚨 심각한 취약점 ({len(critical)}개):")
            for i, vuln in enumerate(critical, 1):
                print(f"  {i}. {os.path.basename(vuln['file_path'])}")
                print(f"     {vuln['description']}")
        
        if high:
            print(f"\n⚠️ 높은 위험 ({len(high)}개):")
            for i, vuln in enumerate(high, 1):
                print(f"  {i}. {os.path.basename(vuln['file_path'])}")
                print(f"     {vuln['description']}")
        
        if medium:
            print(f"\n📋 확인 필요 ({len(medium)}개):")
            for i, vuln in enumerate(medium, 1):
                print(f"  {i}. {os.path.basename(vuln['file_path'])}")
                print(f"     {vuln['description']}")
        
        if safe:
            print(f"\n✅ 안전한 구성 ({len(safe)}개):")
            for i, vuln in enumerate(safe[:3], 1):  # 최대 3개만 표시
                print(f"  {i}. {os.path.basename(vuln['file_path'])}")
                print(f"     {vuln['description']}")
            if len(safe) > 3:
                print(f"     ... 외 {len(safe)-3}개 더")

        self.print_recommendations()

    def print_recommendations(self):
        """권장 조치사항 출력 (취약점이 있을 때만)"""
        if not self.has_vulnerable_log4j and not any(v['severity'] in ['CRITICAL', 'HIGH'] for v in self.results):
            if any(v['severity'] == 'SAFE' for v in self.results):
                print("\n🎉 축하합니다! 안전한 Log4j 버전을 사용하고 있습니다!")
            else:
                print("\n📋 Log4j 사용이 감지되지 않았습니다.")
            print("💡 일반 권장사항:")
            print("  • 의존성을 정기적으로 업데이트하세요")
            print("  • 보안 스캔을 정기적으로 수행하세요")
            return

        print("\n🚨 긴급 조치사항:")
        
        # 1. 버전 업그레이드 (가장 우선)
        print("  1. 📦 Log4j 업그레이드 (최우선)")
        print("     Log4j를 2.17.1 이상 또는 2.12.2, 2.3.1(보안 릴리즈)로 업그레이드")
        
        # 2. JVM 옵션 (2.10.0 이상용)
        if self.log4j_version != "감지되지 않음":
            try:
                version_parts = self.log4j_version.split('.')
                major, minor = int(version_parts[0]), int(version_parts[1])
                if major > 2 or (major == 2 and minor >= 10):
                    print("  2. ⚡ JVM 옵션 적용 (임시 완화)")
                    print("     -Dlog4j2.formatMsgNoLookups=true")
            except:
                print("  2. ⚡ JVM 옵션 적용 (임시 완화)")
                print("     -Dlog4j2.formatMsgNoLookups=true")
        
        # 3. JndiLookup 클래스 제거 (2.10.0 미만용)
        print("  3. 🗑️ JndiLookup 클래스 제거 (2.10.0 미만용)")
        print("     zip -q -d log4j-core-*.jar \\")
        print("       org/apache/logging/log4j/core/lookup/JndiLookup.class")
        print("     ⚠️ 주의: JAR 파일 무결성 검증 실패 가능")

        print("\n📋 추가 권장사항:")
        print("  • 네트워크 아웃바운드 제한 (LDAP/RMI 포트 차단)")
        print("  • 로깅 시 파라미터화된 메시지 사용")
        print("  • CI/CD 파이프라인에 보안 스캔 통합")

    def save_report(self, output_file):
        """리포트 저장"""
        security_display, security_level = self.get_security_status()
        
        report = {
            'scan_time': datetime.now().isoformat(),
            'total_files': len(self.scanned_files),
            'java_version': self.java_version,
            'log4j_version': self.log4j_version,
            'security_status': security_level,
            'has_vulnerable_log4j': self.has_vulnerable_log4j,
            'total_findings': len(self.results),
            'findings_by_severity': {
                'critical': len([v for v in self.results if v['severity'] == 'CRITICAL']),
                'high': len([v for v in self.results if v['severity'] == 'HIGH']),
                'medium': len([v for v in self.results if v['severity'] == 'MEDIUM']),
                'safe': len([v for v in self.results if v['severity'] == 'SAFE'])
            },
            'findings': self.results
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"\n💾 상세 결과 저장: {os.path.abspath(output_file)}")

def main():
    parser = argparse.ArgumentParser(
        description="Static Log4Shell Scanner - Professional vulnerability scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""예시:
  static-log4shell ./my-java-project
  static-log4shell /path/to/project --output report.json
  slog4j ~/workspace/spring-app"""
    )
    
    parser.add_argument('path', help='스캔할 프로젝트 경로')
    parser.add_argument('-o', '--output', help='결과 저장 파일 (JSON 형식)')
    parser.add_argument('--version', action='version', version='static-log4shell 0.1.1')
    parser.add_argument('-q', '--quiet', action='store_true', help='간단한 출력만 표시')

    args = parser.parse_args()

    if not os.path.exists(args.path):
        print(f"❌ 경로를 찾을 수 없습니다: {args.path}")
        return 1

    scanner = Log4ShellScanner()
    
    try:
        scanner.scan_directory(args.path)
        
        if not args.quiet:
            scanner.print_results()
        else:
            _, security_level = scanner.get_security_status()
            print(f"📊 결과: {len(scanner.results)}개 발견사항, 상태: {security_level}")
        
        if args.output:
            scanner.save_report(args.output)
            
    except KeyboardInterrupt:
        print("\n\n⚠️ 사용자에 의해 스캔이 중단되었습니다.")
        return 1
    except Exception as e:
        print(f"\n❌ 스캔 중 오류 발생: {e}")
        return 1

    return 0

if __name__ == '__main__':
    exit(main())