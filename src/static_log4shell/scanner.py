"""
Log4Shell Professional Scanner
핵심 스캐닝 로직과 실행 코드
"""

import os
import re
import json
import sys
import subprocess
from datetime import datetime
from pathlib import Path

class Log4ShellScanner:
    """Log4Shell 취약점 전문 스캐너"""
    
    def __init__(self):
        self.results = []
        self.scanned_files = set()
        self.found_issues = set()
        self.java_version = "감지되지 않음"
        self.log4j_version = "감지되지 않음"
        self.defense_score = 0
        
        # 취약한 Log4j 버전 패턴 (CVE-2021-44228)
        self.vuln_patterns = [
            r'log4j-core-2\.([0-9]|1[0-5])\..*\.jar',
            r'log4j-api-2\.([0-9]|1[0-5])\..*\.jar',
            r'log4j-1\..*\.jar'
        ]

    def scan_project(self, path):
        """
        프로젝트 전체 보안 스캔
        
        Args:
            path (str): 스캔할 프로젝트 경로
            
        Returns:
            dict: 스캔 결과 보고서
        """
        print(f"🔍 Log4Shell 보안 스캔 시작: {path}")
        print("=" * 60)
        
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"경로를 찾을 수 없습니다: {path}")
        
        # 진행 상황 표시
        print("📂 파일 스캔 진행 중...")
        
        # 재귀적으로 모든 파일 스캔
        for root in path.rglob("*"):
            if root.is_file():
                self._scan_file(root)
        
        print(f"\n✅ 스캔 완료: {len(self.scanned_files)}개 파일 검사")
        return self.generate_report()

    def _scan_file(self, file_path):
        """개별 파일 스캔"""
        file_str = str(file_path)
        if file_str in self.scanned_files:
            return
        self.scanned_files.add(file_str)
        
        # 실시간 파일 표시 (같은 줄에서 업데이트)
        display_name = file_path.name[:35]
        sys.stdout.write(f"    > {display_name:<35} \r")
        sys.stdout.flush()
        
        # 파일 타입별 검사
        suffix = file_path.suffix.lower()
        name = file_path.name.lower()
        
        if suffix in ['.jar', '.war', '.ear']:
            self._check_jar_file(file_path)
        elif suffix == '.java':
            self._check_source_code(file_path)
        elif name in ['pom.xml', 'build.gradle']:
            self._check_build_config(file_path)
        elif name in ['application.properties', 'log4j2.xml', 'log4j.properties']:
            self._check_config_files(file_path)

    def _check_jar_file(self, file_path):
        """JAR 파일 취약점 검사"""
        filename = file_path.name
        
        for pattern in self.vuln_patterns:
            if re.match(pattern, filename, re.IGNORECASE):
                version = self._extract_version_from_filename(filename)
                
                # JndiLookup 클래스 제거 확인
                jndi_status = self._check_jndi_removal(file_path)
                
                if jndi_status == "제거됨":
                    severity = "보통"
                    desc = f"취약한 버전이지만 JndiLookup 클래스 제거됨 (버전: {version})"
                else:
                    severity = "높음"
                    desc = f"취약한 Log4j JAR 파일 발견 (버전: {version})"
                
                self._add_finding("JAR_VULNERABILITY", str(file_path), desc, severity)
                break

    def _check_jndi_removal(self, jar_path):
        """JAR 파일에서 JndiLookup 클래스 제거 확인"""
        try:
            # unzip 명령어로 JAR 내용 확인 (간단한 방법)
            result = subprocess.run(
                ['unzip', '-l', str(jar_path)], 
                capture_output=True, 
                text=True, 
                timeout=5
            )
            
            if 'JndiLookup.class' in result.stdout:
                return "존재"
            else:
                return "제거됨"
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            return "확인불가"

    def _check_source_code(self, file_path):
        """소스코드 보안 위험 패턴 검사"""
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            
            # 고위험 패턴들
            risk_patterns = [
                # 외부 입력이 직접 로깅되는 경우 (가장 위험)
                (r'logger\.(info|error|warn|debug|fatal)\([^)]*(?:request\.|getParameter|getHeader)[^)]*\)', 
                 "외부 입력 데이터가 직접 로깅됨 (JNDI 인젝션 위험)", "높음"),
                
                # 문자열 연결 방식 로깅
                (r'logger\.(info|error|warn|debug|fatal)\([^)]*\+[^)]*\)', 
                 "문자열 연결 방식 로깅 (입력 검증 필요)", "보통"),
                
                # 하드코딩된 JNDI 패턴
                (r'\$\{jndi:', 
                 "JNDI 패턴 하드코딩됨 (즉시 제거 필요)", "높음"),
                
                # Log4j import 확인
                (r'import\s+org\.apache\.logging\.log4j', 
                 "Log4j 라이브러리 사용 중 (버전 확인 필요)", "낮음"),
                
                # 보안 필터링 함수 존재 (좋은 패턴)
                (r'(sanitize|validate|escape|filter).*(?:before|prior).*log', 
                 "입력 검증 로직 발견 (보안 강화됨)", "정보"),
            ]
            
            for pattern, desc, severity in risk_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    self._add_finding("SOURCE_RISK", str(file_path), desc, severity)
                    break  # 첫 번째 패턴만 보고
                    
        except Exception:
            pass

    def _check_build_config(self, file_path):
        """빌드 설정에서 Log4j 버전 및 방어 설정 검사"""
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            
            # 버전 정보 추출
            self._extract_versions(content)
            
            # Log4j 의존성이 있는 경우만 검사
            if 'log4j' in content.lower():
                # 방어 설정 확인
                defenses = self._check_defense_configurations(content)
                
                # Log4j 버전 취약성 검사
                if self.log4j_version != "감지되지 않음":
                    if self._is_vulnerable_version(self.log4j_version):
                        if defenses:
                            desc = f"취약한 Log4j 버전 사용 중 (v{self.log4j_version}) - 방어설정: {', '.join(defenses)}"
                            severity = "보통"
                        else:
                            desc = f"취약한 Log4j 버전 사용 중 (v{self.log4j_version}) - 방어설정 없음"
                            severity = "높음"
                    else:
                        desc = f"안전한 Log4j 버전 사용 중 (v{self.log4j_version})"
                        severity = "낮음"
                else:
                    desc = "Log4j 의존성 발견 (정확한 버전 추출 실패)"
                    severity = "보통"
                
                self._add_finding("BUILD_CONFIG", str(file_path), desc, severity)
                
        except Exception:
            pass

    def _check_config_files(self, file_path):
        """Log4j 설정 파일 검사"""
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            
            # 위험한 설정들
            risky_configs = [
                ('JndiLookup', '🚨 JNDI Lookup 활성화됨'),
                ('<JndiLookup', '🚨 JNDI Lookup 설정 발견'),
                ('formatMsgNoLookups.*false', '🚨 보안 옵션 비활성화'),
            ]
            
            # 안전한 설정들
            safe_configs = [
                ('formatMsgNoLookups.*true', '✅ 보안 옵션 활성화됨'),
                ('LOG4J_FORMAT_MSG_NO_LOOKUPS.*true', '✅ 환경변수 보안 설정'),
            ]
            
            for config, desc in risky_configs:
                if re.search(config, content, re.IGNORECASE):
                    self._add_finding("CONFIG_RISK", str(file_path), desc, "높음")
            
            for config, desc in safe_configs:
                if re.search(config, content, re.IGNORECASE):
                    self._add_finding("CONFIG_SAFE", str(file_path), desc, "정보")
                    self.defense_score += 15
                    
        except Exception:
            pass

    def _extract_versions(self, content):
        """빌드 파일에서 Java 및 Log4j 버전 추출"""
        # Java 버전 추출
        java_patterns = [
            r'java\.version["\']?\s*[:=]\s*["\']?([0-9]+\.?[0-9]*)',
            r'sourceCompatibility\s*[:=]\s*["\']?([0-9]+\.?[0-9]*)',
            r'target["\']?\s*[:=]\s*["\']?([0-9]+\.?[0-9]*)'
        ]
        
        for pattern in java_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                self.java_version = match.group(1)
                break
        
        # Log4j 버전 추출  
        log4j_patterns = [
            r'log4j[^>]*?(?:version|:)\s*["\']?([0-9]+\.[0-9]+\.[0-9]+)',
            r'<version>([0-9]+\.[0-9]+\.[0-9]+)</version>.*log4j',
            r'org\.apache\.logging\.log4j[^:]*:([0-9]+\.[0-9]+\.[0-9]+)'
        ]
        
        for pattern in log4j_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                self.log4j_version = match.group(1)
                break

    def _check_defense_configurations(self, content):
        """방어 설정 확인"""
        defenses = []
        
        # JVM 옵션 확인
        if 'formatMsgNoLookups=true' in content:
            defenses.append("JVM옵션")
            self.defense_score += 25
        
        # 환경변수 설정
        if 'LOG4J_FORMAT_MSG_NO_LOOKUPS' in content:
            defenses.append("환경변수")
            self.defense_score += 25
        
        # JNDI 관련 의존성 제외
        if re.search(r'exclude.*jndi', content, re.IGNORECASE):
            defenses.append("의존성제외")
            self.defense_score += 25
        
        # 버전 업그레이드
        if self.log4j_version != "감지되지 않음" and not self._is_vulnerable_version(self.log4j_version):
            defenses.append("버전업그레이드")
            self.defense_score += 25
        
        return defenses

    def _is_vulnerable_version(self, version):
        """Log4j 버전 취약성 판단"""
        try:
            parts = version.split('.')
            major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2])
            
            # 2.16.0 이상은 안전
            if major == 2 and (minor > 15 or (minor == 15 and patch > 0)):
                return False
            # 2.12.2, 2.12.3, 2.3.1은 보안 릴리즈
            elif major == 2 and ((minor == 12 and patch in [2, 3]) or (minor == 3 and patch == 1)):
                return False
            # 나머지는 취약
            elif major <= 2:
                return True
            
            return False
        except:
            return True  # 파싱 실패시 안전을 위해 취약하다고 가정

    def _extract_version_from_filename(self, filename):
        """파일명에서 버전 추출"""
        match = re.search(r'([0-9]+\.[0-9]+\.[0-9]+)', filename)
        return match.group(1) if match else "알수없음"

    def _add_finding(self, category, file_path, description, severity):
        """발견사항 추가"""
        finding_key = f"{category}:{file_path}:{description}"
        if finding_key not in self.found_issues:
            self.found_issues.add(finding_key)
            
            self.results.append({
                'category': category,
                'file_path': file_path,
                'description': description,
                'severity': severity,
                'timestamp': datetime.now().isoformat()
            })
            
            # 높은 위험도 발견시 즉시 알림
            if severity == "높음":
                print(f"\n    🚨 위험 발견: {os.path.basename(file_path)}")

    def _get_risk_assessment(self):
        """위험도 평가"""
        high_count = len([r for r in self.results if r['severity'] == '높음'])
        medium_count = len([r for r in self.results if r['severity'] == '보통'])
        
        if high_count > 0 and self.defense_score < 50:
            return "🔴 매우 높음", "즉시 조치 필요"
        elif high_count > 0 or (medium_count > 1 and self.defense_score < 70):
            return "🟠 높음", "빠른 조치 권장"
        elif medium_count > 0 or self.defense_score < 80:
            return "🟡 보통", "개선 권장"
        else:
            return "🟢 양호", "현재 상태 유지"

    def _generate_recommendations(self):
        """맞춤형 권장사항 생성"""
        recommendations = []
        high_risks = [r for r in self.results if r['severity'] == '높음']
        
        if high_risks:
            recommendations.append("1. 🚨 긴급: Log4j를 2.17.1 이상으로 업그레이드")
            
        if self.defense_score < 50:
            recommendations.append("2. ⚡ 임시조치: JVM 옵션 -Dlog4j2.formatMsgNoLookups=true 적용")
            
        if any('외부 입력' in r['description'] for r in self.results):
            recommendations.append("3. 🛡️ 코드개선: 로깅 전 입력값 검증 로직 추가")
            
        if self.defense_score < 75:
            recommendations.append("4. 🔧 환경설정: LOG4J_FORMAT_MSG_NO_LOOKUPS=true 환경변수 설정")
            
        return recommendations

    def generate_report(self):
        """최종 보고서 생성"""
        risk_level, risk_msg = self._get_risk_assessment()
        
        return {
            'scan_summary': {
                'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'scanned_files': len(self.scanned_files),
                'total_findings': len(self.results),
                'java_version': self.java_version,
                'log4j_version': self.log4j_version,
                'defense_score': min(self.defense_score, 100),
                'risk_level': risk_level,
                'risk_message': risk_msg
            },
            'findings': self.results,
            'recommendations': self._generate_recommendations()
        }


def scan_project(path, output_file=None, verbose=True):
    """
    편의 함수: 프로젝트 스캔
    
    Args:
        path (str): 스캔할 프로젝트 경로
        output_file (str, optional): 결과 저장 파일 경로
        verbose (bool): 상세 출력 여부
        
    Returns:
        dict: 스캔 결과 보고서
    """
    scanner = Log4ShellScanner()
    report = scanner.scan_project(path)
    
    if verbose:
        # 결과 출력
        summary = report['scan_summary']
        print(f"\n📊 스캔 결과 요약")
        print("-" * 40)
        print(f"  📅 스캔 시간: {summary['scan_time']}")
        print(f"  📁 스캔 파일: {summary['scanned_files']:,}개")
        print(f"  ☕ Java 버전: {summary['java_version']}")
        print(f"  📚 Log4j 버전: {summary['log4j_version']}")
        print(f"  🛡️  방어 점수: {summary['defense_score']}/100점")
        print(f"  ⚠️  위험도: {summary['risk_level']} ({summary['risk_message']})")
        print(f"  🔍 발견사항: {summary['total_findings']}개")
        
        # 권장사항 출력
        if report['recommendations']:
            print(f"\n💡 권장 조치사항:")
            for rec in report['recommendations']:
                print(f"  {rec}")
    
    # 파일 저장
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"\n💾 보고서 저장: {output_file}")
    
    return report


def main():
    """CLI 진입점"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Static Log4Shell Scanner - Professional vulnerability scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  static-log4shell ./my-java-project
  static-log4shell /path/to/project --output report.json
  slog4j ~/workspace/spring-app
        """
    )
    
    parser.add_argument(
        'path', 
        help='스캔할 프로젝트 경로'
    )
    parser.add_argument(
        '-o', '--output', 
        help='결과 저장 파일 (JSON 형식)'
    )
    parser.add_argument(
        '--version', 
        action='version', 
        version='Static Log4Shell Scanner v0.1.0'
    )
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='간단한 출력만 표시'
    )
    
    args = parser.parse_args()
    
    try:
        # 스캔 실행
        scan_project(args.path, args.output, verbose=not args.quiet)
        
    except FileNotFoundError as e:
        print(f"❌ 오류: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n⚠️ 사용자에 의해 중단됨")
        sys.exit(1)
    except Exception as e:
        print(f"❌ 예상치 못한 오류: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()