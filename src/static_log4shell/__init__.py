"""
Static Log4Shell Scanner
Professional Log4Shell (CVE-2021-44228) vulnerability scanner
"""

__version__ = "0.1.0"
__author__ = "YourTeam"
__email__ = "your-email@example.com"
__description__ = "Static analysis scanner for Log4Shell vulnerabilities"

# 메인 클래스를 쉽게 import할 수 있도록 설정
from .scanner import Log4ShellScanner, scan_project

# 사용자가 라이브러리를 import할 때 바로 사용할 수 있는 것들
__all__ = [
    "Log4ShellScanner",
    "scan_project",
    "__version__",
    "__author__",
    "__description__",
]

# 간단한 사용법 함수
def quick_scan(path):
    """
    빠른 스캔 함수
    
    Args:
        path (str): 스캔할 프로젝트 경로
        
    Returns:
        dict: 스캔 결과 보고서
    """
    return scan_project(path)


def version_info():
    """버전 정보 출력"""
    return {
        'version': __version__,
        'author': __author__,
        'description': __description__
    }