"""
Static Log4Shell Scanner
A professional vulnerability scanner for Log4Shell (CVE-2021-44228)

This package provides tools to detect Log4Shell vulnerabilities in Java projects
by scanning JAR files, source code, and build configuration files.
"""

__version__ = "0.2.5"
__author__ = "YourTeam"
__email__ = "your-email@example.com"
__description__ = "Static Log4Shell Scanner - Professional vulnerability scanner"

# Import main classes and functions
from .scanner import Log4ShellScanner

# Define what gets exported when someone does "from static_log4shell import *"
__all__ = [
    "Log4ShellScanner",
]

# Package metadata
def get_version():
    """Get the current version of the package."""
    return __version__

def get_info():
    """Get package information."""
    return {
        "name": "static-log4shell",
        "version": __version__,
        "author": __author__,
        "email": __email__,
        "description": __description__
    }