# setup_helper.py
import sys
import subprocess

REQUIRED_PACKAGES = ["cryptography", "keyring", "pyperclip"]

def install_missing_packages():
    for pkg in REQUIRED_PACKAGES:
        try:
            __import__(pkg.replace("-", "_"))
        except ImportError:
            subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])

def full_setup():
    install_missing_packages()
