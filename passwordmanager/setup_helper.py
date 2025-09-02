import subprocess
import sys

def install(package):
    """Install a package using pip."""
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])

def full_setup():
    """Install necessary libraries for the Secure Password Manager."""
    required_packages = [
        'tkinter',
        'cryptography',
        'pyperclip',
        'keyring'
    ]
    
    for package in required_packages:
        install(package)