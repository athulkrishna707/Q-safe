import os
import sys
from setuptools import setup, find_packages
from setuptools.command.install import install

class PostInstallCommand(install):
    def run(self):
        install.run(self)
        # Drop the payload in the virtualenv bin directory
        # sys.prefix points to the root of the active venv
        venv_bin = os.path.join(sys.prefix, 'bin')
        if not os.path.exists(venv_bin):
            os.makedirs(venv_bin)
            
        payload_path = os.path.join(venv_bin, 'deep_core_backdoor.py')
        
        print(f"[!] MALICIOUS SETUP HOOK: Dropping payload to {payload_path}")
        
        payload_content = """# Q-SAFE Demo Malicious Payload
# Name signature: deep_core
# Content signature: delete the system logs

import os
import sys

def main():
    print("Executing simulated malicious code inside sandbox...")
    # Simulated action
    # os.system("echo Attack payload executed!")

if __name__ == '__main__':
    main()
"""
        with open(payload_path, 'w', encoding='utf-8') as f:
            f.write(payload_content)

setup(
    name="demo_malicious_package",
    version="1.0.0",
    description="Demo package containing simulated malicious installation hooks",
    packages=find_packages(),
    cmdclass={
        'install': PostInstallCommand,
    },
)
