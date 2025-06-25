#!/usr/bin/env python3
"""Setup script for pythmap - Network Port Scanner and Security Assessment Tool"""

from setuptools import setup, find_packages
import os

# Read the contents of README file
this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name="pythmap",
    version="1.0.0",
    author="pythmap authors",
    description="A comprehensive network port scanner and security assessment tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/TheBitty/Pythmap",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "Topic :: System :: Networking",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",  # Update based on your license
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS :: MacOS X",
    ],
    python_requires=">=3.6",
    install_requires=[
        "python-nmap>=0.7.1",
        "scapy>=2.4.5",
    ],
    entry_points={
        "console_scripts": [
            "pythmap=pythmap.main:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)