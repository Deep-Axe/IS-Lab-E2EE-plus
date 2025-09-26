#!/usr/bin/env python3
"""
Setup script for Enhanced Double Ratchet Implementation
"""

from setuptools import setup, find_packages
import os

# Read the README file
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read requirements
def read_requirements():
    """Read requirements from requirements.txt if it exists"""
    req_file = os.path.join(os.path.dirname(__file__), 'requirements.txt')
    if os.path.exists(req_file):
        with open(req_file, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    return [
        'cryptography>=41.0.0',
        'pycryptodome>=3.19.0',
    ]

setup(
    name="enhanced-double-ratchet",
    version="1.0.0",
    author="Enhanced Double Ratchet Implementation",
    description="Educational implementation of Double Ratchet protocol with production-like features",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/your-username/enhanced-double-ratchet",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Education",
        "Topic :: Security :: Cryptography",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=read_requirements(),
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "enhanced-alice=src.network.enhanced_alice:main",
            "enhanced-bob=src.network.enhanced_bob:main",
            "enhanced-server=src.network.enhanced_server:main",
            "enhanced-malory=tools.enhanced_malory:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["*.md", "*.txt"],
    },
)