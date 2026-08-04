#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="network-traffic-analyzer",
    version="1.0.0",
    author="Falconmx1",
    author_email="falconmx1@example.com",
    description="Network Traffic Analyzer - Herramienta en tiempo real para monitoreo de red",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Falconmx1/Network-Traffic-Analyzer",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Operating System :: Unix",
        "Operating System :: MacOS",
        "Operating System :: Microsoft :: Windows",
    ],
    python_requires=">=3.8",
    install_requires=[
        "scapy>=2.4.5",
        "reportlab>=4.0.0",
        "matplotlib>=3.5.0",
        "pyyaml>=6.0",
        "tabulate>=0.9.0",
        "prettytable>=3.6.0",
        "colorama>=0.4.6",
    ],
    entry_points={
        "console_scripts": [
            "nta=main:main",
        ],
    },
)
