"""
M7 SSRF — Setup configuration.
Made by Milkyway Intelligence | Author: Sharlix Martin
"""

from setuptools import setup, find_packages

setup(
    name="m7ssrf",
    version="1.0.0",
    author="Sharlix Martin",
    author_email="sharlix@milkyway.intel",
    description="M7 SSRF — Advanced SSRF Research Tool by Milkyway Intelligence",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/Sharlix/m7ssrf",
    packages=find_packages(),
    install_requires=[
        "httpx[asyncio]>=0.25.0",
        "dnspython>=2.4.0",
    ],
    python_requires=">=3.7",
    entry_points={
        "console_scripts": [
            "m7ssrf=m7ssrf.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Environment :: Console",
    ],
    include_package_data=True,
    package_data={
        "": ["data/*.json", "payloads/*.json"],
    },
)
