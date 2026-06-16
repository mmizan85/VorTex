from setuptools import find_packages, setup

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="vortex-vault",
    version="2.0.0",
    author="Vortex Contributors",
    description=(
        "Zero-knowledge file vault with AES-256-GCM, git-like CLI, "
        "audit logging, and auto-lock reminders."
    ),
    long_description=long_description,
    long_description_content_type="text/markdown",
    python_requires=">=3.8",
    packages=find_packages(exclude=["tests*"]),
    install_requires=[
        "click>=8.1.0",
        "cryptography>=41.0.0",
        "rich>=13.7.0",
        "InquirerPy>=0.3.4",
    ],
    extras_require={
        "dev": ["pytest>=7.0", "pytest-cov>=4.0"],
        "pick": ["pick>=2.0.0"],
    },
    entry_points={
        "console_scripts": [
            "vortex=vortex.cli:cli",
            "vtx=vortex.cli:cli",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: End Users/Desktop",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security :: Cryptography",
    ],
)
