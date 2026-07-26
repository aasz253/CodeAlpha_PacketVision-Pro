from setuptools import setup, find_packages

setup(
    name="packetvision-pro",
    version="1.0.0",
    description="Advanced Network Packet Sniffer & Analyzer",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Sifuna Codex",
    url="https://github.com/aasz253/CodeAlpha_PacketVision-Pro",
    license="MIT",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "scapy>=2.5.0",
        "matplotlib>=3.5.0",
        "numpy>=1.21.0",
        "fpdf2>=2.7.0",
    ],
    entry_points={
        "console_scripts": [
            "packetvision=main:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Topic :: System :: Networking :: Monitoring",
    ],
)
