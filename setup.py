"""
Setup configuration for Atous Secure Network package
"""
from setuptools import setup, find_packages

setup(
    name="atous-sec-network",
    version="2.0.0",
    description="Atous Secure Network - Enhanced IoT Security with Federated Learning and LoRa",
    author="Atous Team",
    author_email="dev@atous.tech",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "numpy>=1.21.0",
        "torch>=1.9.0",
        "transformers>=4.11.0",
        "flwr>=1.0.0",
        "scikit-learn>=1.0.0",
        "pandas>=1.3.0",
        "paho-mqtt>=1.6.0",
        "requests>=2.26.0",
        "cryptography>=3.4.0",
        "prometheus-client>=0.11.0",
        "psutil>=5.8.0",
        "dash>=2.0.0",
        "plotly>=5.0.0",
        "bsdiff4>=0.2.0"
    ],
    extras_require={
        "dev": [
            "pytest>=6.2.0",
            "pytest-asyncio>=0.15.0",
            "pytest-cov>=2.12.0",
            "pytest-mock>=3.6.0",
            "black>=21.7b0",
            "flake8>=3.9.0",
            "mypy>=0.910",
            "pyserial-mock>=0.3.0",  # Mock for pyserial
        ],
        "hardware": [
            "RPi.GPIO>=0.7.0",
            "pyserial>=3.5"
        ],
        "test": [  # For CI environments
            "pytest>=6.2.0",
            "pytest-asyncio>=0.15.0",
            "pytest-cov>=2.12.0",
            "pytest-mock>=3.6.0",
            "pyserial-mock>=0.3.0"
        ],
        "all": [
            "pytest>=6.2.0",
            "pytest-asyncio>=0.15.0",
            "pytest-cov>=2.12.0",
            "pytest-mock>=3.6.0",
            "black>=21.7b0",
            "flake8>=3.9.0",
            "mypy>=0.910",
            "RPi.GPIO>=0.7.0",
            "pyserial>=3.5"
        ]
    }
)
