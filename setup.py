"""
Setup script for the HTTP Request Smuggling Detection Tool.
"""

from setuptools import setup, find_packages

setup(
    name="hrs_finder",
    version="0.1.0",
    description="HTTP Request Smuggling Detection Tool",
    author="Vipin",
    author_email="vipin@example.com",
    packages=["src", "src.cli", "src.clients", "src.detectors", "src.utils"],
    package_data={
        "src": ["*.py"],
        "src.cli": ["*.py"],
        "src.clients": ["*.py"],
        "src.detectors": ["*.py"],
        "src.utils": ["*.py"],
    },
    include_package_data=True,
    install_requires=[
        "click>=8.0.0",
        "colorama>=0.4.4",
        "rich>=10.0.0",
        "h2>=4.0.0",
        "hpack>=4.0.0",
    ],
    entry_points={
        "console_scripts": [
            "hrs_finder=src.cli.main:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.11",
)
