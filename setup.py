from setuptools import setup
from setuptools import find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name='cloudflare-dns',
    version='1.0.2',
    packages=find_packages('cloudflare_dns'),
    install_requires=[
        'cloudflare'
    ],
    entry_points={
        'console_scripts': {
            'cloudflare-dns=cloudflare_dns.cli:main',
        }
    },
    description='CLI and Python tool for managing Cloudflare DNS',
    long_description=long_description,
    long_description_content_type="text/markdown",
    author='Tao Z',
    url='https://github.com/ZigZagT/cloudflare-dns',
    project_urls={
        "Bug Tracker": "https://github.com/ZigZagT/cloudflare-dns/issues",
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Typing :: Typed"
    ],
    python_requires=">=3.6",
)
