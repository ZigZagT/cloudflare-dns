from setuptools import setup
from setuptools import find_packages


setup(
    name='cloudflare-dns',
    version='1.0.0',
    packages=find_packages('cloudflare_dns'),
    install_requires=[
        'cloudflare'
    ],
    entry_points={
        'console_scripts': {
            'cloudflare-dns=cloudflare_dns.cli:main',
        }
    }
)
