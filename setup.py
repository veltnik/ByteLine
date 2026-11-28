# setup.py
from setuptools import setup

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="byteline",
    version="0.3.1",
    author="Veltnik",
    author_email="Redm1nx@yandex.ru",
    description="TUN-туннель через Tailcat и надёжный чат с подтверждением доставки",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/veltnik/ByteLine",
    py_modules=["byteline"],
    entry_points={
        "console_scripts": [
            "byteline = byteline:main",
        ],
    },
    python_requires=">=3.11",
    install_requires=[
        "pytap3>=3.1.2",   # TUN-адаптер (Wintun на Windows, /dev/net/tun на Linux)
        "tailkitty>=0.3.0",  # туннель Tailcat
    ],
    license="MIT",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: System :: Networking",
    ],
)
