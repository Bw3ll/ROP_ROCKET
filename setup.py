from setuptools import setup, find_packages
import os
import re

NAME = "ROP ROCKET"
VERSION = "0.9.1"
REQUIREMENTS = [
    "colorama>=0.4.4",
    "unicorn>=1.0.2",
    "pefile>=2019.4.18",
    "capstone>=4.0.2",
    "multiprocess>=0.70.14",
    "pywin32>=300",

]

setup(
    name='ROP ROCKET',
    author='Bramwell Brizendine',
    description='',
    version=VERSION,
    long_description="Words",
    url='https://github.com/',
    include_package_data=True,
    packages=find_packages(),
    install_requires=REQUIREMENTS,
    classifiers=[
        "Programming Language :: Python :: 3",
    ],
    python_requires='>=3.6',
)

