#!/usr/bin/env python
# encoding: utf-8
from setuptools import setup, find_packages

VERSION_STRING = '1.5'

setup(
    name = 'coda_network',
    version = VERSION_STRING,
    packages = find_packages(),
    scripts = ['mini_proxy.py', ]

    author = 'Cambridge Visual Networks',
    author_email = 'support@camvine.com',
    license = 'python',
    url = 'http://www.camvine.com/',
)
