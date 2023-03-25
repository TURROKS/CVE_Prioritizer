#!/usr/bin/env python3

from setuptools import setup, find_packages

setup(name='CVE Prioritizer',
      version='0.1.0',
      description='Check if a CVE should be prioritized based on iin CISAs KEV and its CVSS and EPSS scores',
      author='Mario Rojas',
      author_email='mariro_ch@hotmail.com',
      url='',
      packages=find_packages(include=['scripts']),
      entry_points={
        'console_scripts': []
      },
      install_requires=[],
      )
