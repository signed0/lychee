#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup

from lychee import __version__

setup(name='lychee',
      version=__version__,
      description='A tool for analyzing HTTP requests',
      author='signed0',
      author_email='nathan@signedzero.com',
      packages=['lychee'],
      install_requires=['distribute', 'netifaces', 'dpkt>=1.7', 'pylibpcap>=0.6.4'],
      dependency_links=[
        'http://github.com/signed0/dpkt/tarball/master#egg=dpkt-1.7',
        'http://github.com/signed0/pylibpcap/tarball/master#egg=pylibpcap-0.6.4'
      ],
      entry_points={
        'console_scripts': [
        'lychee = lychee.lychee:main'
        ]
      },
      zip_safe=False
      )
