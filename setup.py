#!/usr/bin/env python

from os import path
from setuptools import setup

current_dir = path.dirname(path.abspath(__file__))
requirements = open(path.join(current_dir, 'requirements.txt')).readlines()

setup(name='lychee',
      version='1.0',
      description='A tool for analyzing HTTP requests',
      author='signed0',
      author_email='nathan@signedzero.com',
      packages=['lychee'],
      install_requires=list(requirements),
      entry_points={
          'console_scripts': [
              'lychee = lychee.lychee:init_sudo'
          ]
      },
      zip_safe=False
      )
