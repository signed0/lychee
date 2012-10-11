#!/usr/bin/env python

from setuptools import setup

setup(name='lychee',
	  version='1.0',
	  description='A tool for analyzing HTTP requests',
	  author='signed0',
	  author_email='nathan@signedzero.com',
	  packages=['lychee'],
	  install_requires=['distribute', 'netifaces'],
	  entry_points={
		  'console_scripts': [
			  'lychee = lychee.lychee:init_sudo'
		  ]
	  },
	  zip_safe=False
	  )
