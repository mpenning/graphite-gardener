#!/usr/bin/env python
import os

from setuptools import setup, find_packages
import sys
CURRENT_PATH=os.getcwd()+'/graphite-gardener'
sys.path.insert(1,CURRENT_PATH)

def read(fname):
    # Dynamically generate setup(long_description)
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(name='graphite-gardener',
      version="0.0.2",
      description='graphite-gardner',
      url='http://github.com/mpenning/graphite-gardener',
      author='David Michael Pennington',
      author_email='mike /|at|\ pennington.net',
      license='GPL',
      platforms='any',
      keywords='',
      entry_points = "",
      long_description=read('README.rst'),
      include_package_data=True,
      packages=find_packages(),
      use_2to3=True,
      zip_safe=False,
      setup_requires=["setuptools_hg"],  # setuptools_hg must be installed as a python module
      classifiers=[
          'Development Status :: 3 - Alpha',
          'Environment :: Plugins',
          'Intended Audience :: Developers',
          'Intended Audience :: System Administrators',
          'Intended Audience :: Information Technology',
          'License :: OSI Approved :: GNU General Public License (GPL)',
          'Natural Language :: English',
          'Operating System :: OS Independent',
          'Programming Language :: Python',
          'Topic :: Software Development :: Libraries :: Python Modules',
          ],
     )

