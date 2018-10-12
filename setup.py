#!/usr/bin/env python
import ibm_botocore
import sys
from setuptools import setup, find_packages

# IbmCos sdk python version check
_valid  =  sys.version_info[:2] == (2, 7) or sys.version_info >= (3,4)
if not _valid:
    sys.exit("Sorry, IBM COS SDK only supports versions 2.7, 3.4, 3.5, 3.6, 3.7 of python.")


requires = ['jmespath>=0.7.1,<1.0.0',
            'docutils>=0.10',
            'urllib3>=1.20,<1.24',
            'python-dateutil>=2.1,<3.0.0']

setup(
    name='ibm-cos-sdk-core',
    version=ibm_botocore.__version__,
    description='Low-level, data-driven core of IBM SDK for Python',
    long_description=open('README.rst').read(),
    author='IBM',
    url='https://github.com/ibm/ibm-cos-sdk-python-core',
    scripts=[],
    packages=find_packages(exclude=['tests*']),
    package_data={'ibm_botocore': ['data/*.json', 'data/*/*.json'],
                  'ibm_botocore.vendored.requests': ['*.pem']},
    include_package_data=True,
    install_requires=requires,
    license="Apache License 2.0",
    classifiers=(
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Natural Language :: English',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ),
)
