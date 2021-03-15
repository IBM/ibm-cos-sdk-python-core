#!/usr/bin/env python
from setuptools import setup, find_packages

import ibm_botocore

requires = ['jmespath>=0.7.1,<1.0.0',
            'requests>=2.18,<3.0',
            'python-dateutil>=2.1,<3.0.0']

setup(
    name='ibm-cos-sdk-core',
    version=ibm_botocore.__version__,
    description='Low-level, data-driven core of IBM SDK for Python',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    author='IBM',
    url='https://github.com/ibm/ibm-cos-sdk-python-core',
    scripts=[],
    packages=find_packages(exclude=['tests*']),
    package_data={'ibm_botocore': ['cacert.pem', 'data/*.json', 'data/*/*.json']},
    include_package_data=True,
    python_requires='~=3.6',
    install_requires=requires,
    license="Apache License 2.0",
    classifiers=(
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Natural Language :: English',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9'
    ),
)
