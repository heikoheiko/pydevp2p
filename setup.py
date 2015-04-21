#!/usr/bin/env python
# -*- coding: utf-8 -*-


try:
    from setuptools import setup, find_packages
except ImportError:
    from distutils.core import setup

from setuptools.command.test import test as TestCommand


class PyTest(TestCommand):

    # problem w/ test_kademlia_protocol.py
    # user_options = [('timeout=', '5', "timeout tests after 5 seconds")]

    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        # import here, cause outside the eggs aren't loaded
        import pytest
        pytest.main(self.test_args)


readme = open('README.rst').read()
history = open('HISTORY.rst').read().replace('.. :changelog:', '')


test_requirements = ['sphinx']  # added to requirements. travis doesn't seem to care

install_requires = set(x.strip() for x in open('requirements.txt'))
install_requires_replacements = {
    'https://github.com/ethereum/pyrlp/tarball/develop': 'rlp>=0.3.8'}
install_requires = [install_requires_replacements.get(r, r) for r in install_requires]

setup(
    name='devp2p',
    version='0.0.6',
    description='Python implementation of the Ethereum P2P stack',
    long_description=readme + '\n\n' + history,
    author='HeikoHeiko',
    author_email='heiko@ethdev.com',
    url='https://github.com/ethereum/pydevp2p',
    packages=find_packages(exclude='devp2p.tests'),
    package_dir={'devp2p': 'devp2p'},
    include_package_data=True,
    install_requires=install_requires,
    license="BSD",
    zip_safe=False,
    keywords='devp2p',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        "Programming Language :: Python :: 2",
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
    ],
    cmdclass={'test': PyTest},
    tests_require=test_requirements
)
