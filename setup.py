#!/usr/bin/env python

from setuptools import setup, find_packages


setup(
    name='django-otp-twilio',
    version='0.5.0',
    description="A django-otp plugin that delivers tokens via Twilio's SMS service.",
    long_description=open('README.rst').read(),
    author='Peter Sagerson',
    author_email='psagersDjwublJf@ignorare.net',
    packages=find_packages(),
    url='https://bitbucket.org/psagers/django-otp',
    license='BSD',
    install_requires=[
        'django-otp >= 0.5.0',
        'requests',
    ],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Framework :: Django",
    ],
)
