#!/usr/bin/env python

"""The setup script."""

from setuptools import setup, find_packages

with open("README.md") as readme_file:
    readme = readme_file.read()

setup(
    author="Olga Novgorodova",
    author_email="olga@novg.net",
    python_requires=">=3.10",
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Programming Language :: Python :: 3.10",
    ],
    description="Fiat API client for Python",
    install_requires=["boto3>=1.35.96", "requests>=2.32.3",
                      "requests-auth-aws-sigv4>=0.7",
                      "dataclasses_json>=0.6.7"],
    license="MIT license",
    long_description=readme,
    include_package_data=True,
    keywords=["fiat", "jeep", "dodge", "ram", "alfa",
              "romeo", "maserati", "chrysler", "api", "cloud"],
    name="python-fiat-api",
    packages=find_packages(
        include=["pyfiat", "pyfiat.*"]
    ),
    url="https://github.com/OlgaNovg/pyfiat",
    version="0.1.6",
    zip_safe=False,
)
