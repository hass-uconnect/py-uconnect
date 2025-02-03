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
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Natural Language :: English",
        "Programming Language :: Python :: 3.10",
    ],
    description="Python API Client for FCA/Stellantis cars",
    install_requires=["boto3>=1.35.96", "requests>=2.32.3",
                      "requests-auth-aws-sigv4>=0.7",
                      "dataclasses_json>=0.6.7"],
    license="Apache license",
    long_description=readme,
    include_package_data=True,
    keywords=["fiat", "jeep", "dodge", "ram", "alfa",
              "romeo", "maserati", "chrysler", "api", "cloud"],
    name="py-uconnect",
    packages=find_packages(
        include=["py-uconnect", "py-uconnect.*"]
    ),
    url="https://github.com/hass-uconnect/py-uconnect",
    version="0.1.11",
    zip_safe=False,
)
