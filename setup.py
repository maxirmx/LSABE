from setuptools import setup, find_packages

setup(
    name = 'LSABE',
    version = '0.0.1',
    url = '',
    description = 'Implementation of LSABE algorithm',
    packages = find_packages(),
    install_requires = [
         "CharmCrypto @ git+ssh://git@github.com/JHUISI/charm.git@master#egg=CharmCrypto"
    ]
)