from setuptools import setup, find_packages

setup(
    name = 'LSABE',
    version = '0.0.1',
    url = '',
    description = 'Implementation of LSABE algorithm',
    packages = find_packages(),
    install_requires = [
         "CharmCrypto>=0.0.1"
    ],
    dependency_links = [
      "git+https://github.com/JHUISI/charm.git#egg=CharmCrypto-0.0.1",
    ]
)

# https://github.com/apache/beam/blob/master/sdks/python/apache_beam/examples/complete/juliaset/setup.py