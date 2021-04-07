from setuptools import setup, find_packages

setup(
    name = 'LSABE',
    version = '0.0.1',
    url = '',
    description = 'Implementation of LSABE algorithm',
    packages = find_packages(),
    install_requires = [
         "CharmCrypto>=0.50.0"
    ],
    dependency_links = [
      "git+https://github.com/JHUISI/charm.git@master#egg=CharmCrypto-0.50.0",
    ],
    classifiers=[
      "Environment :: Console",
      "Intended Audience :: Developers",
      "Intended Audience :: Science/Research",
      "License :: OSI Approved :: MIT License",
      "Operating System :: POSIX :: Linux",
      "Programming Language :: Python :: 3.7",
      "Topic :: Scientific/Engineering",
    ]
)

# https://github.com/apache/beam/blob/master/sdks/python/apache_beam/examples/complete/juliaset/setup.py