import io
import os
import sys
from setuptools import setup

PACKAGES = ["lsabe"]

def setup_module():

  root = os.path.abspath(os.path.dirname(__file__))

  with io.open(os.path.join(root, "lsabe", "__about__.py"), encoding="utf8") as f:
            __about__ = {}
            exec(f.read(), __about__)

  with io.open(os.path.join(root, "README.md"), encoding="utf8") as f:
    readme = f.read()

  setup(
    name=__about__["__name__"],
    packages=PACKAGES,
    description=__about__["__summary__"],
    long_description=readme,
    long_description_content_type="text/markdown",
    author=__about__["__author__"],
    author_email=__about__["__email__"],
    version=__about__["__version__"],
    url=__about__["__uri__"],
    license=__about__["__license__"],
    setup_requires = [
      "CharmCrypto @ git+https://github.com/JHUISI/charm.git@master",
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


if __name__ == "__main__":
    setup_module()

# https://github.com/apache/beam/blob/master/sdks/python/apache_beam/examples/complete/juliaset/setup.py