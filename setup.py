import io
import os

from setuptools import find_packages, setup

__version__ = "0.3.3"


def read_from(file):
    reply = []
    with io.open(os.path.join(here, file), encoding='utf8') as f:
        for l in f:
            l = l.strip()
            if not l:
                break
            if l[0] != '#' or l[:2] != '//':
                reply.append(l)
    return reply


here = os.path.abspath(os.path.dirname(__file__))
with io.open(os.path.join(here, 'README.md'), encoding='utf8') as f:
    README = f.read()
with io.open(os.path.join(here, 'CHANGELOG.md'), encoding='utf8') as f:
    CHANGES = f.read()

setup(name="pywebpush",
      version=__version__,
      packages=find_packages(),
      description='WebPush publication library',
      long_description=README + '\n\n' + CHANGES,
      classifiers=["Topic :: Internet :: WWW/HTTP",
                   "Programming Language :: Python :: Implementation :: PyPy",
                   'Programming Language :: Python',
                   "Programming Language :: Python :: 2",
                   "Programming Language :: Python :: 2.7"
                   ],
      keywords='push webpush publication',
      author="jr conlin",
      author_email="src+webpusher@jrconlin.com",
      url='https://github.com/jrconlin/pywebpush',
      license="MPL2",
      test_suite="nose.collector",
      include_package_data=True,
      zip_safe=False,
      install_requires=read_from('requirements.txt'),
      tests_require=read_from('test-requirements.txt')
      )
