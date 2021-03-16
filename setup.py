import io
import os

from setuptools import find_packages, setup


__version__ = "1.13.0"


def read_from(file):
    reply = []
    with io.open(os.path.join(here, file), encoding='utf8') as f:
        for line in f:
            line = line.strip()
            if not line:
                break
            if line[:2] == '-r':
                reply += read_from(line.split(' ')[1])
                continue
            if line[0] != '#' or line[:2] != '//':
                reply.append(line)
    return reply


here = os.path.abspath(os.path.dirname(__file__))
with io.open(os.path.join(here, 'README.rst'), encoding='utf8') as f:
    README = f.read()
with io.open(os.path.join(here, 'CHANGELOG.md'), encoding='utf8') as f:
    CHANGES = f.read()

setup(
    name="pywebpush",
    version=__version__,
    packages=find_packages(),
    description='WebPush publication library',
    long_description=README + '\n\n' + CHANGES,
    classifiers=[
        "Topic :: Internet :: WWW/HTTP",
        "Programming Language :: Python :: Implementation :: PyPy",
        'Programming Language :: Python',
        "Programming Language :: Python :: 3",
    ],
    keywords='push webpush publication',
    author="JR Conlin",
    author_email="src+webpusher@jrconlin.com",
    url='https://github.com/web-push-libs/pywebpush',
    license="MPL2",
    include_package_data=True,
    zip_safe=False,
    install_requires=read_from('requirements.txt'),
    tests_require=read_from('test-requirements.txt'),
    entry_points="""
    [console_scripts]
    pywebpush = pywebpush.__main__:main
    """,
)
