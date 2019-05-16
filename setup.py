from opendrop import __version__
from codecs import open
from os.path import abspath, dirname, join
from setuptools import find_packages, setup

this_dir = abspath(dirname(__file__))
with open(join(this_dir, 'README.md'), encoding='utf-8') as file:
    long_description = file.read()

setup(
    name='opendrop',
    version=__version__,
    description='An Open Source AirDrop Implementation',
    long_description=long_description,
    url='https://owlink.org',
    author='Milan Stute, Alexander Heinrich',
    classifiers=[
        'Intended Audience :: Developers',
        'Topic :: Utilities',
        'License :: Public Domain',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.6.3',
    ],
    keywords='cli',
    packages=find_packages(exclude=['docs']),
    package_data={
        'opendrop': ['certs/*.pem']
    },

    install_requires=['pycrypto', 'requests', 'fleep', 'netifaces', 'Pillow',
                      'requests_toolbelt', 'ctypescrypto', 'libarchive-c'],
    entry_points={
        'console_scripts': [
            'opendrop=opendrop.cli:main',
        ],
    },
)
