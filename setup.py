# Always prefer setuptools over distutils
from setuptools import setup
# To use a consistent encoding
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

# Read version from VERSION file
with open(path.join(here, 'VERSION')) as version_file:
    version = version_file.read().strip()

# Arguments marked as "Required" below must be included for upload to PyPI.
# Fields marked as "Optional" may be commented out.
setup(
    name='srv6-sdn-data-plane',
    version=version,
    description='SRv6 SDN Data Plane',  # Required
    long_description=long_description,
    long_description_content_type='text/markdown',  # Optional (see note above)
    url='',  # Optional
    packages=['srv6_sdn_data_plane',
              'srv6_sdn_data_plane.southbound',
              'srv6_sdn_data_plane.southbound.grpc',
              'srv6_sdn_data_plane.southbound.netconf',
              'srv6_sdn_data_plane.southbound.rest',
              'srv6_sdn_data_plane.southbound.ssh'],  # Required
    install_requires=[
        'setuptools',
        'grpcio=1.19.0',
        'grpcio-tools=1.19.0',
        'ipaddress>=1.0.22',
        'networkx==1.11',
        'protobuf>=3.7.1',
        'pyroute2==0.6.9',
        'six>=1.12.0',
        'pqueue>=0.1.7',
        'filelock>=3.4.0'
    ]
)
