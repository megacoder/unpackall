#!/usr/bin/python
# vim: noet sw=4 ts=4 filetype=python

from distutils.core import setup

version = '1.0.5'

with open( 'untar/version.py', 'wt' ) as f:
    print >>f, "Version = '{0}'".format( version )

setup(
    name                 = 'untar',
    version              = version,
    description          = "Unpack various families of tar(1) archives.",
    long_description     = open('README.md').read(),
    keywords             = 'tar untar unosw unsos unarchive',
    author               = 'Tommy Reynolds',
    author_email         = 'Oldest.Software.Guy@gmail.com',
    url                  = 'http://www.megacoder.com',
    license              = 'MIT',
    include_package_data = True,
    zip_safe             = False,
    install_requires     = [],
    packages             = [ 'untar' ],
    entry_points         = {
        'console_scripts' : [
            'untar=untar:main'
        ],
    },
    scripts              = [ 'bin/untar' ]
)
