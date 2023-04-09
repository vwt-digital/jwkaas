import os

from setuptools import setup, find_packages

with open('requirements.txt') as f:
    install_requires = f.read().splitlines()

setup(
     name='jwkaas',
     packages=find_packages(),
     include_package_data=True,
     version=os.getenv('TAG_NAME', '0.0.0'),
     license='gpl-3.0',
     scripts=[],
     description="JSON Web Key Advanced Acquiring Store",
     long_description=open('README.md').read(),
     long_description_content_type="text/markdown",
     author="Bernie van Veen",
     author_email="b.vanveen@vwt.digital",
     url="https://github.com/vwt-digital/jwkaas",
     classifiers=[
         "Programming Language :: Python :: 3",
         "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
         "Operating System :: OS Independent",
     ],
     install_requires=install_requires,
     python_requires='>=3.6',
 )
