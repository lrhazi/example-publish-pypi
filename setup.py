from setuptools import setup, find_packages


setup(
    name='bigip_utils',
    version='0.2',
    license='MIT',
    author="Mohamed Lrhazi",
    author_email='lrhazi@gmail.com',
    packages=find_packages('src'),
    package_dir={'': 'src'},
    url='https://github.com/lrhazi/bigip-utils-pypi',
    keywords='bigip utils rest api',
    install_requires=[
          'requests','requests-html','docopt'
      ],

)
