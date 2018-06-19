from setuptools import setup, find_packages
setup(
    name="homeca",
    version="0.1",
    packages=['homeca'],
    install_requires=[ 'cryptography', ],
    entry_points={
        'console_scripts': [
            'homeca = homeca.__main__:main',
        ],
    }
)
