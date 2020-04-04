import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="gluon-qemu-testlab",
    version="0.0.4",
    author="Leonardo Mörlein",
    author_email="me@irrelefant.net",
    description="Python scripts to run qemu and gluon based virtual mesh networks",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/freifunk-gluon/gluon-qemu-testlab",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    install_requires=['asyncssh==2.1.0'],
)

