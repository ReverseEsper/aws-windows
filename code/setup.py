import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="aws-ad",
    version="0.6.5",
    entry_points={
        "console_scripts": [
            "aws-ad = aws_ad.ADFSAuth:main_func"
        ]
    },
    author="Adam Kurowski",
    author_email="adam.kurowski.git@darevee.pl",
    description="A tool for logging into aws with ad credentials",
    long_description=long_description,
    use_2to3=True,
    long_description_content_type="text/markdown",
    url="https://github.com/ReverseEsper/aws-windows",
    install_requires=["bs4", "boto3", "configparser", "argparse", "requests", "ConfigArgParse"],
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
 )
