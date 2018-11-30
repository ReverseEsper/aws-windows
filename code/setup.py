import setuptools
with open("README.md", "r") as fh:
    long_description = fh.read()
setuptools.setup(
     name='aws-ad',  
     version='0.1',
     scripts=['aws-ad'] ,
     author="Adam Kurowski",
     author_email="adam.kurowski.git@darevee.pl",
     description="A tool for logging into aws with ad credentials",
     long_description=long_description,
   long_description_content_type="text/markdown",
     url="https://github.com/ReverseEsper/aws-windows",
     install_requires=['bs4','boto3'],
     packages=setuptools.find_packages(),
     classifiers=[
         "Programming Language :: Python :: 3",
         "License :: OSI Approved :: MIT License",
         "Operating System :: OS Independent",
     ],
 )