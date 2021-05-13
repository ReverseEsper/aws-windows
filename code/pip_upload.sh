#Compile Package
python setup.py sdist bdist_wheel
# Upload Package to PIP
python -m twine uplaod --repository-url https://upload.pypi.org/legacy/ dist/*