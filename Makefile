
build: setup.py
	rm -f dist/*
	python3 setup.py sdist bdist_wheel

testupload:
	python3 -m twine upload --repository-url https://test.pypi.org/legacy/ dist/*
	
