publish:
	rm -rf dist
	python -m pip install --upgrade build twine
	python -m build
	python -m twine upload dist/*
