#!/bin/sh

# You will need pandoc to be installed for this to work correctly, as well as the PyPI packages docutils and pygments

set -e
pandoc --from=markdown --to=rst --output README.rst README.md
python setup.py check --restructuredtext --strict --metadata
