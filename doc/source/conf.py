# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

from docutils import nodes
from sphinx import addnodes

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = 'VulnScout'
copyright = '2026, Savoir-Faire Linux Inc.'
author = 'Savoir-Faire Linux Inc.'
release = 'v0.23'

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = ["myst_parser", "sphinx.ext.intersphinx"]
myst_heading_anchors = 3

templates_path = ['_templates']
exclude_patterns = []

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'sphinx_rtd_theme'
html_static_path = ['_static']

# Set intersphinx mapping with meta-vulnscout documentation.
intersphinx_mapping = {
    "meta-vulnscout": ("https://meta-vulnscout.readthedocs.io/en/latest/", None),
}


def place_getting_started_examples(app, doctree):
    if app.env.docname != 'getting-started':
        return

    for tree in doctree.findall(addnodes.toctree):
        if tree.get('includefiles') != ['examples']:
            continue
        # Keep the final subpage beside the sections, not inside the last one.
        wrapper = tree.parent if isinstance(tree.parent, nodes.compound) else tree
        wrapper.parent.remove(wrapper)
        next(doctree.findall(nodes.section)).append(wrapper)


def setup(app):
    app.connect('doctree-read', place_getting_started_examples, priority=400)
