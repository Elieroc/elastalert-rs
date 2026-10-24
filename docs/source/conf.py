# ElastAlert 3 documentation build configuration file.
# Based on the ElastAlert 2 documentation (Apache-2.0), see NOTICE.

import re
from datetime import datetime
from pathlib import Path

# The version comes from Cargo.toml so the docs follow the releases.
_cargo = Path(__file__).resolve().parents[2] / 'Cargo.toml'
_m = re.search(r'^version\s*=\s*"([^"]+)"', _cargo.read_text(), re.M) if _cargo.exists() else None

extensions = []
templates_path = ['_templates']
source_suffix = ['.rst']
master_doc = 'index'

project = 'ElastAlert 3'
copyright = str(datetime.now().year)
release = _m.group(1) if _m else 'dev'
version = release

exclude_patterns = ['recipes/*.md']
pygments_style = 'sphinx'

html_theme = 'sphinx_rtd_theme'
html_theme_options = {
    'logo_only': True,
    'style_nav_header_background': '#0d1322',
}
html_title = 'ElastAlert 3 documentation'
html_logo = '../assets/logo-horizontal-dark.png'
html_favicon = '../assets/icon.svg'
html_static_path = ['_static']
html_css_files = ['custom.css']
# Search-as-you-type modal over the Pagefind index built after Sphinx (see docs/Dockerfile).
html_js_files = ['search-modal.js']
htmlhelp_basename = 'elastalertdoc'
