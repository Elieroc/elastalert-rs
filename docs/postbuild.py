"""Prepare the Sphinx HTML for Pagefind.

Sphinx puts section ids on <section id="..."> and not on the heading, while Pagefind only builds
per-section results (title, anchor, excerpt) from headings that carry an id. Move each section id
onto its heading: the anchor still points at the same place.

Usage: python postbuild.py <html dir>
"""

import re
import sys
from pathlib import Path

# Sections with an explicit label (".. _name:") carry extra <span id="..."></span> targets before the heading.
SECTION_HEADING = re.compile(r'<section id="([^"]+)">(\s*(?:<span id="[^"]+"></span>)*)<h([1-6])>')


def main(site: Path) -> None:
    for page in site.rglob('*.html'):
        html = page.read_text(encoding='utf-8')
        fixed = SECTION_HEADING.sub(r'<section>\2<h\3 id="\1">', html)
        if fixed != html:
            page.write_text(fixed, encoding='utf-8')


if __name__ == '__main__':
    main(Path(sys.argv[1]))
