# syntax=docker/dockerfile:1
# Documentation site: Sphinx build, served by nginx on port 80 (TLS is left to a reverse proxy).
# Build from the repository root: docker build -f docs/Dockerfile .

# ---- build ----
FROM python:3.13-slim AS build
WORKDIR /src
COPY docs/requirements.txt docs/requirements.txt
RUN pip install --no-cache-dir -r docs/requirements.txt
# conf.py reads the version from Cargo.toml.
COPY Cargo.toml ./
COPY docs ./docs
RUN sphinx-build -W -b html docs/source /html \
 && python docs/postbuild.py /html \
 && python -m pagefind --site /html --root-selector 'div[itemprop=articleBody]' --exclude-selectors 'a.headerlink'

# ---- runtime ----
FROM nginx:1.27-alpine
COPY docs/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /html /usr/share/nginx/html
