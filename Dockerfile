# vsc-scanner runtime image.
#
# Design: the image carries ONLY the language/tool runtimes. The repo
# itself (including tools/gitleaks, tools/osv-scanner, tools/node/...,
# the marketplace JSON, and pw.txt) lives under the shared $HOME and
# is provisioned by the host-side run.sh before launch.sh fires off
# the pod. This keeps the image small and lets us re-deploy code
# changes with a `git pull` instead of a rebuild.

FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# - nodejs/npm: retire.js + js-beautify run under node (bundled in tools/node/).
# - git: belt-and-suspenders so the container can pull updates if the host
#   shared FS lags; also needed for `git rev-parse` (scanner_version).
# - ca-certificates: HTTPS to the marketplace + Supabase.
# - libmagic1: occasionally pulled in by semgrep's deps.
RUN apt-get update && apt-get install -y --no-install-recommends \
        nodejs \
        npm \
        git \
        ca-certificates \
        libmagic1 \
    && rm -rf /var/lib/apt/lists/*

RUN pip install \
        'psycopg[binary]==3.3.4' \
        'requests>=2.31' \
        'semgrep==1.140.0'

# Default working dir — overridden at runtime by the entrypoint, which
# chdirs into $HOME/vsc-scanner where the repo lives.
WORKDIR /work

# Entry wrapper: hop into the synced HOME copy of the repo, then exec the
# node loop. Extra args from `launch.sh -- ...` are forwarded.
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
