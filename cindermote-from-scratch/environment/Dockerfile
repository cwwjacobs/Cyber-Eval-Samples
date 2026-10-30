# Environment for cindermote-from-scratch: a Cindermote checkout with all of its Python source removed.
# The Python patch version matches the one the graded-test list (tests/f2p.json) was computed with.
FROM python:3.11.15-slim-bookworm@sha256:d29f48a31a8b408ed19272ca1e7b10ebae13b240a27e862d3d4217c528e2e0c3

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    LANG=C.UTF-8

# libsodium backs Cindermote's secretstream, patch applies the reference solution, and procps
# provides pkill for the verifier.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libsodium23 patch procps \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /opt/cindermote-task/requirements.txt
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir -r /opt/cindermote-task/requirements.txt \
    && /opt/venv/bin/python -c "import ctypes.util, cryptography; assert ctypes.util.find_library('sodium')"

# Cindermote runs some helpers with the system interpreter at its fixed, trusted path, and the
# python:slim image ships Python only under /usr/local/bin.
RUN ln -s /usr/local/bin/python3 /usr/bin/python3

RUN useradd --create-home --uid 1000 --shell /bin/bash agent \
    && useradd --no-create-home --uid 1001 --shell /usr/sbin/nologin grader

# The tree the agent works in, plus a root-owned pristine copy of its public tests that the
# verifier grades with, so edits under /app/tests change nothing.
COPY app/ /app/
COPY app/tests/ /opt/cindermote-task/visible-tests/
RUN chmod -R go-w /app /opt/cindermote-task \
    && chown -R agent:agent /app

ENV PATH=/opt/venv/bin:$PATH
WORKDIR /app
