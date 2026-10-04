#!/bin/sh
set -e
export PATH="$HOME/.local/bin:$PATH"

# Install uv if the image doesn't have it
if ! command -v uv >/dev/null 2>&1; then
  if command -v curl >/dev/null 2>&1; then
    curl -LsSf https://astral.sh/uv/install.sh | sh
  elif command -v pip3 >/dev/null 2>&1; then
    pip3 install --user uv
  else
    echo "Neither curl nor pip found; install uv manually" >&2
    exit 1
  fi
fi

# Sync dependencies once pyproject.toml exists
if [ -f pyproject.toml ]; then
  uv sync
fi