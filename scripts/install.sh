#!/bin/bash
# 🩺 PyDoctor Installation Script
# This script installs PyDoctor globally using pipx (recommended) or pip.

set -e

echo "🩺 Starting PyDoctor installation..."

# Check for pipx
if command -v pipx >/dev/null 2>&1; then
    echo "✔ Found pipx. Installing PyDoctor in an isolated environment..."
    pipx install pydoctor-cli --force
else
    echo "⚠ pipx not found. Installing via pip..."
    python3 -m pip install --upgrade pydoctor-cli
fi

echo ""
echo "✨ PyDoctor has been installed successfully!"
echo "🚀 Try running: pydoctor diagnose"
