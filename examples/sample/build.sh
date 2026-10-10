#!/usr/bin/env bash
# Builds the two sample binaries used by the walkthrough: with and without symbols.
set -eu
cd "$(dirname "$0")"
gcc -O2 -o sample_unstripped sample.c
cp sample_unstripped sample_stripped && strip sample_stripped
echo "built sample_unstripped and sample_stripped"
