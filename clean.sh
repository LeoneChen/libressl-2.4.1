#!/bin/bash
set -e
cd crypto
make -f Makefile.sgx -j$(nproc) clean -s
rm -rf ../lib