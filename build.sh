#!/bin/bash
set -e

if [[ $1 == 'debug' ]]; then
    DEBUG_FLAG="SGX_DEBUG=1 SGX_PRERELEASE=0"
else
    DEBUG_FLAG="SGX_DEBUG=0 SGX_PRERELEASE=1"
fi

MAKE_FLAG="SGX_MODE=HW ${DEBUG_FLAG} -j$(nproc)"

cd crypto
make -f Makefile.sgx ${MAKE_FLAG}
make -f Makefile.sgx install ${MAKE_FLAG}