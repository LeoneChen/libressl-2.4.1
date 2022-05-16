set -e
cd crypto
make -f Makefile.sgx -j$(nproc)