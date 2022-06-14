set -e
cd crypto
make -f Makefile.sgx -j$(nproc)
make -f Makefile.sgx install
