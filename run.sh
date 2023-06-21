#!/bin/bash
CUR_DIR=$(realpath .)
SGXSAN_DIR=$(realpath ${CUR_DIR}/../../)

source ${SGXSAN_DIR}/kAFL/kafl/env.sh
kafl fuzz -w ${CUR_DIR}/workdir_T0 --kernel /home/leone/Documents/linux/arch/x86_64/boot/bzImage --initrd ${CUR_DIR}/target.cpio.gz --memory 512 --sharedir ${CUR_DIR}/sharedir --seed-dir ${CUR_DIR}/seeds -t 4 -ts 2 -tc -p 1 --redqueen --grimoire --radamsa -D --funky --purge --log-hprintf --abort-time 24 --cpu-offset 12
# kafl debug --action single -w ${CUR_DIR}/workdir_debug --kernel /home/leone/Documents/linux/arch/x86_64/boot/bzImage --initrd ${CUR_DIR}/target_debug.cpio.gz --memory 512 --sharedir ${CUR_DIR}/sharedir --purge --qemu-base "-enable-kvm -machine kAFL64-v1 -cpu kAFL64-Hypervisor-v1,+vmx -no-reboot -nic user,hostfwd=tcp::5555-:1234 -display none" -t 200 --input $1
# kafl cov --kernel /home/leone/Documents/linux/arch/x86_64/boot/bzImage --initrd ${CUR_DIR}/target.cpio.gz --memory 512 --sharedir ${CUR_DIR}/sharedir -r -ip0 0x7ffff6a0b000-0x7ffff6b71000 -w ${CUR_DIR}/workdir_T0 -p 16
# ${SGXSAN_DIR}/Tool/GetLayout.py \
# -d tee \
# obj-sgx/bolos_portable.o \
# obj-sgx/bolos_printf.o \
# obj-sgx/platform_sgx/bolos_platform.o \
# obj-sgx/platform_sgx/platform_al.o \
# obj-sgx/platform_sgx/platform_errno.o \
# obj-sgx/platform_sgx/platform_persistent_context.o \
# obj-sgx/platform_sgx/moxie_swi_bolos_crypto.o \
# obj-sgx/platform_sgx/moxie_swi_bolos_antireplay.o \
# obj-sgx/platform_sgx/moxie_swi_bolos_time.o \
# obj-sgx/platform_sgx/sgx_pse.o \
# obj-sgx/micro-ecc/uECC.o \
# obj-sgx/ctaes/ctaes.o \
# obj-sgx/sha3/sha3.o \
# obj-sgx/ripemd160/ripemd160.o \
# obj-sgx/moxie/moxie.o \
# obj-sgx/moxie/machine.o \
# obj-sgx/moxie/moxie_swi_sodium.o \
# obj-sgx/moxie/moxie_swi_common.o \
# obj-sgx/moxie/moxie_swi_bolos_core.o \
# obj-sgx/moxie/moxie_swi_bolos_continuation.o \
# obj-sgx/moxie/moxie_swi_bolos_utils.o \
# obj-sgx/moxie/moxie_swi_dispatcher.o \
# obj-sgx/moxie/moxie_swi_bolos_wrapping.o \
# obj-sgx/moxie/moxie_swi_bolos_shared_memory.o \
# obj-sgx/moxie/moxie_swi_bolos_endorsement.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_aead/chacha20poly1305/sodium/aead_chacha20poly1305.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_auth/crypto_auth.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_auth/hmacsha256/auth_hmacsha256.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_auth/hmacsha512/auth_hmacsha512.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_auth/hmacsha512256/auth_hmacsha512256.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_box/crypto_box.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_box/crypto_box_easy.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_box/crypto_box_seal.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_box/curve25519xsalsa20poly1305/box_curve25519xsalsa20poly1305.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_core/curve25519/ref10/curve25519_ref10.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_core/hsalsa20/ref2/core_hsalsa20_ref2.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_core/hsalsa20/core_hsalsa20.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_core/salsa/ref/core_salsa_ref.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_generichash/crypto_generichash.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_generichash/blake2b/generichash_blake2.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_generichash/blake2b/ref/blake2b-compress-ref.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_generichash/blake2b/ref/blake2b-ref.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_generichash/blake2b/ref/generichash_blake2b.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_hash/crypto_hash.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_hash/sha256/hash_sha256.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_hash/sha256/cp/hash_sha256_cp.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_hash/sha512/hash_sha512.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_onetimeauth/crypto_onetimeauth.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_onetimeauth/poly1305/onetimeauth_poly1305.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_pwhash/scryptsalsa208sha256/crypto_scrypt-common.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_pwhash/scryptsalsa208sha256/scrypt_platform.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_pwhash/scryptsalsa208sha256/pbkdf2-sha256.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_pwhash/scryptsalsa208sha256/pwhash_scryptsalsa208sha256.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_pwhash/scryptsalsa208sha256/nosse/pwhash_scryptsalsa208sha256_nosse.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_pwhash/crypto_pwhash.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_pwhash/argon2/pwhash_argon2i.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_pwhash/argon2/argon2.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_pwhash/argon2/argon2-core.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_pwhash/argon2/argon2-encoding.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_pwhash/argon2/argon2-fill-block-ref.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_pwhash/argon2/blake2b-long.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_scalarmult/crypto_scalarmult.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_scalarmult/curve25519/scalarmult_curve25519.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_secretbox/crypto_secretbox.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_secretbox/crypto_secretbox_easy.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_secretbox/xsalsa20poly1305/secretbox_xsalsa20poly1305.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_shorthash/crypto_shorthash.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_shorthash/siphash24/shorthash_siphash24.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_shorthash/siphash24/ref/shorthash_siphash24_ref.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_sign/crypto_sign.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_sign/ed25519/sign_ed25519.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_sign/ed25519/ref10/keypair.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_sign/ed25519/ref10/open.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_sign/ed25519/ref10/sign.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_stream/crypto_stream.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_stream/chacha20/stream_chacha20.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_stream/chacha20/ref/chacha20_ref.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_stream/salsa20/stream_salsa20.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_stream/xsalsa20/stream_xsalsa20.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_verify/sodium/verify.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/randombytes/randombytes.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/sodium/core.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/sodium/runtime.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/sodium/utils.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/sodium/version.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/crypto_stream/salsa20/ref/salsa20_ref.o \
# obj-sgx/libsodium-1.0.12/src/libsodium/randombytes/sysrandom/randombytes_sysrandom.o \
# /home/leone/Documents/SGXSan/install/lib64/libSGXSanRTEnclave.a \
# /home/leone/Documents/SGXSan/install/lib64/libsgx_trts_sim.a \
# /home/leone/Documents/SGXSan/install/lib64/libsgx_tkey_exchange.a \
# /home/leone/Documents/SGXSan/install/lib64/libsgx_tcrypto.a \
# /home/leone/Documents/SGXSan/install/lib64/libsgx_tservice_sim.a
# ${SGXSAN_DIR}/kAFL/kafl/fuzzer/scripts/ghidra_run.sh ${CUR_DIR}/workdir_T0 ${CUR_DIR}/tee/obj-sgx/BolosSGX.so ${SGXSAN_DIR}/ghidra_cov_analysis.py
