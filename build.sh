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

# ~/SGXSan/Tool/GetLayout.sh enclave_t.o enclaveshim_ocalls.o tls_processing_interface.o ecall_queue.o mpmc_queue.o lthread.o lthread_sched.o mempool.o aes/aes-elf-x86_64.o aes/bsaes-elf-x86_64.o aes/vpaes-elf-x86_64.o aes/aesni-elf-x86_64.o aes/aesni-sha1-elf-x86_64.o bn/modexp512-elf-x86_64.o bn/mont-elf-x86_64.o bn/mont5-elf-x86_64.o bn/gf2m-elf-x86_64.o camellia/cmll-elf-x86_64.o md5/md5-elf-x86_64.o modes/ghash-elf-x86_64.o rc4/rc4-elf-x86_64.o rc4/rc4-md5-elf-x86_64.o sha/sha1-elf-x86_64.o whrlpool/wp-elf-x86_64.o  sha/sha256-elf-x86_64.o sha/sha512-elf-x86_64.o cpuid-elf-x86_64.o  cpt_err.o cryptlib.o cversion.o ex_data.o malloc-wrapper.o mem_clr.o mem_dbg.o o_init.o o_str.o o_time.o hashmap.o aes/aes_cfb.o aes/aes_ctr.o aes/aes_ecb.o aes/aes_ige.o aes/aes_misc.o aes/aes_ofb.o aes/aes_wrap.o asn1/a_bitstr.o asn1/a_bool.o asn1/a_bytes.o asn1/a_d2i_fp.o asn1/a_digest.o asn1/a_dup.o asn1/a_enum.o asn1/a_i2d_fp.o asn1/a_int.o asn1/a_mbstr.o asn1/a_object.o asn1/a_octet.o asn1/a_print.o asn1/a_set.o asn1/a_sign.o asn1/a_strex.o asn1/a_strnid.o asn1/a_time.o asn1/a_time_tm.o asn1/a_type.o asn1/a_utf8.o asn1/a_verify.o asn1/ameth_lib.o asn1/asn1_err.o asn1/asn1_gen.o asn1/asn1_lib.o asn1/asn1_par.o asn1/asn_mime.o asn1/asn_moid.o asn1/asn_pack.o asn1/bio_asn1.o asn1/bio_ndef.o asn1/d2i_pr.o asn1/d2i_pu.o asn1/evp_asn1.o asn1/f_enum.o asn1/f_int.o asn1/f_string.o asn1/i2d_pr.o asn1/i2d_pu.o asn1/n_pkey.o asn1/nsseq.o asn1/p5_pbe.o asn1/p5_pbev2.o asn1/p8_pkey.o asn1/t_bitst.o asn1/t_crl.o asn1/t_pkey.o asn1/t_req.o asn1/t_spki.o asn1/t_x509.o asn1/t_x509a.o asn1/tasn_dec.o asn1/tasn_enc.o asn1/tasn_fre.o asn1/tasn_new.o asn1/tasn_prn.o asn1/tasn_typ.o asn1/tasn_utl.o asn1/x_algor.o asn1/x_attrib.o asn1/x_bignum.o asn1/x_crl.o asn1/x_exten.o asn1/x_info.o asn1/x_long.o asn1/x_name.o asn1/x_nx509.o asn1/x_pkey.o asn1/x_pubkey.o asn1/x_req.o asn1/x_sig.o asn1/x_spki.o asn1/x_val.o asn1/x_x509.o asn1/x_x509a.o bf/bf_cfb64.o bf/bf_ecb.o bf/bf_enc.o bf/bf_ofb64.o bf/bf_skey.o bio/b_dump.o bio/b_posix.o bio/b_print.o bio/b_sock.o bio/bf_buff.o bio/bf_nbio.o bio/bf_null.o bio/bio_cb.o bio/bio_err.o bio/bio_lib.o bio/bss_acpt.o bio/bss_bio.o bio/bss_conn.o bio/bss_dgram.o bio/bss_fd.o bio/bss_file.o bio/bss_log.o bio/bss_mem.o bio/bss_null.o bio/bss_sock.o bn/bn_add.o bn/bn_asm.o bn/bn_blind.o bn/bn_const.o bn/bn_ctx.o bn/bn_depr.o bn/bn_div.o bn/bn_err.o bn/bn_exp.o bn/bn_exp2.o bn/bn_gcd.o bn/bn_gf2m.o bn/bn_kron.o bn/bn_lib.o bn/bn_mod.o bn/bn_mont.o bn/bn_mpi.o bn/bn_mul.o bn/bn_nist.o bn/bn_prime.o bn/bn_print.o bn/bn_rand.o bn/bn_recp.o bn/bn_shift.o bn/bn_sqr.o bn/bn_sqrt.o bn/bn_word.o bn/bn_x931p.o buffer/buf_err.o buffer/buf_str.o buffer/buffer.o camellia/cmll_cfb.o camellia/cmll_ctr.o camellia/cmll_ecb.o camellia/cmll_misc.o camellia/cmll_ofb.o cast/c_cfb64.o cast/c_ecb.o cast/c_enc.o cast/c_ofb64.o cast/c_skey.o chacha/chacha.o cmac/cm_ameth.o cmac/cm_pmeth.o cmac/cmac.o comp/c_rle.o comp/c_zlib.o comp/comp_err.o comp/comp_lib.o conf/conf_api.o conf/conf_def.o conf/conf_err.o conf/conf_lib.o conf/conf_mall.o conf/conf_mod.o conf/conf_sap.o des/cbc_cksm.o des/cbc_enc.o des/cfb64ede.o des/cfb64enc.o des/cfb_enc.o des/des_enc.o des/ecb3_enc.o des/ecb_enc.o des/ede_cbcm_enc.o des/enc_read.o des/enc_writ.o des/fcrypt.o des/fcrypt_b.o des/ofb64ede.o des/ofb64enc.o des/ofb_enc.o des/pcbc_enc.o des/qud_cksm.o des/rand_key.o des/set_key.o des/str2key.o des/xcbc_enc.o dh/dh_ameth.o dh/dh_asn1.o dh/dh_check.o dh/dh_depr.o dh/dh_err.o dh/dh_gen.o dh/dh_key.o dh/dh_lib.o dh/dh_pmeth.o dh/dh_prn.o dsa/dsa_ameth.o dsa/dsa_asn1.o dsa/dsa_depr.o dsa/dsa_err.o dsa/dsa_gen.o dsa/dsa_key.o dsa/dsa_lib.o dsa/dsa_ossl.o dsa/dsa_pmeth.o dsa/dsa_prn.o dsa/dsa_sign.o dsa/dsa_vrf.o ec/ec2_mult.o ec/ec2_oct.o ec/ec2_smpl.o ec/ec_ameth.o ec/ec_asn1.o ec/ec_check.o ec/ec_curve.o ec/ec_cvt.o ec/ec_err.o ec/ec_key.o ec/ec_lib.o ec/ec_mult.o ec/ec_oct.o ec/ec_pmeth.o ec/ec_print.o ec/eck_prn.o ec/ecp_mont.o ec/ecp_nist.o ec/ecp_oct.o ec/ecp_smpl.o ecdh/ech_err.o ecdh/ech_key.o ecdh/ech_lib.o ecdsa/ecs_asn1.o ecdsa/ecs_err.o ecdsa/ecs_lib.o ecdsa/ecs_ossl.o ecdsa/ecs_sign.o ecdsa/ecs_vrf.o engine/eng_all.o engine/eng_cnf.o engine/eng_ctrl.o engine/eng_dyn.o engine/eng_err.o engine/eng_fat.o engine/eng_init.o engine/eng_lib.o engine/eng_list.o engine/eng_openssl.o engine/eng_pkey.o engine/eng_table.o engine/tb_asnmth.o engine/tb_cipher.o engine/tb_dh.o engine/tb_digest.o engine/tb_dsa.o engine/tb_ecdh.o engine/tb_ecdsa.o engine/tb_pkmeth.o engine/tb_rand.o engine/tb_rsa.o engine/tb_store.o err/err.o err/err_all.o err/err_prn.o evp/bio_b64.o evp/bio_enc.o evp/bio_md.o evp/c_all.o evp/digest.o evp/e_aes.o evp/e_aes_cbc_hmac_sha1.o evp/e_bf.o evp/e_camellia.o evp/e_cast.o evp/e_chacha.o evp/e_chacha20poly1305.o evp/e_des.o evp/e_des3.o evp/e_gost2814789.o evp/e_idea.o evp/e_null.o evp/e_old.o evp/e_rc2.o evp/e_rc4.o evp/e_rc4_hmac_md5.o evp/e_xcbc_d.o evp/encode.o evp/evp_aead.o evp/evp_enc.o evp/evp_err.o evp/evp_key.o evp/evp_lib.o evp/evp_pbe.o evp/evp_pkey.o evp/m_dss.o evp/m_dss1.o evp/m_ecdsa.o evp/m_gost2814789.o evp/m_gostr341194.o evp/m_md4.o evp/m_md5.o evp/m_null.o evp/m_ripemd.o evp/m_sha1.o evp/m_sigver.o evp/m_streebog.o evp/m_wp.o evp/names.o evp/p5_crpt.o evp/p5_crpt2.o evp/p_dec.o evp/p_enc.o evp/p_lib.o evp/p_open.o evp/p_seal.o evp/p_sign.o evp/p_verify.o evp/pmeth_fn.o evp/pmeth_gn.o evp/pmeth_lib.o gost/gost2814789.o gost/gost89_keywrap.o gost/gost89_params.o gost/gost89imit_ameth.o gost/gost89imit_pmeth.o gost/gost_asn1.o gost/gost_err.o gost/gostr341001.o gost/gostr341001_ameth.o gost/gostr341001_key.o gost/gostr341001_params.o gost/gostr341001_pmeth.o gost/gostr341194.o gost/streebog.o hmac/hm_ameth.o hmac/hm_pmeth.o hmac/hmac.o idea/i_cbc.o idea/i_cfb64.o idea/i_ecb.o idea/i_ofb64.o idea/i_skey.o krb5/krb5_asn.o lhash/lh_stats.o lhash/lhash.o md4/md4_dgst.o md4/md4_one.o md5/md5_dgst.o md5/md5_one.o modes/cbc128.o modes/ccm128.o modes/cfb128.o modes/ctr128.o modes/cts128.o modes/gcm128.o modes/ofb128.o modes/xts128.o objects/o_names.o objects/obj_dat.o objects/obj_err.o objects/obj_lib.o objects/obj_xref.o ocsp/ocsp_asn.o ocsp/ocsp_cl.o ocsp/ocsp_err.o ocsp/ocsp_ext.o ocsp/ocsp_ht.o ocsp/ocsp_lib.o ocsp/ocsp_prn.o ocsp/ocsp_srv.o ocsp/ocsp_vfy.o pem/pem_all.o pem/pem_err.o pem/pem_info.o pem/pem_lib.o pem/pem_oth.o pem/pem_pk8.o pem/pem_pkey.o pem/pem_seal.o pem/pem_sign.o pem/pem_x509.o pem/pem_xaux.o pem/pvkfmt.o pkcs12/p12_add.o pkcs12/p12_asn.o pkcs12/p12_attr.o pkcs12/p12_crpt.o pkcs12/p12_crt.o pkcs12/p12_decr.o pkcs12/p12_init.o pkcs12/p12_key.o pkcs12/p12_kiss.o pkcs12/p12_mutl.o pkcs12/p12_npas.o pkcs12/p12_p8d.o pkcs12/p12_p8e.o pkcs12/p12_utl.o pkcs12/pk12err.o pkcs7/bio_pk7.o pkcs7/pk7_asn1.o pkcs7/pk7_attr.o pkcs7/pk7_doit.o pkcs7/pk7_lib.o pkcs7/pk7_mime.o pkcs7/pk7_smime.o pkcs7/pkcs7err.o poly1305/poly1305.o rand/rand_err.o rand/rand_lib.o rand/randfile.o rc2/rc2_cbc.o rc2/rc2_ecb.o rc2/rc2_skey.o rc2/rc2cfb64.o rc2/rc2ofb64.o ripemd/rmd_dgst.o ripemd/rmd_one.o rsa/rsa_ameth.o rsa/rsa_asn1.o rsa/rsa_chk.o rsa/rsa_crpt.o rsa/rsa_depr.o rsa/rsa_eay.o rsa/rsa_err.o rsa/rsa_gen.o rsa/rsa_lib.o rsa/rsa_none.o rsa/rsa_oaep.o rsa/rsa_pk1.o rsa/rsa_pmeth.o rsa/rsa_prn.o rsa/rsa_pss.o rsa/rsa_saos.o rsa/rsa_sign.o rsa/rsa_ssl.o rsa/rsa_x931.o sha/sha1_one.o sha/sha1dgst.o sha/sha256.o sha/sha512.o stack/stack.o ts/ts_asn1.o ts/ts_conf.o ts/ts_err.o ts/ts_lib.o ts/ts_req_print.o ts/ts_req_utils.o ts/ts_rsp_print.o ts/ts_rsp_sign.o ts/ts_rsp_utils.o ts/ts_rsp_verify.o ts/ts_verify_ctx.o txt_db/txt_db.o whrlpool/wp_dgst.o x509/by_dir.o x509/by_file.o x509/by_mem.o x509/x509_att.o x509/x509_cmp.o x509/x509_d2.o x509/x509_def.o x509/x509_err.o x509/x509_ext.o x509/x509_lu.o x509/x509_obj.o x509/x509_r2x.o x509/x509_req.o x509/x509_set.o x509/x509_trs.o x509/x509_txt.o x509/x509_v3.o x509/x509_vfy.o x509/x509_vpm.o x509/x509cset.o x509/x509name.o x509/x509rset.o x509/x509spki.o x509/x509type.o x509/x_all.o x509v3/pcy_cache.o x509v3/pcy_data.o x509v3/pcy_lib.o x509v3/pcy_map.o x509v3/pcy_node.o x509v3/pcy_tree.o x509v3/v3_akey.o x509v3/v3_akeya.o x509v3/v3_alt.o x509v3/v3_bcons.o x509v3/v3_bitst.o x509v3/v3_conf.o x509v3/v3_cpols.o x509v3/v3_crld.o x509v3/v3_enum.o x509v3/v3_extku.o x509v3/v3_genn.o x509v3/v3_ia5.o x509v3/v3_info.o x509v3/v3_int.o x509v3/v3_lib.o x509v3/v3_ncons.o x509v3/v3_ocsp.o x509v3/v3_pci.o x509v3/v3_pcia.o x509v3/v3_pcons.o x509v3/v3_pku.o x509v3/v3_pmaps.o x509v3/v3_prn.o x509v3/v3_purp.o x509v3/v3_skey.o x509v3/v3_sxnet.o x509v3/v3_utl.o x509v3/v3err.o ui/ui_err.o ui/ui_lib.o ui/ui_openssl.o ui/ui_util.o dso/dso_dlfcn.o dso/dso_err.o dso/dso_lib.o dso/dso_null.o dso/dso_openssl.o ../ssl/bio_ssl.o ../ssl/bs_ber.o ../ssl/bs_cbb.o ../ssl/bs_cbs.o ../ssl/d1_both.o ../ssl/d1_clnt.o ../ssl/d1_enc.o ../ssl/d1_lib.o ../ssl/d1_meth.o ../ssl/d1_pkt.o ../ssl/d1_srtp.o ../ssl/d1_srvr.o ../ssl/pqueue.o ../ssl/s23_clnt.o ../ssl/s23_lib.o ../ssl/s23_pkt.o ../ssl/s23_srvr.o ../ssl/s3_both.o ../ssl/s3_cbc.o ../ssl/s3_clnt.o ../ssl/s3_lib.o ../ssl/s3_pkt.o ../ssl/s3_srvr.o ../ssl/ssl_algs.o ../ssl/ssl_asn1.o ../ssl/ssl_cert.o ../ssl/ssl_ciph.o ../ssl/ssl_err.o ../ssl/ssl_err2.o ../ssl/ssl_lib.o ../ssl/ssl_rsa.o ../ssl/ssl_sess.o ../ssl/ssl_stat.o ../ssl/ssl_txt.o ../ssl/t1_clnt.o ../ssl/t1_enc.o ../ssl/t1_lib.o ../ssl/t1_meth.o ../ssl/t1_reneg.o ../ssl/t1_srvr.o compat/strlcat.o compat/strlcpy.o compat/reallocarray.o compat/timingsafe_memcmp.o compat/timingsafe_bcmp.o compat/arc4random.o compat/explicit_bzero.o compat/getentropy_linux.o logpoint.o /opt/intel/sgxsdk/lib64/libsgx_trts.a /opt/intel/sgxsdk/lib64/libsgx_tstdc.a /opt/intel/sgxsdk/lib64/libsgx_tcxx.a /opt/intel/sgxsdk/lib64/libsgx_tcmalloc.a /opt/intel/sgxsdk/lib64/libsgx_tservice.a
