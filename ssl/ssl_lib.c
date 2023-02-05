#include "kafl_hc.h"
/* $OpenBSD: ssl_lib.c,v 1.115 2015/10/19 17:59:39 beck Exp $ */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */
/* ====================================================================
 * Copyright (c) 1998-2007 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * ECC cipher suite support in OpenSSL originally developed by
 * SUN MICROSYSTEMS, INC., and contributed to the OpenSSL project.
 */
/* ====================================================================
 * Copyright 2005 Nokia. All rights reserved.
 *
 * The portions of the attached software ("Contribution") is developed by
 * Nokia Corporation and is licensed pursuant to the OpenSSL open source
 * license.
 *
 * The Contribution, originally written by Mika Kousa and Pasi Eronen of
 * Nokia Corporation, consists of the "PSK" (Pre-Shared Key) ciphersuites
 * support (see RFC 4279) to OpenSSL.
 *
 * No patent licenses or other rights except those expressly stated in
 * the OpenSSL open source license shall be deemed granted or received
 * expressly, by implication, estoppel, or otherwise.
 *
 * No assurances are provided by Nokia that the Contribution does not
 * infringe the patent or other intellectual property rights of any third
 * party or that the license provides you with all the necessary rights
 * to make use of the Contribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. IN
 * ADDITION TO THE DISCLAIMERS INCLUDED IN THE LICENSE, NOKIA
 * SPECIFICALLY DISCLAIMS ANY LIABILITY FOR CLAIMS BROUGHT BY YOU OR ANY
 * OTHER ENTITY BASED ON INFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS OR
 * OTHERWISE.
 */

#include <stdio.h>

#include "ssl_locl.h"

#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/lhash.h>
#include <openssl/objects.h>
#include <openssl/ocsp.h>
#include <openssl/x509v3.h>

#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif

#include "bytestring.h"

#ifdef COMPILE_WITH_INTEL_SGX
#include "sgx_error.h"
#include "sgx_trts.h"
#include "sgx_spinlock.h"
#include "hashmap.h"
#include "ecall_queue.h"
#include "lthread.h"
#include "mpmc_queue.h"
#include "enclaveshim_ocalls.h"
#include "sgx_thread.h"
#endif

#ifdef COMPILE_WITH_INTEL_SGX
extern sgx_status_t ocall_malloc(void** retval, size_t size);
extern void ocall_exit(int code);
extern void ocall_execute_ssl_ctx_info_callback(const SSL *ssl, int type, int val, void* cb);
extern int ocall_pem_password_cb(int* retval, char* buf, int size, int rwflag, void* userdata, void* cb);
extern int ocall_ssl_ctx_callback_ctrl(int* retval, SSL* ssl, int* ad, void* arg, void* cb);
extern int ocall_new_session_callback(int* retval, struct ssl_st* ssl, void* sess, void* cb);
sgx_status_t ocall_alpn_select_cb(int* retval, SSL* s, unsigned char** out, unsigned char* outlen, const unsigned char* in, unsigned int inlen, void* arg, void* cb);
sgx_status_t ocall_next_protos_advertised_cb(int* retval, SSL* s, unsigned char** buf, unsigned int* len, void* arg, void* cb);
sgx_status_t ocall_crypto_ex_free_cb(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp, void* cb);
sgx_status_t ocall_sk_pop_free_cb(void* data, void* cb);
sgx_status_t ocall_get_session_cb(void** retval, struct ssl_st* ssl, unsigned char* data, int len, int* copy, void* cb);

/*
extern int ocall_ssl_ctx_callback_ctrl(SSL* ssl, int* ad, void* arg, void* cb);
extern int ocall_pem_password_cb(char *buf, int size, int rwflag, void *userdata, void* cb);
extern int ocall_new_session_callback(struct ssl_st *ssl, void *sess, void* cb);
*/
#endif
extern void tls_processing_new_connection(const SSL* s);
extern void tls_processing_free_connection(const SSL* s);

const char *SSL_version_str = OPENSSL_VERSION_TEXT;

SSL3_ENC_METHOD ssl3_undef_enc_method = {
	/*
	 * Evil casts, but these functions are only called if there's a
	 * library bug.
	 */
	.enc = (int (*)(SSL *, int))ssl_undefined_function,
	.mac = (int (*)(SSL *, unsigned char *, int))ssl_undefined_function,
	.setup_key_block = ssl_undefined_function,
	.generate_master_secret = (int (*)(SSL *, unsigned char *,
	    unsigned char *, int))ssl_undefined_function,
	.change_cipher_state = (int (*)(SSL*, int))ssl_undefined_function,
	.final_finish_mac = (int (*)(SSL *,  const char*, int,
	    unsigned char *))ssl_undefined_function,
	.finish_mac_length = 0,
	.cert_verify_mac = (int (*)(SSL *, int,
	    unsigned char *))ssl_undefined_function,
	.client_finished_label = NULL,
	.client_finished_label_len = 0,
	.server_finished_label = NULL,
	.server_finished_label_len = 0,
	.alert_value = (int (*)(int))ssl_undefined_function,
	.export_keying_material = (int (*)(SSL *, unsigned char *, size_t,
	    const char *, size_t, const unsigned char *, size_t,
	    int use_context))ssl_undefined_function,
	.enc_flags = 0,
};

int
SSL_clear(SSL *s)
{
	if (s->method == NULL) {
		SSLerr(SSL_F_SSL_CLEAR, SSL_R_NO_METHOD_SPECIFIED);
		return (0);
	}

	if (ssl_clear_bad_session(s)) {
		SSL_SESSION_free(s->session);
		s->session = NULL;
	}

	s->error = 0;
	s->hit = 0;
	s->shutdown = 0;

	if (s->renegotiate) {
		SSLerr(SSL_F_SSL_CLEAR, ERR_R_INTERNAL_ERROR);
		return (0);
	}

	s->type = 0;

	s->state = SSL_ST_BEFORE|((s->server) ? SSL_ST_ACCEPT : SSL_ST_CONNECT);

	s->version = s->method->version;
	s->client_version = s->version;
	s->rwstate = SSL_NOTHING;
	s->rstate = SSL_ST_READ_HEADER;

	BUF_MEM_free(s->init_buf);
	s->init_buf = NULL;

	ssl_clear_cipher_ctx(s);
	ssl_clear_hash_ctx(&s->read_hash);
	ssl_clear_hash_ctx(&s->write_hash);

	s->first_packet = 0;

	/*
	 * Check to see if we were changed into a different method, if
	 * so, revert back if we are not doing session-id reuse.
	 */
	if (!s->in_handshake && (s->session == NULL) &&
	    (s->method != s->ctx->method)) {
		s->method->ssl_free(s);
		s->method = s->ctx->method;
		if (!s->method->ssl_new(s))
			return (0);
	} else
		s->method->ssl_clear(s);

	return (1);
}

/* Used to change an SSL_CTXs default SSL method type */
int
SSL_CTX_set_ssl_version(SSL_CTX *ctx, const SSL_METHOD *meth)
{
	STACK_OF(SSL_CIPHER)	*sk;

	ctx->method = meth;

	sk = ssl_create_cipher_list(ctx->method, &(ctx->cipher_list),
	    &(ctx->cipher_list_by_id), SSL_DEFAULT_CIPHER_LIST);
	if ((sk == NULL) || (sk_SSL_CIPHER_num(sk) <= 0)) {
		SSLerr(SSL_F_SSL_CTX_SET_SSL_VERSION,
		    SSL_R_SSL_LIBRARY_HAS_NO_CIPHERS);
		return (0);
	}
	return (1);
}

#ifdef COMPILE_WITH_INTEL_SGX

static int ssl_hardening_initialized = 0;
static hashmap* ssl_hardening_map = NULL;
sgx_spinlock_t ssl_hardening_map_lock = SGX_SPINLOCK_INITIALIZER;

static hashmap* get_ssl_hardening() {
	int expected = 0;
	int desired = 1;
	if (__atomic_compare_exchange_n(&ssl_hardening_initialized, &expected, desired, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
		ssl_hardening_map = hashmapCreate(251);
	}
	while (!ssl_hardening_map) {
		// burn cycles
	}

	hashmap* m = (hashmap*)hashmapGet(ssl_hardening_map, (unsigned long)sgx_thread_self());
	if (!m) {
		m = hashmapCreate(251);
		sgx_spin_lock(&ssl_hardening_map_lock);
		//	need a lock on the insert, just to be safe. However each thread will acquire the lock only once during its execution
		hashmapInsert(ssl_hardening_map, (const void*)m, (unsigned long)sgx_thread_self());
		sgx_spin_unlock(&ssl_hardening_map_lock);
	}

	//my_printf("thread %lu get_ssl_hardening -> %p\n", (unsigned long)sgx_thread_self(), m);

	return m;
}

void SSL_copy_fields_to_out_struct(const SSL* in, SSL* out) {
	out->state = in->state;
	out->verify_mode = in->verify_mode;
	out->verify_result = in->verify_result;
	out->wbio = in->wbio;
	out->shutdown = in->shutdown;
	out->ctx = in->ctx;
	out->verify_callback = in->verify_callback;
	out->session = (SSL_SESSION*)(in->session ? in->session->peer : NULL); // we store the X509* pointer into the SSL_SESSION* field :)
	if (out->s3 && in->s3) { 	out->s3->flags = in->s3->flags; }
	out->references = in->references;
	SSL_set_session_id_context(out, in->sid_ctx, in->sid_ctx_length);
}

void SSL_copy_fields_to_in_struct(SSL* in, const SSL* out) {
	//XXX we also want to check the values
	in->state = out->state;
	in->verify_mode = out->verify_mode;
	in->verify_result = out->verify_result;
	in->wbio = out->wbio;
	in->shutdown = out->shutdown;
	in->ctx = out->ctx;
	in->verify_callback = out->verify_callback;
	if (out->s3 && in->s3) { 	in->s3->flags = out->s3->flags; }
	in->references = out->references;
	SSL_set_session_id_context(in, out->sid_ctx, out->sid_ctx_length);
}

SSL* SSL_get_in_pointer(SSL* out_s) {
	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);
	return in_s;
}

int ocall_alpn_select_cb_wrapper(SSL* s, unsigned char** out, unsigned char* outlen, const unsigned char* in, unsigned int inlen, void* arg, void* cb) {
	SSL* in_s = s;
	int retval;

	hashmap* m = get_ssl_hardening();
	SSL* out_s = (SSL*) hashmapGet(m, (unsigned long)in_s);

	SSL_copy_fields_to_out_struct(in_s, out_s);
	retval = ocall_alpn_select_cb_async_wrapper(out_s, out, outlen, in, inlen, arg, cb);
	SSL_copy_fields_to_in_struct(in_s, out_s);

	return retval;
}

int ocall_next_protos_advertised_cb_wrapper(SSL* s, unsigned char** buf, unsigned int* len, void* arg, void* cb) {
	SSL* in_s = s;
	int retval;

	hashmap* m = get_ssl_hardening();
	SSL* out_s = (SSL*) hashmapGet(m, (unsigned long)in_s);

	SSL_copy_fields_to_out_struct(in_s, out_s);
	sgx_status_t ret = ocall_next_protos_advertised_cb(&retval, out_s, buf, len, arg, cb);
	if (ret != SGX_SUCCESS) {
		my_printf("%s ocall error: %d\n", __func__, ret);
		retval = 0;
	}
	SSL_copy_fields_to_in_struct(in_s, out_s);
	return retval;
}

void crypto_ex_free_cb_wrapper(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp, void* cb) {
	sgx_status_t ret = ocall_crypto_ex_free_cb(parent, ptr, ad, idx, argl, argp, cb);
	if (ret != SGX_SUCCESS) {
		my_printf("%s ocall error: %d\n", __func__, ret);
	}
}

void ocall_sk_pop_free_cb_wrapper(void* data, void* cb) {
	sgx_status_t ret = ocall_sk_pop_free_cb(data, cb);
	if (ret != SGX_SUCCESS) {
		my_printf("%s ocall error: %d\n", __func__, ret);
	}
}
#endif

SSL *
ecall_SSL_new(SSL_CTX *ctx, SSL* out_s) {
    LogEnter(__func__);
#ifdef COMPILE_WITH_INTEL_SGX
	SSL* s = SSL_new(ctx);
	SSL_copy_fields_to_out_struct(s, out_s);

	hashmap* m = get_ssl_hardening();
	hashmapInsert(m, (const void*)out_s, (unsigned long)s); // map[s] = out_s
	hashmapInsert(m, (const void*)s, (unsigned long)out_s); // map[out_s] = s

	return out_s;
#else
	return SSL_new(ctx);
#endif
}
SSL *
SSL_new(SSL_CTX *ctx)
{
	SSL	*s;

	if (ctx == NULL) {
		SSLerr(SSL_F_SSL_NEW, SSL_R_NULL_SSL_CTX);
		return (NULL);
	}
	if (ctx->method == NULL) {
		SSLerr(SSL_F_SSL_NEW, SSL_R_SSL_CTX_HAS_NO_DEFAULT_SSL_VERSION);
		return (NULL);
	}

	s = calloc(1, sizeof(SSL));
	if (s == NULL)
		goto err;


	s->options = ctx->options;
	s->mode = ctx->mode;
	s->max_cert_list = ctx->max_cert_list;

	if (ctx->cert != NULL) {
		/*
		 * Earlier library versions used to copy the pointer to
		 * the CERT, not its contents; only when setting new
		 * parameters for the per-SSL copy, ssl_cert_new would be
		 * called (and the direct reference to the per-SSL_CTX
		 * settings would be lost, but those still were indirectly
		 * accessed for various purposes, and for that reason they
		 * used to be known as s->ctx->default_cert).
		 * Now we don't look at the SSL_CTX's CERT after having
		 * duplicated it once.
		*/
		s->cert = ssl_cert_dup(ctx->cert);
		if (s->cert == NULL)
			goto err;
	} else
		s->cert=NULL; /* Cannot really happen (see SSL_CTX_new) */

	s->read_ahead = ctx->read_ahead;
	s->msg_callback = ctx->msg_callback;
	s->msg_callback_arg = ctx->msg_callback_arg;
	s->verify_mode = ctx->verify_mode;
	s->sid_ctx_length = ctx->sid_ctx_length;
	OPENSSL_assert(s->sid_ctx_length <= sizeof s->sid_ctx);
	memcpy(&s->sid_ctx, &ctx->sid_ctx, sizeof(s->sid_ctx));
	s->verify_callback = ctx->default_verify_callback;
	s->generate_session_id = ctx->generate_session_id;

	s->param = X509_VERIFY_PARAM_new();
	if (!s->param)
		goto err;
	X509_VERIFY_PARAM_inherit(s->param, ctx->param);
	s->quiet_shutdown = ctx->quiet_shutdown;
	s->max_send_fragment = ctx->max_send_fragment;

	CRYPTO_add(&ctx->references, 1, CRYPTO_LOCK_SSL_CTX);
	s->ctx = ctx;
	s->tlsext_debug_cb = 0;
	s->tlsext_debug_arg = NULL;
	s->tlsext_ticket_expected = 0;
	s->tlsext_status_type = -1;
	s->tlsext_status_expected = 0;
	s->tlsext_ocsp_ids = NULL;
	s->tlsext_ocsp_exts = NULL;
	s->tlsext_ocsp_resp = NULL;
	s->tlsext_ocsp_resplen = -1;
	CRYPTO_add(&ctx->references, 1, CRYPTO_LOCK_SSL_CTX);
	s->initial_ctx = ctx;
	s->next_proto_negotiated = NULL;

	if (s->ctx->alpn_client_proto_list != NULL) {
		s->alpn_client_proto_list =
		    malloc(s->ctx->alpn_client_proto_list_len);
		if (s->alpn_client_proto_list == NULL)
			goto err;
		memcpy(s->alpn_client_proto_list,
		    s->ctx->alpn_client_proto_list,
		    s->ctx->alpn_client_proto_list_len);
		s->alpn_client_proto_list_len =
		    s->ctx->alpn_client_proto_list_len;
	}

	s->verify_result = X509_V_OK;

	s->method = ctx->method;

	if (!s->method->ssl_new(s))
		goto err;

	s->references = 1;
	s->server = (ctx->method->ssl_accept == ssl_undefined_function) ? 0 : 1;

	SSL_clear(s);

	CRYPTO_new_ex_data(CRYPTO_EX_INDEX_SSL, s, &s->ex_data);

	tls_processing_new_connection((const SSL*)s);

	return (s);

err:
	SSL_free(s);
	SSLerr(SSL_F_SSL_NEW, ERR_R_MALLOC_FAILURE);
	return (NULL);
}

int
ecall_SSL_CTX_set_session_id_context(SSL_CTX *ctx, const unsigned char *sid_ctx,
    unsigned int sid_ctx_len) {
    LogEnter(__func__);
	return SSL_CTX_set_session_id_context(ctx, sid_ctx, sid_ctx_len);
}
int
SSL_CTX_set_session_id_context(SSL_CTX *ctx, const unsigned char *sid_ctx,
    unsigned int sid_ctx_len)
{
	if (sid_ctx_len > sizeof ctx->sid_ctx) {
		SSLerr(SSL_F_SSL_CTX_SET_SESSION_ID_CONTEXT,
		    SSL_R_SSL_SESSION_ID_CONTEXT_TOO_LONG);
		return (0);
	}
	ctx->sid_ctx_length = sid_ctx_len;
	memcpy(ctx->sid_ctx, sid_ctx, sid_ctx_len);

	return (1);
}

int
ecall_SSL_set_session_id_context(SSL *ssl, const unsigned char *sid_ctx,
	unsigned int sid_ctx_len)
{
    LogEnter(__func__);
#ifdef COMPILE_WITH_INTEL_SGX
	SSL* out_s = ssl;

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	SSL_copy_fields_to_in_struct(in_s, out_s);
	int ret = SSL_set_session_id_context(in_s, sid_ctx, sid_ctx_len);
	SSL_copy_fields_to_out_struct(in_s, out_s);
	return ret;
#else
	return SSL_set_session_id_context(ssl, sid_ctx, sid_ctx_len);
#endif
}
int
SSL_set_session_id_context(SSL *ssl, const unsigned char *sid_ctx,
    unsigned int sid_ctx_len)
{
	if (sid_ctx_len > SSL_MAX_SID_CTX_LENGTH) {
		SSLerr(SSL_F_SSL_SET_SESSION_ID_CONTEXT,
		    SSL_R_SSL_SESSION_ID_CONTEXT_TOO_LONG);
		return (0);
	}
	ssl->sid_ctx_length = sid_ctx_len;
	memcpy(ssl->sid_ctx, sid_ctx, sid_ctx_len);

	return (1);
}

int
SSL_CTX_set_generate_session_id(SSL_CTX *ctx, GEN_SESSION_CB cb)
{
	CRYPTO_w_lock(CRYPTO_LOCK_SSL_CTX);
	ctx->generate_session_id = cb;
	CRYPTO_w_unlock(CRYPTO_LOCK_SSL_CTX);
	return (1);
}

int
SSL_set_generate_session_id(SSL *ssl, GEN_SESSION_CB cb)
{
	CRYPTO_w_lock(CRYPTO_LOCK_SSL);
	ssl->generate_session_id = cb;
	CRYPTO_w_unlock(CRYPTO_LOCK_SSL);
	return (1);
}

int
SSL_has_matching_session_id(const SSL *ssl, const unsigned char *id,
    unsigned int id_len)
{
	/*
	 * A quick examination of SSL_SESSION_hash and SSL_SESSION_cmp
	 * shows how we can "construct" a session to give us the desired
	 * check - ie. to find if there's a session in the hash table
	 * that would conflict with any new session built out of this
	 * id/id_len and the ssl_version in use by this SSL.
	 */
	SSL_SESSION r, *p;

	if (id_len > sizeof r.session_id)
		return (0);

	r.ssl_version = ssl->version;
	r.session_id_length = id_len;
	memcpy(r.session_id, id, id_len);

	CRYPTO_r_lock(CRYPTO_LOCK_SSL_CTX);
	p = lh_SSL_SESSION_retrieve(ssl->ctx->sessions, &r);
	CRYPTO_r_unlock(CRYPTO_LOCK_SSL_CTX);
	return (p != NULL);
}

int
SSL_CTX_set_purpose(SSL_CTX *s, int purpose)
{
	return (X509_VERIFY_PARAM_set_purpose(s->param, purpose));
}

int
SSL_set_purpose(SSL *s, int purpose)
{
	return (X509_VERIFY_PARAM_set_purpose(s->param, purpose));
}

int
SSL_CTX_set_trust(SSL_CTX *s, int trust)
{
	return (X509_VERIFY_PARAM_set_trust(s->param, trust));
}

int
SSL_set_trust(SSL *s, int trust)
{
	return (X509_VERIFY_PARAM_set_trust(s->param, trust));
}

int
SSL_CTX_set1_param(SSL_CTX *ctx, X509_VERIFY_PARAM *vpm)
{
	return (X509_VERIFY_PARAM_set1(ctx->param, vpm));
}

int
SSL_set1_param(SSL *ssl, X509_VERIFY_PARAM *vpm)
{
	return (X509_VERIFY_PARAM_set1(ssl->param, vpm));
}


void
ecall_SSL_free(SSL *s) {
    LogEnter(__func__);
#ifdef COMPILE_WITH_INTEL_SGX
	SSL* out_s = s;

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);
	out_s->references = in_s->references-1;
	if (out_s->references <= 0) {
		hashmapRemove(m, (unsigned long)out_s);
		hashmapRemove(m, (unsigned long)in_s);
	}

	// no need for an ocall_free(out_s) as the untrusted code in enclaveshim_ecalls.c does it for us
	s = in_s;
#endif
	SSL_free(s);
}
void
SSL_free(SSL *s)
{
	int	i;

	if (s == NULL) {
		return;
	}

	i = CRYPTO_add(&s->references, -1, CRYPTO_LOCK_SSL);
	if (i > 0) {
		return;
	}

	if (s->param)
		X509_VERIFY_PARAM_free(s->param);

	CRYPTO_free_ex_data(CRYPTO_EX_INDEX_SSL, s, &s->ex_data);

	if (s->bbio != NULL) {
		/* If the buffering BIO is in place, pop it off */
		if (s->bbio == s->wbio) {
			s->wbio = BIO_pop(s->wbio);
		}
		BIO_free(s->bbio);
		s->bbio = NULL;
	}

	if (s->rbio != s->wbio)
		BIO_free_all(s->rbio);
	BIO_free_all(s->wbio);

	if (s->init_buf != NULL)
		BUF_MEM_free(s->init_buf);

	/* add extra stuff */
	if (s->cipher_list != NULL)
		sk_SSL_CIPHER_free(s->cipher_list);
	if (s->cipher_list_by_id != NULL)
		sk_SSL_CIPHER_free(s->cipher_list_by_id);

	/* Make the next call work :-) */
	if (s->session != NULL) {
		ssl_clear_bad_session(s);
		SSL_SESSION_free(s->session);
	}

	ssl_clear_cipher_ctx(s);
	ssl_clear_hash_ctx(&s->read_hash);
	ssl_clear_hash_ctx(&s->write_hash);

	if (s->cert != NULL)
		ssl_cert_free(s->cert);
	/* Free up if allocated */

	free(s->tlsext_hostname);
	SSL_CTX_free(s->initial_ctx);
	free(s->tlsext_ecpointformatlist);
	free(s->tlsext_ellipticcurvelist);
	if (s->tlsext_ocsp_exts)
		sk_X509_EXTENSION_pop_free(s->tlsext_ocsp_exts,
		    X509_EXTENSION_free);
	if (s->tlsext_ocsp_ids)
		sk_OCSP_RESPID_pop_free(s->tlsext_ocsp_ids, OCSP_RESPID_free);
	free(s->tlsext_ocsp_resp);

	if (s->client_CA != NULL)
		sk_X509_NAME_pop_free(s->client_CA, X509_NAME_free);

	if (s->method != NULL)
		s->method->ssl_free(s);

	SSL_CTX_free(s->ctx);


	free(s->next_proto_negotiated);
	free(s->alpn_client_proto_list);

#ifndef OPENSSL_NO_SRTP
	if (s->srtp_profiles)
		sk_SRTP_PROTECTION_PROFILE_free(s->srtp_profiles);
#endif

	tls_processing_free_connection((const SSL*)s);

	free(s);
}

void
ecall_SSL_set_bio(SSL *s, BIO *rbio, BIO *wbio)
{
    LogEnter(__func__);
#ifdef COMPILE_WITH_INTEL_SGX
	SSL* out_s = s;

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	SSL_copy_fields_to_in_struct(in_s, out_s);
	SSL_set_bio(in_s, rbio, wbio);
	SSL_copy_fields_to_out_struct(in_s, out_s);
#else
	SSL_set_bio(s, rbio, wbio);
#endif
}
void
SSL_set_bio(SSL *s, BIO *rbio, BIO *wbio)
{
	/* If the output buffering BIO is still in place, remove it */
	if (s->bbio != NULL) {
		if (s->wbio == s->bbio) {
			s->wbio = s->wbio->next_bio;
			s->bbio->next_bio = NULL;
		}
	}

	if (s->rbio != rbio && s->rbio != s->wbio)
		BIO_free_all(s->rbio);
	if (s->wbio != wbio)
		BIO_free_all(s->wbio);
	s->rbio = rbio;
	s->wbio = wbio;
}

BIO *
ecall_SSL_get_rbio(const SSL *s)
{
    LogEnter(__func__);
#ifdef COMPILE_WITH_INTEL_SGX
	SSL* out_s = (SSL*)s;

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	SSL_copy_fields_to_in_struct(in_s, out_s);
	BIO* ret = SSL_get_rbio((const SSL*)in_s);
	SSL_copy_fields_to_out_struct(in_s, out_s);
	return ret;
#else
	return SSL_get_rbio(s);
#endif
}
BIO *
SSL_get_rbio(const SSL *s)
{
	return (s->rbio);
}

BIO *
ecall_SSL_get_wbio(const SSL *s)
{
    LogEnter(__func__);
#ifdef COMPILE_WITH_INTEL_SGX
	SSL* out_s = (SSL*)s;

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	SSL_copy_fields_to_in_struct(in_s, out_s);
	BIO* ret = SSL_get_wbio((const SSL*)in_s);
	SSL_copy_fields_to_out_struct(in_s, out_s);
	return ret;
#else
	return SSL_get_wbio(s);
#endif
}
BIO *
SSL_get_wbio(const SSL *s)
{
	return (s->wbio);
}

int
SSL_get_fd(const SSL *s)
{
	return (SSL_get_rfd(s));
}

int
SSL_get_rfd(const SSL *s)
{
	int	 ret = -1;
	BIO	*b, *r;

	b = SSL_get_rbio(s);
	r = BIO_find_type(b, BIO_TYPE_DESCRIPTOR);
	if (r != NULL)
		BIO_get_fd(r, &ret);
	return (ret);
}

int
SSL_get_wfd(const SSL *s)
{
	int	 ret = -1;
	BIO	*b, *r;

	b = SSL_get_wbio(s);
	r = BIO_find_type(b, BIO_TYPE_DESCRIPTOR);
	if (r != NULL)
		BIO_get_fd(r, &ret);
	return (ret);
}

int
ecall_SSL_set_fd(SSL *s, int fd) {
    LogEnter(__func__);
#ifdef COMPILE_WITH_INTEL_SGX
	SSL* out_s = s;

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	SSL_copy_fields_to_in_struct(in_s, out_s);
	int ret = SSL_set_fd(in_s, fd);
	SSL_copy_fields_to_out_struct(in_s, out_s);
	return ret;
#else
	return SSL_set_fd(s, fd);
#endif
}

int
SSL_set_fd(SSL *s, int fd)
{
	int	 ret = 0;
	BIO	*bio = NULL;

	bio = BIO_new(BIO_s_socket());

	if (bio == NULL) {
		SSLerr(SSL_F_SSL_SET_FD, ERR_R_BUF_LIB);
		goto err;
	}
	BIO_set_fd(bio, fd, BIO_NOCLOSE);
	SSL_set_bio(s, bio, bio);
	ret = 1;
err:
	return (ret);
}

int
SSL_set_wfd(SSL *s, int fd)
{
	int	 ret = 0;
	BIO	*bio = NULL;

	if ((s->rbio == NULL) || (BIO_method_type(s->rbio) != BIO_TYPE_SOCKET)
	    || ((int)BIO_get_fd(s->rbio, NULL) != fd)) {
		bio = BIO_new(BIO_s_socket());

		if (bio == NULL) {
			SSLerr(SSL_F_SSL_SET_WFD, ERR_R_BUF_LIB);
			goto err;
		}
		BIO_set_fd(bio, fd, BIO_NOCLOSE);
		SSL_set_bio(s, SSL_get_rbio(s), bio);
	} else
		SSL_set_bio(s, SSL_get_rbio(s), SSL_get_rbio(s));
	ret = 1;
err:
	return (ret);
}

int
SSL_set_rfd(SSL *s, int fd)
{
	int	 ret = 0;
	BIO	*bio = NULL;

	if ((s->wbio == NULL) || (BIO_method_type(s->wbio) != BIO_TYPE_SOCKET)
	    || ((int)BIO_get_fd(s->wbio, NULL) != fd)) {
		bio = BIO_new(BIO_s_socket());

		if (bio == NULL) {
			SSLerr(SSL_F_SSL_SET_RFD, ERR_R_BUF_LIB);
			goto err;
		}
		BIO_set_fd(bio, fd, BIO_NOCLOSE);
		SSL_set_bio(s, bio, SSL_get_wbio(s));
	} else
		SSL_set_bio(s, SSL_get_wbio(s), SSL_get_wbio(s));
	ret = 1;
err:
	return (ret);
}


/* return length of latest Finished message we sent, copy to 'buf' */
size_t
SSL_get_finished(const SSL *s, void *buf, size_t count)
{
	size_t	ret = 0;

	if (s->s3 != NULL) {
		ret = s->s3->tmp.finish_md_len;
		if (count > ret)
			count = ret;
		memcpy(buf, s->s3->tmp.finish_md, count);
	}
	return (ret);
}

/* return length of latest Finished message we expected, copy to 'buf' */
size_t
SSL_get_peer_finished(const SSL *s, void *buf, size_t count)
{
	size_t	ret = 0;

	if (s->s3 != NULL) {
		ret = s->s3->tmp.peer_finish_md_len;
		if (count > ret)
			count = ret;
		memcpy(buf, s->s3->tmp.peer_finish_md, count);
	}
	return (ret);
}


int
ecall_SSL_get_verify_mode(const SSL *s)
{
    LogEnter(__func__);
#ifdef COMPILE_WITH_INTEL_SGX
	SSL* out_s = (SSL*)s;

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	SSL_copy_fields_to_in_struct(in_s, out_s);
	int ret = SSL_get_verify_mode((const SSL*)in_s);
	SSL_copy_fields_to_out_struct(in_s, out_s);
	return ret;
#else
	return SSL_get_verify_mode(s);
#endif
}
int
SSL_get_verify_mode(const SSL *s)
{
	return (s->verify_mode);
}

int
SSL_get_verify_depth(const SSL *s)
{
	return (X509_VERIFY_PARAM_get_depth(s->param));
}

int
(*SSL_get_verify_callback(const SSL *s))(int, X509_STORE_CTX *)
{
	return (s->verify_callback);
}

int
ecall_SSL_CTX_get_verify_mode(const SSL_CTX *ctx)
{
    LogEnter(__func__);
	return SSL_CTX_get_verify_mode(ctx);
}
int
SSL_CTX_get_verify_mode(const SSL_CTX *ctx)
{
	return (ctx->verify_mode);
}

int
SSL_CTX_get_verify_depth(const SSL_CTX *ctx)
{
	return (X509_VERIFY_PARAM_get_depth(ctx->param));
}

void* ecall_SSL_CTX_get_verify_callback(const SSL_CTX *ctx)
{
    LogEnter(__func__);
	return (void*)SSL_CTX_get_verify_callback(ctx);
}
int (*SSL_CTX_get_verify_callback(const SSL_CTX *ctx))(int, X509_STORE_CTX *)
{
	return (ctx->default_verify_callback);
}

#ifdef COMPILE_WITH_INTEL_SGX
int (*ssl_set_verify_cb_address)(int, X509_STORE_CTX*) = NULL;
int ssl_set_verify_fake_cb(int ok, X509_STORE_CTX *ctx) {
	my_fprintf(0, "%s:%s:%i need to implement callback\n", __FILE__, __func__, __LINE__);
	if (ssl_set_verify_cb_address) {
		//TODO ocall(ok, ctx, address)
	}
	return 0;
}
#endif

void
ecall_SSL_set_verify(SSL *s, int mode, void* cb)
{
    LogEnter(__func__);
	int (*callback)(int, X509_STORE_CTX*);
#ifdef COMPILE_WITH_INTEL_SGX
	ssl_set_verify_cb_address = (int (*)(int, X509_STORE_CTX*))cb;
	callback = ssl_set_verify_fake_cb;
#else
	callback = (int (*)(int, X509_STORE_CTX*))cb;
#endif

#ifdef COMPILE_WITH_INTEL_SGX
	SSL* out_s = s;

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	SSL_copy_fields_to_in_struct(in_s, out_s);
	SSL_set_verify(in_s, mode, callback);
	SSL_copy_fields_to_out_struct(in_s, out_s);
#else
	SSL_set_verify(s, mode, callback);
#endif
}
void
SSL_set_verify(SSL *s, int mode,
    int (*callback)(int ok, X509_STORE_CTX *ctx))
{
	s->verify_mode = mode;
	if (callback != NULL)
		s->verify_callback = callback;
}

void
ecall_SSL_set_verify_depth(SSL *s, int depth) {
	return SSL_set_verify_depth(s, depth);
}
void
SSL_set_verify_depth(SSL *s, int depth)
{
	X509_VERIFY_PARAM_set_depth(s->param, depth);
}

void
SSL_set_read_ahead(SSL *s, int yes)
{
	s->read_ahead = yes;
}

int
SSL_get_read_ahead(const SSL *s)
{
	return (s->read_ahead);
}

int
ecall_SSL_pending(const SSL *s)
{
    LogEnter(__func__);
	int ret = 0;
#ifdef COMPILE_WITH_INTEL_SGX
	SSL* out_s = (SSL*)s;

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	SSL_copy_fields_to_in_struct(in_s, out_s);
	ret = SSL_pending(in_s);
	SSL_copy_fields_to_out_struct(in_s, out_s);
#else
	ret = SSL_pending(s);
#endif
	return ret;
}
int
SSL_pending(const SSL *s)
{
	/*
	 * SSL_pending cannot work properly if read-ahead is enabled
	 * (SSL_[CTX_]ctrl(..., SSL_CTRL_SET_READ_AHEAD, 1, NULL)),
	 * and it is impossible to fix since SSL_pending cannot report
	 * errors that may be observed while scanning the new data.
	 * (Note that SSL_pending() is often used as a boolean value,
	 * so we'd better not return -1.)
	 */
	return (s->method->ssl_pending(s));
}

X509 *
ecall_SSL_get_peer_certificate(const SSL *s)
{
    LogEnter(__func__);
#ifdef COMPILE_WITH_INTEL_SGX
	SSL* out_s = (SSL*)s;

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	SSL_copy_fields_to_in_struct(in_s, out_s);
	X509* ret = SSL_get_peer_certificate((const SSL*)in_s);
	SSL_copy_fields_to_out_struct(in_s, out_s);
	return ret;
#else
	return SSL_get_peer_certificate(s);
#endif
}
X509 *
SSL_get_peer_certificate(const SSL *s)
{
	X509	*r;

	if ((s == NULL) || (s->session == NULL))
		r = NULL;
	else
		r = s->session->peer;

	if (r == NULL)
		return (r);

	CRYPTO_add(&r->references, 1, CRYPTO_LOCK_X509);

	return (r);
}

STACK_OF(X509) *
SSL_get_peer_cert_chain(const SSL *s)
{
	STACK_OF(X509)	*r;

	if ((s == NULL) || (s->session == NULL) ||
	    (s->session->sess_cert == NULL))
		r = NULL;
	else
		r = s->session->sess_cert->cert_chain;

	/*
	 * If we are a client, cert_chain includes the peer's own
	 * certificate;
	 * if we are a server, it does not.
	 */
	return (r);
}

/*
 * Now in theory, since the calling process own 't' it should be safe to
 * modify.  We need to be able to read f without being hassled
 */
void
SSL_copy_session_id(SSL *t, const SSL *f)
{
	CERT	*tmp;

	/* Do we need to to SSL locking? */
	SSL_set_session(t, SSL_get_session(f));

	/*
	 * What if we are setup as SSLv2 but want to talk SSLv3 or
	 * vice-versa.
	 */
	if (t->method != f->method) {
		t->method->ssl_free(t);	/* cleanup current */
		t->method=f->method;	/* change method */
		t->method->ssl_new(t);	/* setup new */
	}

	tmp = t->cert;
	if (f->cert != NULL) {
		CRYPTO_add(&f->cert->references, 1, CRYPTO_LOCK_SSL_CERT);
		t->cert = f->cert;
	} else
		t->cert = NULL;
	if (tmp != NULL)
		ssl_cert_free(tmp);
	SSL_set_session_id_context(t, f->sid_ctx, f->sid_ctx_length);
}

/* Fix this so it checks all the valid key/cert options */
int
ecall_SSL_CTX_check_private_key(const SSL_CTX *ctx) {
    LogEnter(__func__);
	return SSL_CTX_check_private_key(ctx);
}
int
SSL_CTX_check_private_key(const SSL_CTX *ctx)
{
	if ((ctx == NULL) || (ctx->cert == NULL) ||
	    (ctx->cert->key->x509 == NULL)) {
		SSLerr(SSL_F_SSL_CTX_CHECK_PRIVATE_KEY,
		    SSL_R_NO_CERTIFICATE_ASSIGNED);
		return (0);
	}
	if (ctx->cert->key->privatekey == NULL) {
		SSLerr(SSL_F_SSL_CTX_CHECK_PRIVATE_KEY,
		    SSL_R_NO_PRIVATE_KEY_ASSIGNED);
		return (0);
	}
	return (X509_check_private_key(ctx->cert->key->x509,
	    ctx->cert->key->privatekey));
}

/* Fix this function so that it takes an optional type parameter */
int
SSL_check_private_key(const SSL *ssl)
{
	if (ssl == NULL) {
		SSLerr(SSL_F_SSL_CHECK_PRIVATE_KEY,
		    ERR_R_PASSED_NULL_PARAMETER);
		return (0);
	}
	if (ssl->cert == NULL) {
		SSLerr(SSL_F_SSL_CHECK_PRIVATE_KEY,
		    SSL_R_NO_CERTIFICATE_ASSIGNED);
		return (0);
	}
	if (ssl->cert->key->x509 == NULL) {
		SSLerr(SSL_F_SSL_CHECK_PRIVATE_KEY,
		    SSL_R_NO_CERTIFICATE_ASSIGNED);
		return (0);
	}
	if (ssl->cert->key->privatekey == NULL) {
		SSLerr(SSL_F_SSL_CHECK_PRIVATE_KEY,
		    SSL_R_NO_PRIVATE_KEY_ASSIGNED);
		return (0);
	}
	return (X509_check_private_key(ssl->cert->key->x509,
	    ssl->cert->key->privatekey));
}

#ifdef COMPILE_WITH_INTEL_SGX

void lthread_main_handler(void* arg) {
	//Do not return from this function, otherwise the LT_ST_EXITED bit in lt->state is set
	//and it creates problems

	while (1) {
		char* msg = lthread_get_task_args()->msg;
		enum transition_type type = lthread_get_task_args()->type;
		//int slot = lthread_get_task_args()->slot;
		size_t size = 0;

		//my_printf("task %p msg %p type %d slot %d\n", lthread_current(), msg, type, slot);

		if (type == ecall_ssl_accept) {
			struct cell_ssl_accept* s = (struct cell_ssl_accept*)msg;
			size = sizeof(*s);
			//my_printf("task %p slot %d ecall_SSL_accept\n", lthread_current(), slot);
			s->ret = ecall_SSL_accept(s->ssl);
		} else if (type == ecall_ssl_read) {
			struct cell_ssl_read* s = (struct cell_ssl_read*)msg;
			size = sizeof(*s);
			//my_printf("task %p slot %d ecall_SSL_read\n", lthread_current(), slot);
			s->ret = ecall_SSL_read(s->ssl, s->buf, s->num);
		} else if (type == ecall_ssl_new) {
			struct cell_ssl_new* s = (struct cell_ssl_new*)msg;
			size = sizeof(*s);
			//my_printf("task %p slot %d ecall_SSL_new\n", lthread_current(), slot);
			s->ret = ecall_SSL_new(s->ctx, s->out_s);
		} else if (type == ecall_ssl_free) {
			struct cell_ssl_free* s = (struct cell_ssl_free*)msg;
			size = sizeof(*s);
			//my_printf("task %p slot %d ecall_SSL_free\n", lthread_current(), slot);
			ecall_SSL_free(s->out_s);
		} else if (type == ecall_ssl_write) {
			struct cell_ssl_write* s = (struct cell_ssl_write*)msg;
			size = sizeof(*s);
			//my_printf("task %p slot %d ecall_SSL_write\n", lthread_current(), slot);
			s->ret = ecall_SSL_write(s->ssl, s->buf, s->num);
		} else if (type == ecall_ssl_ctrl) {
			struct cell_ssl_ctrl* s = (struct cell_ssl_ctrl*)msg;
			size = sizeof(*s);
			//my_printf("task %p slot %d ecall_SSL_ctrl\n", lthread_current(), slot);
			s->ret = ecall_SSL_ctrl(s->ssl, s->cmd, s->larg, s->parg);
		} else if (type == ecall_ssl_set_bio) {
			struct cell_ssl_set_bio* s = (struct cell_ssl_set_bio*)msg;
			size = sizeof(*s);
			//my_printf("task %p slot %d ecall_SSL_set_bio\n", lthread_current(), slot);
			ecall_SSL_set_bio(s->ssl, s->rbio, s->wbio);
		} else if (type == ecall_ssl_shutdown) {
			struct cell_ssl_shutdown* s = (struct cell_ssl_shutdown*)msg;
			size = sizeof(*s);
			//my_printf("task %p slot %d ecall_SSL_shutdown\n", lthread_current(), slot);
			s->ret = ecall_SSL_shutdown(s->ssl);
		} else if (type == ecall_ssl_set_connect_state) {
			struct cell_ssl_set_connect_state* s = (struct cell_ssl_set_connect_state*)msg;
			size = sizeof(*s);
			//my_printf("task %p slot %d ecall_SSL_set_connect_state\n", lthread_current(), slot);
			ecall_SSL_set_connect_state(s->ssl);
			s->ret = 1;
		} else if (type == ecall_ssl_get_certificate) {
			struct cell_ssl_get_certificate* s = (struct cell_ssl_get_certificate*)msg;
			size = sizeof(*s);
			//my_printf("task %p slot %d ecall_SSL_get_certificate\n", lthread_current(), slot);
			s->ret = ecall_SSL_get_certificate(s->ssl);
		} else if (type == ecall_ssl_get_error) {
			struct cell_ssl_get_error* s = (struct cell_ssl_get_error*)msg;
			size = sizeof(*s);
			//my_printf("task %p slot %d ecall_SSL_get_error\n", lthread_current(), slot);
			s->ret = ecall_SSL_get_error(s->ssl, s->ret_code);
		} else if (type == ecall_bio_new) {
			struct cell_bio_new* s = (struct cell_bio_new*)msg;
			size = sizeof(*s);
			//my_printf("task %p slot %d ecall_BIO_new\n", lthread_current(), slot);
			s->ret = ecall_BIO_new(s->type, &(s->method_in_enclave));
		} else if (type == ecall_bio_ctrl) {
			struct cell_bio_ctrl* s = (struct cell_bio_ctrl*)msg;
			size = sizeof(*s);
			//my_printf("task %p slot %d ecall_BIO_ctrl\n", lthread_current(), slot);
			s->ret = ecall_BIO_ctrl(s->bio, s->cmd, s->larg, s->parg);
		} else {
			//undef: no message
			//my_printf("task %p slot %d no message\n", lthread_current(), slot);
		}

		lthread_get_task_args()->size = size;
		lthread_get_task_args()->do_ocall = 0;
		lthread_yield();
	}
}

void ecall_start_sgx_thread(void* eq, void* oq, int tid, int appthreads, int sgxthreads, int lthread_tasks, int ncycles, uint64_t* rdtsc_value) {
    LogEnter(__func__);
	int i;

	ocall_init_async_ocalls(oq, tid, appthreads, sgxthreads, lthread_tasks, ncycles);
	// 1 queue per thread, as tasks don't have the same scheduler
	struct mpmc_queue* sched_ready_q;
	struct mpmc_queue* sched_ocall_q;
	__initschedqueue((size_t)appthreads, &sched_ready_q, &sched_ocall_q);

	for (i=0; i<lthread_tasks; i++) {
		my_printf("thread %d starting task %d\n", tid, i);
		lthread_t *lt = NULL;
		lthread_create(&lt, lthread_main_handler, NULL, sched_ready_q);
	}

	my_printf("run lthread in thread %d\n", tid);
	lthread_run(eq, oq, tid, appthreads, sgxthreads, lthread_tasks, ncycles, sched_ready_q, sched_ocall_q, rdtsc_value);
}
#endif


int
ecall_SSL_accept(SSL *s)
{
    LogEnter(__func__);
#ifdef COMPILE_WITH_INTEL_SGX
	SSL* out_s = s;

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	SSL_copy_fields_to_in_struct(in_s, out_s);
	int ret = SSL_accept(in_s);
	SSL_copy_fields_to_out_struct(in_s, out_s);

	return ret;
#else
	return SSL_accept(s);
#endif
}
int
SSL_accept(SSL *s)
{
	if (s->handshake_func == NULL)
		SSL_set_accept_state(s); /* Not properly initialized yet */

	return (s->method->ssl_accept(s));
}

int
ecall_SSL_connect(SSL *s) {
    LogEnter(__func__);
	int ret;
#ifdef COMPILE_WITH_INTEL_SGX
	SSL* out_s = s;

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	SSL_copy_fields_to_in_struct(in_s, out_s);
	ret = SSL_connect(in_s);
	SSL_copy_fields_to_out_struct(in_s, out_s);
#else
	ret = SSL_connect(s);
#endif
	return ret;
}
int
SSL_connect(SSL *s)
{
	if (s->handshake_func == NULL)
		SSL_set_connect_state(s); /* Not properly initialized yet */

	return (s->method->ssl_connect(s));
}

long
SSL_get_default_timeout(const SSL *s)
{
	return (s->method->get_timeout());
}

int
ecall_SSL_read(SSL *s, void *buf, int num) {
    LogEnter(__func__);
#ifdef COMPILE_WITH_INTEL_SGX
	SSL* out_s = s;
 
	// Fix Github issue #20: need to ensure that buf
	// is allocated outside the enclave
	if (!sgx_is_outside_enclave(buf, num)) {
		return -1;
	}

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	SSL_copy_fields_to_in_struct(in_s, out_s);
	int ret = SSL_read(in_s, buf, num);
	SSL_copy_fields_to_out_struct(in_s, out_s);
	return ret;
#else
	return SSL_read(s, buf, num);
#endif
}
int
SSL_read(SSL *s, void *buf, int num)
{
	if (s->handshake_func == NULL) {
		SSLerr(SSL_F_SSL_READ, SSL_R_UNINITIALIZED);
		return (-1);
	}

	if (s->shutdown & SSL_RECEIVED_SHUTDOWN) {
		s->rwstate = SSL_NOTHING;
		return (0);
	}
	return (s->method->ssl_read(s, buf, num));
}

int
SSL_peek(SSL *s, void *buf, int num)
{
	if (s->handshake_func == NULL) {
		SSLerr(SSL_F_SSL_PEEK, SSL_R_UNINITIALIZED);
		return (-1);
	}

	if (s->shutdown & SSL_RECEIVED_SHUTDOWN) {
		return (0);
	}
	return (s->method->ssl_peek(s, buf, num));
}

int
ecall_SSL_write(SSL *s, const void *buf, int num) {
    LogEnter(__func__);
#ifdef COMPILE_WITH_INTEL_SGX
	SSL* out_s = s;

	// Fix Github issue #13: need to ensure that the buf
	// buffer is allocated outside the enclave, otherwise an
	// attacker could send enclave memory to a remote party
	if (!sgx_is_outside_enclave(buf, num)) {
		return -1;
	}

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	SSL_copy_fields_to_in_struct(in_s, out_s);
	int ret = SSL_write(in_s, buf, num);
	SSL_copy_fields_to_out_struct(in_s, out_s);
	return ret;
#else
	return SSL_write(s, buf, num);
#endif
}
int
SSL_write(SSL *s, const void *buf, int num)
{
	if (s->handshake_func == NULL) {
		SSLerr(SSL_F_SSL_WRITE, SSL_R_UNINITIALIZED);
		return (-1);
	}

	if (s->shutdown & SSL_SENT_SHUTDOWN) {
		s->rwstate = SSL_NOTHING;
		SSLerr(SSL_F_SSL_WRITE, SSL_R_PROTOCOL_IS_SHUTDOWN);
		return (-1);
	}
	return (s->method->ssl_write(s, buf, num));
}

int
ecall_SSL_shutdown(SSL *s) {
    LogEnter(__func__);
#ifdef COMPILE_WITH_INTEL_SGX
	SSL* out_s = s;

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	SSL_copy_fields_to_in_struct(in_s, out_s);
	int ret = SSL_shutdown(in_s);
	SSL_copy_fields_to_out_struct(in_s, out_s);
	return ret;
#else
	return SSL_shutdown(s);
#endif
}
int
SSL_shutdown(SSL *s)
{
	/*
	 * Note that this function behaves differently from what one might
	 * expect.  Return values are 0 for no success (yet),
	 * 1 for success; but calling it once is usually not enough,
	 * even if blocking I/O is used (see ssl3_shutdown).
	 */

	if (s->handshake_func == NULL) {
		SSLerr(SSL_F_SSL_SHUTDOWN, SSL_R_UNINITIALIZED);
		return (-1);
	}

	if ((s != NULL) && !SSL_in_init(s))
		return (s->method->ssl_shutdown(s));
	else
		return (1);
}

int
SSL_renegotiate(SSL *s)
{
	if (s->renegotiate == 0)
		s->renegotiate = 1;

	s->new_session = 1;

	return (s->method->ssl_renegotiate(s));
}

int
SSL_renegotiate_abbreviated(SSL *s)
{
	if (s->renegotiate == 0)
		s->renegotiate = 1;

	s->new_session = 0;

	return (s->method->ssl_renegotiate(s));
}

int
SSL_renegotiate_pending(SSL *s)
{
	/*
	 * Becomes true when negotiation is requested;
	 * false again once a handshake has finished.
	 */
	return (s->renegotiate != 0);
}

long
ecall_SSL_ctrl(SSL *s, int cmd, long larg, void *parg)
{
    LogEnter(__func__);
#ifdef COMPILE_WITH_INTEL_SGX
	SSL* out_s = s;

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	SSL_copy_fields_to_in_struct(in_s, out_s);
	long ret = SSL_ctrl(in_s, cmd, larg, parg);
	SSL_copy_fields_to_out_struct(in_s, out_s);
	return ret;
#else
	return SSL_ctrl(s, cmd, larg, parg);
#endif
}
long
SSL_ctrl(SSL *s, int cmd, long larg, void *parg)
{
	long	l;

	switch (cmd) {
	case SSL_CTRL_GET_READ_AHEAD:
		return (s->read_ahead);
	case SSL_CTRL_SET_READ_AHEAD:
		l = s->read_ahead;
		s->read_ahead = larg;
		return (l);

	case SSL_CTRL_SET_MSG_CALLBACK_ARG:
		s->msg_callback_arg = parg;
		return (1);

	case SSL_CTRL_OPTIONS:
		return (s->options|=larg);
	case SSL_CTRL_CLEAR_OPTIONS:
		return (s->options&=~larg);
	case SSL_CTRL_MODE:
		return (s->mode|=larg);
	case SSL_CTRL_CLEAR_MODE:
		return (s->mode &=~larg);
	case SSL_CTRL_GET_MAX_CERT_LIST:
		return (s->max_cert_list);
	case SSL_CTRL_SET_MAX_CERT_LIST:
		l = s->max_cert_list;
		s->max_cert_list = larg;
		return (l);
	case SSL_CTRL_SET_MTU:
#ifndef OPENSSL_NO_DTLS1
		if (larg < (long)dtls1_min_mtu())
			return (0);
#endif
		if (SSL_IS_DTLS(s)) {
			s->d1->mtu = larg;
			return (larg);
		}
		return (0);
	case SSL_CTRL_SET_MAX_SEND_FRAGMENT:
		if (larg < 512 || larg > SSL3_RT_MAX_PLAIN_LENGTH)
			return (0);
		s->max_send_fragment = larg;
		return (1);
	case SSL_CTRL_GET_RI_SUPPORT:
		if (s->s3)
			return (s->s3->send_connection_binding);
		else return (0);
	default:
		return (s->method->ssl_ctrl(s, cmd, larg, parg));
	}
}

long
SSL_callback_ctrl(SSL *s, int cmd, void (*fp)(void))
{
	switch (cmd) {
	case SSL_CTRL_SET_MSG_CALLBACK:
		s->msg_callback = (void (*)(int write_p, int version,
		    int content_type, const void *buf, size_t len,
		    SSL *ssl, void *arg))(fp);
		return (1);

	default:
		return (s->method->ssl_callback_ctrl(s, cmd, fp));
	}
}

LHASH_OF(SSL_SESSION) *
SSL_CTX_sessions(SSL_CTX *ctx)
{
	return (ctx->sessions);
}

long ecall_SSL_CTX_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg) {
    LogEnter(__func__);
	return SSL_CTX_ctrl(ctx, cmd, larg, parg);
}

long
SSL_CTX_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg)
{
	long	l;

	switch (cmd) {
	case SSL_CTRL_GET_READ_AHEAD:
		return (ctx->read_ahead);
	case SSL_CTRL_SET_READ_AHEAD:
		l = ctx->read_ahead;
		ctx->read_ahead = larg;
		return (l);

	case SSL_CTRL_SET_MSG_CALLBACK_ARG:
		ctx->msg_callback_arg = parg;
		return (1);

	case SSL_CTRL_GET_MAX_CERT_LIST:
		return (ctx->max_cert_list);
	case SSL_CTRL_SET_MAX_CERT_LIST:
		l = ctx->max_cert_list;
		ctx->max_cert_list = larg;
		return (l);

	case SSL_CTRL_SET_SESS_CACHE_SIZE:
		l = ctx->session_cache_size;
		ctx->session_cache_size = larg;
		return (l);
	case SSL_CTRL_GET_SESS_CACHE_SIZE:
		return (ctx->session_cache_size);
	case SSL_CTRL_SET_SESS_CACHE_MODE:
		l = ctx->session_cache_mode;
		ctx->session_cache_mode = larg;
		return (l);
	case SSL_CTRL_GET_SESS_CACHE_MODE:
		return (ctx->session_cache_mode);

	case SSL_CTRL_SESS_NUMBER:
		return (lh_SSL_SESSION_num_items(ctx->sessions));
	case SSL_CTRL_SESS_CONNECT:
		return (ctx->stats.sess_connect);
	case SSL_CTRL_SESS_CONNECT_GOOD:
		return (ctx->stats.sess_connect_good);
	case SSL_CTRL_SESS_CONNECT_RENEGOTIATE:
		return (ctx->stats.sess_connect_renegotiate);
	case SSL_CTRL_SESS_ACCEPT:
		return (ctx->stats.sess_accept);
	case SSL_CTRL_SESS_ACCEPT_GOOD:
		return (ctx->stats.sess_accept_good);
	case SSL_CTRL_SESS_ACCEPT_RENEGOTIATE:
		return (ctx->stats.sess_accept_renegotiate);
	case SSL_CTRL_SESS_HIT:
		return (ctx->stats.sess_hit);
	case SSL_CTRL_SESS_CB_HIT:
		return (ctx->stats.sess_cb_hit);
	case SSL_CTRL_SESS_MISSES:
		return (ctx->stats.sess_miss);
	case SSL_CTRL_SESS_TIMEOUTS:
		return (ctx->stats.sess_timeout);
	case SSL_CTRL_SESS_CACHE_FULL:
		return (ctx->stats.sess_cache_full);
	case SSL_CTRL_OPTIONS:
		return (ctx->options|=larg);
	case SSL_CTRL_CLEAR_OPTIONS:
		return (ctx->options&=~larg);
	case SSL_CTRL_MODE:
		return (ctx->mode|=larg);
	case SSL_CTRL_CLEAR_MODE:
		return (ctx->mode&=~larg);
	case SSL_CTRL_SET_MAX_SEND_FRAGMENT:
		if (larg < 512 || larg > SSL3_RT_MAX_PLAIN_LENGTH)
			return (0);
		ctx->max_send_fragment = larg;
		return (1);
	default:
		return (ctx->method->ssl_ctx_ctrl(ctx, cmd, larg, parg));
	}
}

#ifdef COMPILE_WITH_INTEL_SGX

void* ssl_ctx_info_cb_address = 0;

void ssl_ctx_info_fake_cb(const SSL *ssl, int type, int val) {
	/*
	 * From the documentation ( man SSL_CTX_set_info_callback):
	 *        When setting up a connection and during use, it is possible to obtain
	 *        state information from the SSL/TLS engine. When set, an information
	 *        callback function is called whenever the state changes, an alert
	 *        appears, or an error occurs.
	 */
	// do not use this callback in Apache (not needed). However nginx requires it
#ifdef COMPILE_OPTIMISATION_FOR_APACHE
	return;
#else
	if (ssl_ctx_info_cb_address) {
		hashmap* m = get_ssl_hardening();
		SSL* out_s = (SSL*) hashmapGet(m, (unsigned long)ssl);

		SSL_copy_fields_to_out_struct(ssl, out_s);
		ocall_execute_ssl_ctx_info_callback(out_s, type, val, ssl_ctx_info_cb_address);
		SSL_copy_fields_to_in_struct((SSL*)ssl, (const SSL*)out_s);
	}
#endif
}
#endif

#ifdef COMPILE_WITH_INTEL_SGX
static void* callback_address = 0;

static int callback_trampoline(SSL* ssl, int* ad, void* arg) {
	return SSL_TLSEXT_ERR_OK;
	// don't call this callback. It is used for SNI stuff that we don't need
	int ret = 0;
	if (callback_address) {
		hashmap* m = get_ssl_hardening();
		SSL* out_s = (SSL*) hashmapGet(m, (unsigned long)ssl);

		SSL_copy_fields_to_out_struct(ssl, out_s);
		ocall_ssl_ctx_callback_ctrl(&ret, out_s, ad, arg, (void*)callback_address);
		SSL_copy_fields_to_in_struct(ssl, out_s);
	}
	return ret;
}

long
ecall_SSL_CTX_callback_ctrl(SSL_CTX *ctx, int cmd, void *cb) {
    LogEnter(__func__);
	if (cmd != SSL_CTRL_SET_TLSEXT_SERVERNAME_CB) {
		// we don't handle other cases
		return 0;
	} else {
		callback_address = cb;
		return SSL_CTX_callback_ctrl(ctx, cmd, (void (*)(void))callback_trampoline);
	}
}
#else
long
ecall_SSL_CTX_callback_ctrl(SSL_CTX *ctx, int cmd, void *cb) {
    LogEnter(__func__);
	return SSL_CTX_callback_ctrl(ctx, cmd, (void (*)(void))cb);
}
#endif

long
SSL_CTX_callback_ctrl(SSL_CTX *ctx, int cmd, void (*fp)(void))
{
	switch (cmd) {
	case SSL_CTRL_SET_MSG_CALLBACK:
		ctx->msg_callback = (void (*)(int write_p, int version,
		    int content_type, const void *buf, size_t len, SSL *ssl,
		    void *arg))(fp);
		return (1);

	default:
		return (ctx->method->ssl_ctx_callback_ctrl(ctx, cmd, fp));
	}
}

int
ssl_cipher_id_cmp(const SSL_CIPHER *a, const SSL_CIPHER *b)
{
	long	l;

	l = a->id - b->id;
	if (l == 0L)
		return (0);
	else
		return ((l > 0) ? 1:-1);
}

int
ssl_cipher_ptr_id_cmp(const SSL_CIPHER * const *ap,
    const SSL_CIPHER * const *bp)
{
	long	l;

	l = (*ap)->id - (*bp)->id;
	if (l == 0L)
		return (0);
	else
		return ((l > 0) ? 1:-1);
}

/*
 * Return a STACK of the ciphers available for the SSL and in order of
 * preference.
 */
STACK_OF(SSL_CIPHER) *
ecall_SSL_get_ciphers(const SSL *s)
{
    LogEnter(__func__);
#ifdef COMPILE_WITH_INTEL_SGX
	const SSL* out_s = s;

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	SSL_copy_fields_to_in_struct(in_s, out_s);
	STACK_OF(SSL_CIPHER) *ret = SSL_get_ciphers(in_s);
	return ret;
#else
	return SSL_get_ciphers(s);
#endif
}
STACK_OF(SSL_CIPHER) *
SSL_get_ciphers(const SSL *s)
{
	if (s != NULL) {
		if (s->cipher_list != NULL) {
			return (s->cipher_list);
		} else if ((s->ctx != NULL) && (s->ctx->cipher_list != NULL)) {
			return (s->ctx->cipher_list);
		}
	}
	return (NULL);
}

/*
 * Return a STACK of the ciphers available for the SSL and in order of
 * algorithm id.
 */
STACK_OF(SSL_CIPHER) *
ssl_get_ciphers_by_id(SSL *s)
{
	if (s != NULL) {
		if (s->cipher_list_by_id != NULL) {
			return (s->cipher_list_by_id);
		} else if ((s->ctx != NULL) &&
		    (s->ctx->cipher_list_by_id != NULL)) {
			return (s->ctx->cipher_list_by_id);
		}
	}
	return (NULL);
}

/* The old interface to get the same thing as SSL_get_ciphers(). */
const char *
SSL_get_cipher_list(const SSL *s, int n)
{
	SSL_CIPHER		*c;
	STACK_OF(SSL_CIPHER)	*sk;

	if (s == NULL)
		return (NULL);
	sk = SSL_get_ciphers(s);
	if ((sk == NULL) || (sk_SSL_CIPHER_num(sk) <= n))
		return (NULL);
	c = sk_SSL_CIPHER_value(sk, n);
	if (c == NULL)
		return (NULL);
	return (c->name);
}

/* Specify the ciphers to be used by default by the SSL_CTX. */
int
ecall_SSL_CTX_set_cipher_list(SSL_CTX *ctx, const char *str) {
    LogEnter(__func__);
	return SSL_CTX_set_cipher_list(ctx, str);
}
int
SSL_CTX_set_cipher_list(SSL_CTX *ctx, const char *str)
{
	STACK_OF(SSL_CIPHER)	*sk;

	sk = ssl_create_cipher_list(ctx->method, &ctx->cipher_list,
	    &ctx->cipher_list_by_id, str);
	/*
	 * ssl_create_cipher_list may return an empty stack if it
	 * was unable to find a cipher matching the given rule string
	 * (for example if the rule string specifies a cipher which
	 * has been disabled). This is not an error as far as
	 * ssl_create_cipher_list is concerned, and hence
	 * ctx->cipher_list and ctx->cipher_list_by_id has been
	 * updated.
	 */
	if (sk == NULL)
		return (0);
	else if (sk_SSL_CIPHER_num(sk) == 0) {
		SSLerr(SSL_F_SSL_CTX_SET_CIPHER_LIST, SSL_R_NO_CIPHER_MATCH);
		return (0);
	}
	return (1);
}

/* Specify the ciphers to be used by the SSL. */
int
ecall_SSL_set_cipher_list(SSL *s, const char *str)
{
    LogEnter(__func__);
	int ret;
#ifdef COMPILE_WITH_INTEL_SGX
	SSL* out_s = s;
	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	SSL_copy_fields_to_in_struct(in_s, out_s);
	ret = SSL_set_cipher_list(in_s, str);
	SSL_copy_fields_to_out_struct(in_s, out_s);
#else
	ret = SSL_set_cipher_list(s, str);
#endif
	return ret;
}
int
SSL_set_cipher_list(SSL *s, const char *str)
{
	STACK_OF(SSL_CIPHER)	*sk;

	sk = ssl_create_cipher_list(s->ctx->method, &s->cipher_list,
	&s->cipher_list_by_id, str);
	/* see comment in SSL_CTX_set_cipher_list */
	if (sk == NULL)
		return (0);
	else if (sk_SSL_CIPHER_num(sk) == 0) {
		SSLerr(SSL_F_SSL_SET_CIPHER_LIST, SSL_R_NO_CIPHER_MATCH);
		return (0);
	}
	return (1);
}

/* works well for SSLv2, not so good for SSLv3 */
char *
SSL_get_shared_ciphers(const SSL *s, char *buf, int len)
{
	char			*end;
	STACK_OF(SSL_CIPHER)	*sk;
	SSL_CIPHER		*c;
	size_t			 curlen = 0;
	int			 i;

	if (s->session == NULL || s->session->ciphers == NULL || len < 2)
		return (NULL);

	sk = s->session->ciphers;
	if (sk_SSL_CIPHER_num(sk) == 0)
		return (NULL);

	buf[0] = '\0';
	for (i = 0; i < sk_SSL_CIPHER_num(sk); i++) {
		c = sk_SSL_CIPHER_value(sk, i);
		end = buf + curlen;
		if (strlcat(buf, c->name, len) >= len ||
		    (curlen = strlcat(buf, ":", len)) >= len) {
			/* remove truncated cipher from list */
			*end = '\0';
			break;
		}
	}
	/* remove trailing colon */
	if ((end = strrchr(buf, ':')) != NULL)
		*end = '\0';
	return (buf);
}

int
ssl_cipher_list_to_bytes(SSL *s, STACK_OF(SSL_CIPHER) *sk, unsigned char *p)
{
	int		 i;
	SSL_CIPHER	*c;
	unsigned char	*q;

	if (sk == NULL)
		return (0);
	q = p;

	for (i = 0; i < sk_SSL_CIPHER_num(sk); i++) {
		c = sk_SSL_CIPHER_value(sk, i);

		/* Skip TLS v1.2 only ciphersuites if lower than v1.2 */
		if ((c->algorithm_ssl & SSL_TLSV1_2) &&
		    (TLS1_get_client_version(s) < TLS1_2_VERSION))
			continue;

		s2n(ssl3_cipher_get_value(c), p);
	}

	/*
	 * If p == q, no ciphers and caller indicates an error. Otherwise
	 * add SCSV if not renegotiating.
	 */
	if (p != q && !s->renegotiate)
		s2n(SSL3_CK_SCSV & SSL3_CK_VALUE_MASK, p);

	return (p - q);
}

STACK_OF(SSL_CIPHER) *
ssl_bytes_to_cipher_list(SSL *s, const unsigned char *p, int num)
{
	CBS			 cbs;
	const SSL_CIPHER	*c;
	STACK_OF(SSL_CIPHER)	*sk = NULL;
	unsigned long		 cipher_id;
	uint16_t		 cipher_value, max_version;

	if (s->s3)
		s->s3->send_connection_binding = 0;

	/*
	 * RFC 5246 section 7.4.1.2 defines the interval as [2,2^16-2].
	 */
	if (num < 2 || num > 0x10000 - 2) {
		SSLerr(SSL_F_SSL_BYTES_TO_CIPHER_LIST,
		    SSL_R_ERROR_IN_RECEIVED_CIPHER_LIST);
		return (NULL);
	}

	if ((sk = sk_SSL_CIPHER_new_null()) == NULL) {
		SSLerr(SSL_F_SSL_BYTES_TO_CIPHER_LIST, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	CBS_init(&cbs, p, num);
	while (CBS_len(&cbs) > 0) {
		if (!CBS_get_u16(&cbs, &cipher_value)) {
			SSLerr(SSL_F_SSL_BYTES_TO_CIPHER_LIST,
			    SSL_R_ERROR_IN_RECEIVED_CIPHER_LIST);
			goto err;
		}

		cipher_id = SSL3_CK_ID | cipher_value;

		if (s->s3 != NULL && cipher_id == SSL3_CK_SCSV) {
			/*
			 * TLS_EMPTY_RENEGOTIATION_INFO_SCSV is fatal if
			 * renegotiating.
			 */
			if (s->renegotiate) {
				SSLerr(SSL_F_SSL_BYTES_TO_CIPHER_LIST,
				    SSL_R_SCSV_RECEIVED_WHEN_RENEGOTIATING);
				ssl3_send_alert(s, SSL3_AL_FATAL,
				    SSL_AD_HANDSHAKE_FAILURE);

				goto err;
			}
			s->s3->send_connection_binding = 1;
			continue;
		}

		if (cipher_id == SSL3_CK_FALLBACK_SCSV) {
			/*
			 * TLS_FALLBACK_SCSV indicates that the client
			 * previously tried a higher protocol version.
			 * Fail if the current version is an unexpected
			 * downgrade.
			 */
			max_version = ssl_max_server_version(s);
			if (max_version == 0 || s->version < max_version) {
				SSLerr(SSL_F_SSL_BYTES_TO_CIPHER_LIST,
				    SSL_R_INAPPROPRIATE_FALLBACK);
				if (s->s3 != NULL)
					ssl3_send_alert(s, SSL3_AL_FATAL,
					    SSL_AD_INAPPROPRIATE_FALLBACK);
				goto err;
			}
			continue;
		}

		if ((c = ssl3_get_cipher_by_value(cipher_value)) != NULL) {
			if (!sk_SSL_CIPHER_push(sk, c)) {
				SSLerr(SSL_F_SSL_BYTES_TO_CIPHER_LIST,
				    ERR_R_MALLOC_FAILURE);
				goto err;
			}
		}
	}

	return (sk);

err:
	sk_SSL_CIPHER_free(sk);

	return (NULL);
}


/*
 * Return a servername extension value if provided in Client Hello, or NULL.
 * So far, only host_name types are defined (RFC 3546).
 */
void ecall_SSL_get_servername(const SSL *s, int type, char* servername, int* len) {
    LogEnter(__func__);
#ifdef COMPILE_WITH_INTEL_SGX
	SSL* out_s = (SSL*)s;

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	SSL_copy_fields_to_in_struct(in_s, out_s);
	const char* sn = SSL_get_servername((const SSL*)in_s, type);
	SSL_copy_fields_to_out_struct(in_s, out_s);
#else
	const char* sn = SSL_get_servername(s, type);
#endif
	if (sn == NULL) {
		servername[0] = '\0';
		*len = 0;
	} else {
		*len = strlen(sn);
		memcpy(servername, sn, *len);
	}
}
const char *
SSL_get_servername(const SSL *s, const int type)
{
	if (type != TLSEXT_NAMETYPE_host_name)
		return (NULL);

	return (s->session && !s->tlsext_hostname ?
	    s->session->tlsext_hostname :
	    s->tlsext_hostname);
}

int
SSL_get_servername_type(const SSL *s)
{
	if (s->session &&
	    (!s->tlsext_hostname ?
	    s->session->tlsext_hostname : s->tlsext_hostname))
		return (TLSEXT_NAMETYPE_host_name);
	return (-1);
}

/*
 * SSL_select_next_proto implements the standard protocol selection. It is
 * expected that this function is called from the callback set by
 * SSL_CTX_set_next_proto_select_cb.
 *
 * The protocol data is assumed to be a vector of 8-bit, length prefixed byte
 * strings. The length byte itself is not included in the length. A byte
 * string of length 0 is invalid. No byte string may be truncated.
 *
 * The current, but experimental algorithm for selecting the protocol is:
 *
 * 1) If the server doesn't support NPN then this is indicated to the
 * callback. In this case, the client application has to abort the connection
 * or have a default application level protocol.
 *
 * 2) If the server supports NPN, but advertises an empty list then the
 * client selects the first protcol in its list, but indicates via the
 * API that this fallback case was enacted.
 *
 * 3) Otherwise, the client finds the first protocol in the server's list
 * that it supports and selects this protocol. This is because it's
 * assumed that the server has better information about which protocol
 * a client should use.
 *
 * 4) If the client doesn't support any of the server's advertised
 * protocols, then this is treated the same as case 2.
 *
 * It returns either
 * OPENSSL_NPN_NEGOTIATED if a common protocol was found, or
 * OPENSSL_NPN_NO_OVERLAP if the fallback case was reached.
 */
int
ecall_SSL_select_next_proto(unsigned char **out, unsigned char *outlen,
    const unsigned char *server, unsigned int server_len,
    const unsigned char *client, unsigned int client_len)
{
    LogEnter(__func__);
	return SSL_select_next_proto(out, outlen, server, server_len, client, client_len);
}
int
SSL_select_next_proto(unsigned char **out, unsigned char *outlen,
    const unsigned char *server, unsigned int server_len,
    const unsigned char *client, unsigned int client_len)
{
	unsigned int		 i, j;
	const unsigned char	*result;
	int			 status = OPENSSL_NPN_UNSUPPORTED;

	/*
	 * For each protocol in server preference order,
	 * see if we support it.
	 */
	for (i = 0; i < server_len; ) {
		for (j = 0; j < client_len; ) {
			if (server[i] == client[j] &&
			    memcmp(&server[i + 1],
			    &client[j + 1], server[i]) == 0) {
				/* We found a match */
				result = &server[i];
				status = OPENSSL_NPN_NEGOTIATED;
				goto found;
			}
			j += client[j];
			j++;
		}
		i += server[i];
		i++;
	}

	/* There's no overlap between our protocols and the server's list. */
	result = client;
	status = OPENSSL_NPN_NO_OVERLAP;

found:
	*out = (unsigned char *) result + 1;
	*outlen = result[0];
	return (status);
}

/*
 * SSL_get0_next_proto_negotiated sets *data and *len to point to the client's
 * requested protocol for this connection and returns 0. If the client didn't
 * request any protocol, then *data is set to NULL.
 *
 * Note that the client can request any protocol it chooses. The value returned
 * from this function need not be a member of the list of supported protocols
 * provided by the callback.
 */
void
SSL_get0_next_proto_negotiated(const SSL *s, const unsigned char **data,
    unsigned *len)
{
	*data = s->next_proto_negotiated;
	if (!*data) {
		*len = 0;
	} else {
		*len = s->next_proto_negotiated_len;
	}
}

/*
 * SSL_CTX_set_next_protos_advertised_cb sets a callback that is called when a
 * TLS server needs a list of supported protocols for Next Protocol
 * Negotiation. The returned list must be in wire format.  The list is returned
 * by setting |out| to point to it and |outlen| to its length. This memory will
 * not be modified, but one should assume that the SSL* keeps a reference to
 * it.
 *
 * The callback should return SSL_TLSEXT_ERR_OK if it wishes to advertise.
 * Otherwise, no such extension will be included in the ServerHello.
 */
void ecall_SSL_CTX_set_next_protos_advertised_cb(SSL_CTX *s, void *cb, void *arg) {
    LogEnter(__func__);
	int (*callback) (SSL *ssl,  const unsigned char **out, unsigned int *outlen, void *arg) = (int (*) (SSL *ssl, const unsigned char **out, unsigned int *outlen, void *arg))cb;
	SSL_CTX_set_next_protos_advertised_cb(s, callback, arg);
}
void
SSL_CTX_set_next_protos_advertised_cb(SSL_CTX *ctx, int (*cb) (SSL *ssl,
    const unsigned char **out, unsigned int *outlen, void *arg), void *arg)
{
	ctx->next_protos_advertised_cb = cb;
	ctx->next_protos_advertised_cb_arg = arg;
}

/*
 * SSL_CTX_set_next_proto_select_cb sets a callback that is called when a
 * client needs to select a protocol from the server's provided list. |out|
 * must be set to point to the selected protocol (which may be within |in|).
 * The length of the protocol name must be written into |outlen|. The server's
 * advertised protocols are provided in |in| and |inlen|. The callback can
 * assume that |in| is syntactically valid.
 *
 * The client must select a protocol. It is fatal to the connection if this
 * callback returns a value other than SSL_TLSEXT_ERR_OK.
 */
#ifdef COMPILE_WITH_INTEL_SGX
int (*ssl_ctx_set_next_proto_select_cb_address)(SSL *s, unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg) = NULL;
int ssl_ctx_set_next_proto_select_fake_cb(SSL *s, unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg) {
	int retval = -1;

	if (ssl_ctx_set_next_proto_select_cb_address) {
		SSL* in_s = s;

		hashmap* m = get_ssl_hardening();
		SSL* out_s = (SSL*) hashmapGet(m, (unsigned long)in_s);

		SSL_copy_fields_to_out_struct(in_s, out_s);
		retval = ssl_ctx_set_next_proto_select_async_cb_wrapper(s, out, outlen, in, inlen, arg, ssl_ctx_set_next_proto_select_cb_address);
		SSL_copy_fields_to_in_struct(in_s, out_s);
	}
	return retval;
}
#endif

void ecall_SSL_CTX_set_next_proto_select_cb(SSL_CTX *s, void* cb, void *arg) {
    LogEnter(__func__);
#ifdef COMPILE_WITH_INTEL_SGX
	ssl_ctx_set_next_proto_select_cb_address = (int (*)(SSL *s, unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg))cb;
	int (*callback)(SSL *s, unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg) = ssl_ctx_set_next_proto_select_fake_cb;
#else
	int (*callback)(SSL *s, unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg) =
			(int (*)(SSL *s, unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg))cb;
#endif
	SSL_CTX_set_next_proto_select_cb(s, callback, arg);
}
void
SSL_CTX_set_next_proto_select_cb(SSL_CTX *ctx, int (*cb) (SSL *s,
    unsigned char **out, unsigned char *outlen, const unsigned char *in,
    unsigned int inlen, void *arg), void *arg)
{
	ctx->next_proto_select_cb = cb;
	ctx->next_proto_select_cb_arg = arg;
}

/*
 * SSL_CTX_set_alpn_protos sets the ALPN protocol list to the specified
 * protocols, which must be in wire-format (i.e. a series of non-empty,
 * 8-bit length-prefixed strings). Returns 0 on success.
 */
int
SSL_CTX_set_alpn_protos(SSL_CTX *ctx, const unsigned char *protos,
    unsigned int protos_len)
{
	free(ctx->alpn_client_proto_list);
	if ((ctx->alpn_client_proto_list = malloc(protos_len)) == NULL)
		return (1);
	memcpy(ctx->alpn_client_proto_list, protos, protos_len);
	ctx->alpn_client_proto_list_len = protos_len;

	return (0);
}

/*
 * SSL_set_alpn_protos sets the ALPN protocol list to the specified
 * protocols, which must be in wire-format (i.e. a series of non-empty,
 * 8-bit length-prefixed strings). Returns 0 on success.
 */
int
ecall_SSL_set_alpn_protos(SSL *ssl, const unsigned char* protos, unsigned int protos_len) {
    LogEnter(__func__);
    int retval = -1;
#ifdef COMPILE_WITH_INTEL_SGX
    SSL* out_s = (SSL*)ssl;

	 hashmap* m = get_ssl_hardening();
	 SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	SSL_copy_fields_to_in_struct(in_s, out_s);
	retval = SSL_set_alpn_protos(in_s, protos, protos_len);
	SSL_copy_fields_to_out_struct(in_s, out_s);
#else
	retval = SSL_set_alpn_protos(ssl, protos, protos_len);
#endif
    return retval;
}
int
SSL_set_alpn_protos(SSL *ssl, const unsigned char* protos,
    unsigned int protos_len)
{
	free(ssl->alpn_client_proto_list);
	if ((ssl->alpn_client_proto_list = malloc(protos_len)) == NULL)
		return (1);
	memcpy(ssl->alpn_client_proto_list, protos, protos_len);
	ssl->alpn_client_proto_list_len = protos_len;

	return (0);
}

/*
 * SSL_CTX_set_alpn_select_cb sets a callback function that is called during
 * ClientHello processing in order to select an ALPN protocol from the
 * client's list of offered protocols.
 */
void
ecall_SSL_CTX_set_alpn_select_cb(SSL_CTX* ctx, void *cb, void *arg)
{
    LogEnter(__func__);
	int (*callback) (SSL *ssl, const unsigned char **out, unsigned char *outlen,
	    const unsigned char *in, unsigned int inlen, void *arg) = (int (*) (SSL *ssl, const unsigned char **out, unsigned char *outlen,
	    	    const unsigned char *in, unsigned int inlen, void *arg))cb;
	SSL_CTX_set_alpn_select_cb(ctx, callback, arg);
}
void
SSL_CTX_set_alpn_select_cb(SSL_CTX* ctx,
    int (*cb) (SSL *ssl, const unsigned char **out, unsigned char *outlen,
    const unsigned char *in, unsigned int inlen, void *arg), void *arg)
{
	ctx->alpn_select_cb = cb;
	ctx->alpn_select_cb_arg = arg;
}

/*
 * SSL_get0_alpn_selected gets the selected ALPN protocol (if any). On return
 * it sets data to point to len bytes of protocol name (not including the
 * leading length-prefix byte). If the server didn't respond with* a negotiated
 * protocol then len will be zero.
 */
void
SSL_get0_alpn_selected(const SSL *ssl, const unsigned char **data,
    unsigned *len)
{
	*data = NULL;
	*len = 0;

	if (ssl->s3 != NULL) {
		*data = ssl->s3->alpn_selected;
		*len = ssl->s3->alpn_selected_len;
	}
}

int
SSL_export_keying_material(SSL *s, unsigned char *out, size_t olen,
    const char *label, size_t llen, const unsigned char *p, size_t plen,
    int use_context)
{
	return (s->method->ssl3_enc->export_keying_material(s, out, olen,
	    label, llen, p, plen, use_context));
}

static unsigned long
ssl_session_hash(const SSL_SESSION *a)
{
	unsigned long	l;

	l = (unsigned long)
	    ((unsigned int) a->session_id[0]     )|
	    ((unsigned int) a->session_id[1]<< 8L)|
	    ((unsigned long)a->session_id[2]<<16L)|
	    ((unsigned long)a->session_id[3]<<24L);
	return (l);
}

/*
 * NB: If this function (or indeed the hash function which uses a sort of
 * coarser function than this one) is changed, ensure
 * SSL_CTX_has_matching_session_id() is checked accordingly. It relies on being
 * able to construct an SSL_SESSION that will collide with any existing session
 * with a matching session ID.
 */
static int
ssl_session_cmp(const SSL_SESSION *a, const SSL_SESSION *b)
{
	if (a->ssl_version != b->ssl_version)
		return (1);
	if (a->session_id_length != b->session_id_length)
		return (1);
	if (timingsafe_memcmp(a->session_id, b->session_id, a->session_id_length) != 0)
		return (1);
	return (0);
}

/*
 * These wrapper functions should remain rather than redeclaring
 * SSL_SESSION_hash and SSL_SESSION_cmp for void* types and casting each
 * variable. The reason is that the functions aren't static, they're exposed via
 * ssl.h.
 */
static
IMPLEMENT_LHASH_HASH_FN(ssl_session, SSL_SESSION)
static
IMPLEMENT_LHASH_COMP_FN(ssl_session, SSL_SESSION)

SSL_CTX *
ecall_SSL_CTX_new(const SSL_METHOD *meth) {
    LogEnter(__func__);
	return SSL_CTX_new(meth);
}
SSL_CTX *
SSL_CTX_new(const SSL_METHOD *meth)
{
	SSL_CTX	*ret = NULL;

	if (meth == NULL) {
		SSLerr(SSL_F_SSL_CTX_NEW, SSL_R_NULL_SSL_METHOD_PASSED);
		return (NULL);
	}

	if (SSL_get_ex_data_X509_STORE_CTX_idx() < 0) {
		SSLerr(SSL_F_SSL_CTX_NEW,
		    SSL_R_X509_VERIFICATION_SETUP_PROBLEMS);
		goto err;
	}
	ret = calloc(1, sizeof(SSL_CTX));
	if (ret == NULL)
		goto err;

	ret->method = meth;

	ret->cert_store = NULL;
	ret->session_cache_mode = SSL_SESS_CACHE_SERVER;
	ret->session_cache_size = SSL_SESSION_CACHE_MAX_SIZE_DEFAULT;
	ret->session_cache_head = NULL;
	ret->session_cache_tail = NULL;

	/* We take the system default */
	ret->session_timeout = meth->get_timeout();

	ret->new_session_cb = 0;
	ret->remove_session_cb = 0;
	ret->get_session_cb = 0;
	ret->generate_session_id = 0;

	memset((char *)&ret->stats, 0, sizeof(ret->stats));

	ret->references = 1;
	ret->quiet_shutdown = 0;

	ret->info_callback = NULL;

	ret->app_verify_callback = 0;
	ret->app_verify_arg = NULL;

	ret->max_cert_list = SSL_MAX_CERT_LIST_DEFAULT;
	ret->read_ahead = 0;
	ret->msg_callback = 0;
	ret->msg_callback_arg = NULL;
	ret->verify_mode = SSL_VERIFY_NONE;
	ret->sid_ctx_length = 0;
	ret->default_verify_callback = NULL;
	if ((ret->cert = ssl_cert_new()) == NULL)
		goto err;

	ret->default_passwd_callback = 0;
	ret->default_passwd_callback_userdata = NULL;
	ret->client_cert_cb = 0;
	ret->app_gen_cookie_cb = 0;
	ret->app_verify_cookie_cb = 0;

	ret->sessions = lh_SSL_SESSION_new();
	if (ret->sessions == NULL)
		goto err;
	ret->cert_store = X509_STORE_new();
	if (ret->cert_store == NULL)
		goto err;

	ssl_create_cipher_list(ret->method, &ret->cipher_list,
	    &ret->cipher_list_by_id, SSL_DEFAULT_CIPHER_LIST);
	if (ret->cipher_list == NULL ||
	    sk_SSL_CIPHER_num(ret->cipher_list) <= 0) {
		SSLerr(SSL_F_SSL_CTX_NEW, SSL_R_LIBRARY_HAS_NO_CIPHERS);
		goto err2;
	}

	ret->param = X509_VERIFY_PARAM_new();
	if (!ret->param)
		goto err;

	if ((ret->md5 = EVP_get_digestbyname("ssl3-md5")) == NULL) {
		SSLerr(SSL_F_SSL_CTX_NEW,
		    SSL_R_UNABLE_TO_LOAD_SSL3_MD5_ROUTINES);
		goto err2;
	}
	if ((ret->sha1 = EVP_get_digestbyname("ssl3-sha1")) == NULL) {
		SSLerr(SSL_F_SSL_CTX_NEW,
		    SSL_R_UNABLE_TO_LOAD_SSL3_SHA1_ROUTINES);
		goto err2;
	}

	if ((ret->client_CA = sk_X509_NAME_new_null()) == NULL)
		goto err;

	CRYPTO_new_ex_data(CRYPTO_EX_INDEX_SSL_CTX, ret, &ret->ex_data);

	ret->extra_certs = NULL;

	ret->max_send_fragment = SSL3_RT_MAX_PLAIN_LENGTH;

	ret->tlsext_servername_callback = 0;
	ret->tlsext_servername_arg = NULL;

	/* Setup RFC4507 ticket keys */
	arc4random_buf(ret->tlsext_tick_key_name, 16);
	arc4random_buf(ret->tlsext_tick_hmac_key, 16);
	arc4random_buf(ret->tlsext_tick_aes_key, 16);

	ret->tlsext_status_cb = 0;
	ret->tlsext_status_arg = NULL;

	ret->next_protos_advertised_cb = 0;
	ret->next_proto_select_cb = 0;
#ifndef OPENSSL_NO_ENGINE
	ret->client_cert_engine = NULL;
#ifdef OPENSSL_SSL_CLIENT_ENGINE_AUTO
#define eng_strx(x)	#x
#define eng_str(x)	eng_strx(x)
	/* Use specific client engine automatically... ignore errors */
	{
		ENGINE *eng;
		eng = ENGINE_by_id(eng_str(OPENSSL_SSL_CLIENT_ENGINE_AUTO));
		if (!eng) {
			ERR_clear_error();
			ENGINE_load_builtin_engines();
			eng = ENGINE_by_id(eng_str(
			    OPENSSL_SSL_CLIENT_ENGINE_AUTO));
		}
		if (!eng || !SSL_CTX_set_client_cert_engine(ret, eng))
			ERR_clear_error();
	}
#endif
#endif
	/*
	 * Default is to connect to non-RI servers. When RI is more widely
	 * deployed might change this.
	 */
	ret->options |= SSL_OP_LEGACY_SERVER_CONNECT;

	return (ret);
err:
	SSLerr(SSL_F_SSL_CTX_NEW, ERR_R_MALLOC_FAILURE);
err2:
	SSL_CTX_free(ret);
	return (NULL);
}

void
ecall_SSL_CTX_free(SSL_CTX *a) {
    LogEnter(__func__);
	SSL_CTX_free(a);
}
void
SSL_CTX_free(SSL_CTX *a)
{
	int	i;

	if (a == NULL)
		return;

	i = CRYPTO_add(&a->references, -1, CRYPTO_LOCK_SSL_CTX);
	if (i > 0)
		return;

	if (a->param)
		X509_VERIFY_PARAM_free(a->param);

	/*
	 * Free internal session cache. However: the remove_cb() may reference
	 * the ex_data of SSL_CTX, thus the ex_data store can only be removed
	 * after the sessions were flushed.
	 * As the ex_data handling routines might also touch the session cache,
	 * the most secure solution seems to be: empty (flush) the cache, then
	 * free ex_data, then finally free the cache.
	 * (See ticket [openssl.org #212].)
	 */
	if (a->sessions != NULL)
		SSL_CTX_flush_sessions(a, 0);

	CRYPTO_free_ex_data(CRYPTO_EX_INDEX_SSL_CTX, a, &a->ex_data);

	if (a->sessions != NULL)
		lh_SSL_SESSION_free(a->sessions);

	if (a->cert_store != NULL)
		X509_STORE_free(a->cert_store);
	if (a->cipher_list != NULL)
		sk_SSL_CIPHER_free(a->cipher_list);
	if (a->cipher_list_by_id != NULL)
		sk_SSL_CIPHER_free(a->cipher_list_by_id);
	if (a->cert != NULL)
		ssl_cert_free(a->cert);
	if (a->client_CA != NULL)
		sk_X509_NAME_pop_free(a->client_CA, X509_NAME_free);
	if (a->extra_certs != NULL)
		sk_X509_pop_free(a->extra_certs, X509_free);

#ifndef OPENSSL_NO_SRTP
	if (a->srtp_profiles)
		sk_SRTP_PROTECTION_PROFILE_free(a->srtp_profiles);
#endif

#ifndef OPENSSL_NO_ENGINE
	if (a->client_cert_engine)
		ENGINE_finish(a->client_cert_engine);
#endif

	free(a->alpn_client_proto_list);

	free(a);
}

#ifdef COMPILE_WITH_INTEL_SGX
static void* default_passwd_callback_ocall = 0;

int pem_password_cb_for_ocall(char *buf, int size, int rwflag, void *userdata) {
	if (default_passwd_callback_ocall) {
		int retval;
		ocall_pem_password_cb(&retval, buf, size, rwflag, userdata, default_passwd_callback_ocall);
		return retval;
	} else {
		return -1;
	}
}

void ecall_SSL_CTX_set_default_passwd_cb(SSL_CTX *ctx, void *cb) {
    LogEnter(__func__);
	default_passwd_callback_ocall = cb;
	SSL_CTX_set_default_passwd_cb(ctx, pem_password_cb_for_ocall);
}
#else
void ecall_SSL_CTX_set_default_passwd_cb(SSL_CTX *ctx, void *cb) {
    LogEnter(__func__);
	SSL_CTX_set_default_passwd_cb(ctx, (pem_password_cb*)cb);
}
#endif

void
SSL_CTX_set_default_passwd_cb(SSL_CTX *ctx, pem_password_cb *cb)
{
	ctx->default_passwd_callback = cb;
}

void
SSL_CTX_set_default_passwd_cb_userdata(SSL_CTX *ctx, void *u)
{
	ctx->default_passwd_callback_userdata = u;
}

#ifdef COMPILE_WITH_INTEL_SGX
int (*ssl_ctx_set_cert_verify_cb_address)(X509_STORE_CTX *, void *) = NULL;
int ssl_ctx_set_cert_verify_fake_cb(X509_STORE_CTX * ctx, void *arg) {
	if (ssl_ctx_set_cert_verify_cb_address) {
		my_fprintf(0, "need to call ssl_ctx_set_cert_verify_cb_address\n");
	}
	return 0;
}
#endif

void ecall_SSL_CTX_set_cert_verify_callback(SSL_CTX *ctx, void* cb, void *arg) {
    LogEnter(__func__);
#ifdef COMPILE_WITH_INTEL_SGX
	ssl_ctx_set_cert_verify_cb_address = (int(*)(X509_STORE_CTX *, void *))cb;
	int (*callback)(X509_STORE_CTX *, void *) = ssl_ctx_set_cert_verify_fake_cb;
#else
	int (*callback)(X509_STORE_CTX *, void *) = (int(*)(X509_STORE_CTX *, void *))cb;
#endif
	SSL_CTX_set_cert_verify_callback(ctx, callback, arg);
}

void
SSL_CTX_set_cert_verify_callback(SSL_CTX *ctx, int (*cb)(X509_STORE_CTX *,
    void *), void *arg)
{
	ctx->app_verify_callback = cb;
	ctx->app_verify_arg = arg;
}

#ifdef COMPILE_WITH_INTEL_SGX
int (*ssl_ctx_set_verify_callback_address)(int, X509_STORE_CTX *) = NULL;
int ssl_ctx_set_verify_fake_callback(int mode, X509_STORE_CTX *ctx) {
	if (ssl_ctx_set_verify_callback_address) {
		//TODO: make ocall
		my_fprintf(0, "need to call callback ssl_ctx_set_verify_callback_address\n");
	}
	return 0;
}
#endif

void ecall_SSL_CTX_set_verify(SSL_CTX *ctx, int mode, void* callback) {
    LogEnter(__func__);
	int (*cb)(int, X509_STORE_CTX *);
#ifdef COMPILE_WITH_INTEL_SGX
	ssl_ctx_set_verify_callback_address = (int (*)(int, X509_STORE_CTX *))callback;
	cb = ssl_ctx_set_verify_fake_callback;
#else
	cb = (int (*)(int, X509_STORE_CTX *))callback;
#endif
	SSL_CTX_set_verify(ctx, mode, cb);
}

void
SSL_CTX_set_verify(SSL_CTX *ctx, int mode, int (*cb)(int, X509_STORE_CTX *))
{
	ctx->verify_mode = mode;
	ctx->default_verify_callback = cb;
}

void
ecall_SSL_CTX_set_verify_depth(SSL_CTX *ctx, int depth) {
    LogEnter(__func__);
	SSL_CTX_set_verify_depth(ctx, depth);
}
void
SSL_CTX_set_verify_depth(SSL_CTX *ctx, int depth)
{
	X509_VERIFY_PARAM_set_depth(ctx->param, depth);
}

void
ssl_set_cert_masks(CERT *c, const SSL_CIPHER *cipher)
{
	CERT_PKEY	*cpk;
	int		 rsa_enc, rsa_sign, dh_tmp, dsa_sign;
	unsigned long	 mask_k, mask_a;
	int		 have_ecc_cert, ecdh_ok, ecdsa_ok;
	int		 have_ecdh_tmp;
	X509		*x = NULL;
	EVP_PKEY	*ecc_pkey = NULL;
	int		 signature_nid = 0, pk_nid = 0, md_nid = 0;

	if (c == NULL)
		return;

	dh_tmp = (c->dh_tmp != NULL || c->dh_tmp_cb != NULL ||
	    c->dh_tmp_auto != 0);

	have_ecdh_tmp = (c->ecdh_tmp != NULL || c->ecdh_tmp_cb != NULL ||
	    c->ecdh_tmp_auto != 0);
	cpk = &(c->pkeys[SSL_PKEY_RSA_ENC]);
	rsa_enc = (cpk->x509 != NULL && cpk->privatekey != NULL);
	cpk = &(c->pkeys[SSL_PKEY_RSA_SIGN]);
	rsa_sign = (cpk->x509 != NULL && cpk->privatekey != NULL);
	cpk = &(c->pkeys[SSL_PKEY_DSA_SIGN]);
	dsa_sign = (cpk->x509 != NULL && cpk->privatekey != NULL);
/* FIX THIS EAY EAY EAY */
	cpk = &(c->pkeys[SSL_PKEY_ECC]);
	have_ecc_cert = (cpk->x509 != NULL && cpk->privatekey != NULL);
	mask_k = 0;
	mask_a = 0;

	cpk = &(c->pkeys[SSL_PKEY_GOST01]);
	if (cpk->x509 != NULL && cpk->privatekey !=NULL) {
		mask_k |= SSL_kGOST;
		mask_a |= SSL_aGOST01;
	}

	if (rsa_enc)
		mask_k|=SSL_kRSA;

	if (dh_tmp)
		mask_k|=SSL_kDHE;

	if (rsa_enc || rsa_sign)
		mask_a|=SSL_aRSA;

	if (dsa_sign)
		mask_a|=SSL_aDSS;

	mask_a|=SSL_aNULL;

	/*
	 * An ECC certificate may be usable for ECDH and/or
	 * ECDSA cipher suites depending on the key usage extension.
	 */
	if (have_ecc_cert) {
		/* This call populates extension flags (ex_flags) */
		x = (c->pkeys[SSL_PKEY_ECC]).x509;
		X509_check_purpose(x, -1, 0);
		ecdh_ok = (x->ex_flags & EXFLAG_KUSAGE) ?
		(x->ex_kusage & X509v3_KU_KEY_AGREEMENT) : 1;
		ecdsa_ok = (x->ex_flags & EXFLAG_KUSAGE) ?
		(x->ex_kusage & X509v3_KU_DIGITAL_SIGNATURE) : 1;
		ecc_pkey = X509_get_pubkey(x);
		EVP_PKEY_free(ecc_pkey);
		if ((x->sig_alg) && (x->sig_alg->algorithm)) {
			signature_nid = OBJ_obj2nid(x->sig_alg->algorithm);
			OBJ_find_sigid_algs(signature_nid, &md_nid, &pk_nid);
		}
		if (ecdh_ok) {
			if (pk_nid == NID_rsaEncryption || pk_nid == NID_rsa) {
				mask_k|=SSL_kECDHr;
				mask_a|=SSL_aECDH;
			}
			if (pk_nid == NID_X9_62_id_ecPublicKey) {
				mask_k|=SSL_kECDHe;
				mask_a|=SSL_aECDH;
			}
		}
		if (ecdsa_ok)
			mask_a|=SSL_aECDSA;
	}

	if (have_ecdh_tmp) {
		mask_k|=SSL_kECDHE;
	}


	c->mask_k = mask_k;
	c->mask_a = mask_a;
	c->valid = 1;
}

/* This handy macro borrowed from crypto/x509v3/v3_purp.c */
#define ku_reject(x, usage) \
	(((x)->ex_flags & EXFLAG_KUSAGE) && !((x)->ex_kusage & (usage)))


int
ssl_check_srvr_ecc_cert_and_alg(X509 *x, SSL *s)
{
	unsigned long		 alg_k, alg_a;
	int			 signature_nid = 0, md_nid = 0, pk_nid = 0;
	const SSL_CIPHER	*cs = s->s3->tmp.new_cipher;

	alg_k = cs->algorithm_mkey;
	alg_a = cs->algorithm_auth;

	/* This call populates the ex_flags field correctly */
	X509_check_purpose(x, -1, 0);
	if ((x->sig_alg) && (x->sig_alg->algorithm)) {
		signature_nid = OBJ_obj2nid(x->sig_alg->algorithm);
		OBJ_find_sigid_algs(signature_nid, &md_nid, &pk_nid);
	}
	if (alg_k & SSL_kECDHe || alg_k & SSL_kECDHr) {
		/* key usage, if present, must allow key agreement */
		if (ku_reject(x, X509v3_KU_KEY_AGREEMENT)) {
			SSLerr(SSL_F_SSL_CHECK_SRVR_ECC_CERT_AND_ALG,
			    SSL_R_ECC_CERT_NOT_FOR_KEY_AGREEMENT);
			return (0);
		}
		if ((alg_k & SSL_kECDHe) && TLS1_get_version(s) <
		    TLS1_2_VERSION) {
			/* signature alg must be ECDSA */
			if (pk_nid != NID_X9_62_id_ecPublicKey) {
				SSLerr(SSL_F_SSL_CHECK_SRVR_ECC_CERT_AND_ALG,
				    SSL_R_ECC_CERT_SHOULD_HAVE_SHA1_SIGNATURE);
				return (0);
			}
		}
		if ((alg_k & SSL_kECDHr) && TLS1_get_version(s) <
		    TLS1_2_VERSION) {
			/* signature alg must be RSA */
			if (pk_nid != NID_rsaEncryption && pk_nid != NID_rsa) {
				SSLerr(SSL_F_SSL_CHECK_SRVR_ECC_CERT_AND_ALG,
				    SSL_R_ECC_CERT_SHOULD_HAVE_RSA_SIGNATURE);
				return (0);
			}
		}
	}
	if (alg_a & SSL_aECDSA) {
		/* key usage, if present, must allow signing */
		if (ku_reject(x, X509v3_KU_DIGITAL_SIGNATURE)) {
			SSLerr(SSL_F_SSL_CHECK_SRVR_ECC_CERT_AND_ALG,
			    SSL_R_ECC_CERT_NOT_FOR_SIGNING);
			return (0);
		}
	}

	return (1);
	/* all checks are ok */
}


/* THIS NEEDS CLEANING UP */
CERT_PKEY *
ssl_get_server_send_pkey(const SSL *s)
{
	unsigned long	 alg_k, alg_a;
	CERT		*c;
	int		 i;

	c = s->cert;
	ssl_set_cert_masks(c, s->s3->tmp.new_cipher);

	alg_k = s->s3->tmp.new_cipher->algorithm_mkey;
	alg_a = s->s3->tmp.new_cipher->algorithm_auth;

	if (alg_k & (SSL_kECDHr|SSL_kECDHe)) {
		/*
		 * We don't need to look at SSL_kECDHE
		 * since no certificate is needed for
		 * anon ECDH and for authenticated
		 * ECDHE, the check for the auth
		 * algorithm will set i correctly
		 * NOTE: For ECDH-RSA, we need an ECC
		 * not an RSA cert but for EECDH-RSA
		 * we need an RSA cert. Placing the
		 * checks for SSL_kECDH before RSA
		 * checks ensures the correct cert is chosen.
		 */
		i = SSL_PKEY_ECC;
	} else if (alg_a & SSL_aECDSA) {
		i = SSL_PKEY_ECC;
	} else if (alg_a & SSL_aDSS) {
		i = SSL_PKEY_DSA_SIGN;
	} else if (alg_a & SSL_aRSA) {
		if (c->pkeys[SSL_PKEY_RSA_ENC].x509 == NULL)
			i = SSL_PKEY_RSA_SIGN;
		else
			i = SSL_PKEY_RSA_ENC;
	} else if (alg_a & SSL_aGOST01) {
		i = SSL_PKEY_GOST01;
	} else { /* if (alg_a & SSL_aNULL) */
		SSLerr(SSL_F_SSL_GET_SERVER_SEND_PKEY, ERR_R_INTERNAL_ERROR);
		return (NULL);
	}

	return (c->pkeys + i);
}

X509 *
ssl_get_server_send_cert(const SSL *s)
{
	CERT_PKEY	*cpk;

	cpk = ssl_get_server_send_pkey(s);
	if (!cpk)
		return (NULL);
	return (cpk->x509);
}

EVP_PKEY *
ssl_get_sign_pkey(SSL *s, const SSL_CIPHER *cipher, const EVP_MD **pmd)
{
	unsigned long	 alg_a;
	CERT		*c;
	int		 idx = -1;

	alg_a = cipher->algorithm_auth;
	c = s->cert;

	if ((alg_a & SSL_aDSS) &&
	    (c->pkeys[SSL_PKEY_DSA_SIGN].privatekey != NULL))
		idx = SSL_PKEY_DSA_SIGN;
	else if (alg_a & SSL_aRSA) {
		if (c->pkeys[SSL_PKEY_RSA_SIGN].privatekey != NULL)
			idx = SSL_PKEY_RSA_SIGN;
		else if (c->pkeys[SSL_PKEY_RSA_ENC].privatekey != NULL)
			idx = SSL_PKEY_RSA_ENC;
	} else if ((alg_a & SSL_aECDSA) &&
	    (c->pkeys[SSL_PKEY_ECC].privatekey != NULL))
		idx = SSL_PKEY_ECC;
	if (idx == -1) {
		SSLerr(SSL_F_SSL_GET_SIGN_PKEY, ERR_R_INTERNAL_ERROR);
		return (NULL);
	}
	if (pmd)
		*pmd = c->pkeys[idx].digest;
	return (c->pkeys[idx].privatekey);
}

DH *
ssl_get_auto_dh(SSL *s)
{
	CERT_PKEY *cpk;
	int keylen;
	DH *dhp;

	if (s->cert->dh_tmp_auto == 2) {
		keylen = 1024;
	} else if (s->s3->tmp.new_cipher->algorithm_auth & SSL_aNULL) {
		keylen = 1024;
		if (s->s3->tmp.new_cipher->strength_bits == 256)
			keylen = 3072;
	} else {
		if ((cpk = ssl_get_server_send_pkey(s)) == NULL)
			return (NULL);
		if (cpk->privatekey == NULL || cpk->privatekey->pkey.dh == NULL)
			return (NULL);
		keylen = EVP_PKEY_bits(cpk->privatekey);
	}

	if ((dhp = DH_new()) == NULL)
		return (NULL);

	dhp->g = BN_new();
	if (dhp->g != NULL)
		BN_set_word(dhp->g, 2);

	if (keylen >= 8192)
		dhp->p = get_rfc3526_prime_8192(NULL);
	else if (keylen >= 4096)
		dhp->p = get_rfc3526_prime_4096(NULL);
	else if (keylen >= 3072)
		dhp->p = get_rfc3526_prime_3072(NULL);
	else if (keylen >= 2048)
		dhp->p = get_rfc3526_prime_2048(NULL);
	else if (keylen >= 1536)
		dhp->p = get_rfc3526_prime_1536(NULL);
	else
		dhp->p = get_rfc2409_prime_1024(NULL);

	if (dhp->p == NULL || dhp->g == NULL) {
		DH_free(dhp);
		return (NULL);
	}
	return (dhp);
}

#ifdef COMPILE_WITH_INTEL_SGX
	static SSL_SESSION* ssl_session_outside = NULL;
#endif

static int ocall_new_session_callback_wrapper(struct ssl_st *ssl) {
	int retval;

#ifdef COMPILE_WITH_INTEL_SGX
	if (!ssl_session_outside) {
		ocall_malloc((void**)&ssl_session_outside, sizeof(*ssl_session_outside));
	}
	//ssl_session_outside is a copy of the ssl session, so squid can access the session_id and session_id_length fields
	memcpy(ssl_session_outside, ssl->session, sizeof(*ssl_session_outside));

	sgx_status_t ret;
	if (sgx_is_within_enclave(ssl, sizeof(*ssl))) {
		hashmap* m = get_ssl_hardening();
		SSL* out_s = (SSL*) hashmapGet(m, (unsigned long)ssl);
		SSL_copy_fields_to_out_struct(ssl, out_s);
		ret = ocall_new_session_callback(&retval, out_s, (void*)ssl_session_outside, (void*)ssl->session_ctx->new_session_cb);
		SSL_copy_fields_to_in_struct(ssl, out_s);
	} else {
		ret = ocall_new_session_callback(&retval, ssl, (void*)ssl_session_outside, (void*)ssl->session_ctx->new_session_cb);
	}

	if (ret != SGX_SUCCESS) {
		my_printf("Error in callback %s: %d\n", __func__, ret);
		retval = 0;
	}
#else
	retval = ssl->session_ctx->new_session_cb(ssl, ssl->session);
#endif

	return retval;
}

void
ssl_update_cache(SSL *s, int mode)
{
	int	i;

	/*
	 * If the session_id_length is 0, we are not supposed to cache it,
	 * and it would be rather hard to do anyway :-)
	 */
	if (s->session->session_id_length == 0)
		return;

	i = s->session_ctx->session_cache_mode;
	if ((i & mode) && (!s->hit) && ((i & SSL_SESS_CACHE_NO_INTERNAL_STORE)
	    || SSL_CTX_add_session(s->session_ctx, s->session))
	    && (s->session_ctx->new_session_cb != NULL)) {
		CRYPTO_add(&s->session->references, 1, CRYPTO_LOCK_SSL_SESSION);
		//my_printf("%s:%i (%s) gonna call new_session_cb @ %p\n", __FILE__, __LINE__, __func__, (void*)s->session_ctx->new_session_cb);
		int retval = ocall_new_session_callback_wrapper(s);
		if (!retval)
			SSL_SESSION_free(s->session);
	}

	/* auto flush every 255 connections */
	if ((!(i & SSL_SESS_CACHE_NO_AUTO_CLEAR)) &&
	    ((i & mode) == mode)) {
		if ((((mode & SSL_SESS_CACHE_CLIENT) ?
		    s->session_ctx->stats.sess_connect_good :
		    s->session_ctx->stats.sess_accept_good) & 0xff) == 0xff) {
			SSL_CTX_flush_sessions(s->session_ctx, time(NULL));
		}
	}
}

const SSL_METHOD *
SSL_get_ssl_method(SSL *s)
{
	return (s->method);
}

int
SSL_set_ssl_method(SSL *s, const SSL_METHOD *meth)
{
	int	conn = -1;
	int	ret = 1;

	if (s->method != meth) {
		if (s->handshake_func != NULL)
			conn = (s->handshake_func == s->method->ssl_connect);

		if (s->method->version == meth->version)
			s->method = meth;
		else {
			s->method->ssl_free(s);
			s->method = meth;
			ret = s->method->ssl_new(s);
		}

		if (conn == 1)
			s->handshake_func = meth->ssl_connect;
		else if (conn == 0)
			s->handshake_func = meth->ssl_accept;
	}
	return (ret);
}

int
ecall_SSL_get_error(const SSL *s, int i) {
    LogEnter(__func__);
#ifdef COMPILE_WITH_INTEL_SGX
	const SSL* out_s = s;

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	s = in_s;
#endif
	return SSL_get_error(s, i);
}
int
SSL_get_error(const SSL *s, int i)
{
	int		 reason;
	unsigned long	 l;
	BIO		*bio;

	if (i > 0)
		return (SSL_ERROR_NONE);

	/* Make things return SSL_ERROR_SYSCALL when doing SSL_do_handshake
	 * etc, where we do encode the error */
	if ((l = ERR_peek_error()) != 0) {
		if (ERR_GET_LIB(l) == ERR_LIB_SYS)
			return (SSL_ERROR_SYSCALL);
		else
			return (SSL_ERROR_SSL);
	}

	if ((i < 0) && SSL_want_read(s)) {
		bio = SSL_get_rbio(s);
		if (BIO_should_read(bio)) {
			return (SSL_ERROR_WANT_READ);
		} else if (BIO_should_write(bio)) {
			/*
			 * This one doesn't make too much sense...  We never
			 * try to write to the rbio, and an application
			 * program where rbio and wbio are separate couldn't
			 * even know what it should wait for.  However if we
			 * ever set s->rwstate incorrectly (so that we have
			 * SSL_want_read(s) instead of SSL_want_write(s))
			 * and rbio and wbio *are* the same, this test works
			 * around that bug; so it might be safer to keep it.
			 */
			return (SSL_ERROR_WANT_WRITE);
		} else if (BIO_should_io_special(bio)) {
			reason = BIO_get_retry_reason(bio);
			if (reason == BIO_RR_CONNECT)
				return (SSL_ERROR_WANT_CONNECT);
			else if (reason == BIO_RR_ACCEPT)
				return (SSL_ERROR_WANT_ACCEPT);
			else
				return (SSL_ERROR_SYSCALL); /* unknown */
		}
	}

	if ((i < 0) && SSL_want_write(s)) {
		bio = SSL_get_wbio(s);
		if (BIO_should_write(bio)) {
			return (SSL_ERROR_WANT_WRITE);
		} else if (BIO_should_read(bio)) {
			/*
			 * See above (SSL_want_read(s) with
			 * BIO_should_write(bio))
			 */
			return (SSL_ERROR_WANT_READ);
		} else if (BIO_should_io_special(bio)) {
			reason = BIO_get_retry_reason(bio);
			if (reason == BIO_RR_CONNECT)
				return (SSL_ERROR_WANT_CONNECT);
			else if (reason == BIO_RR_ACCEPT)
				return (SSL_ERROR_WANT_ACCEPT);
			else
				return (SSL_ERROR_SYSCALL);
		}
	}
	if ((i < 0) && SSL_want_x509_lookup(s)) {
		return (SSL_ERROR_WANT_X509_LOOKUP);
	}

	if (i == 0) {
		if ((s->shutdown & SSL_RECEIVED_SHUTDOWN) &&
		    (s->s3->warn_alert == SSL_AD_CLOSE_NOTIFY))
		return (SSL_ERROR_ZERO_RETURN);
	}
	return (SSL_ERROR_SYSCALL);
}

int
ecall_SSL_do_handshake(SSL *s) {
    LogEnter(__func__);
#ifdef COMPILE_WITH_INTEL_SGX
	const SSL* out_s = s;

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	s = in_s;
#endif
	return SSL_do_handshake(s);
}
int
SSL_do_handshake(SSL *s)
{
	int	ret = 1;

	if (s->handshake_func == NULL) {
		SSLerr(SSL_F_SSL_DO_HANDSHAKE, SSL_R_CONNECTION_TYPE_NOT_SET);
		return (-1);
	}

	s->method->ssl_renegotiate_check(s);

	if (SSL_in_init(s) || SSL_in_before(s)) {
		ret = s->handshake_func(s);
	}
	return (ret);
}

/*
 * For the next 2 functions, SSL_clear() sets shutdown and so
 * one of these calls will reset it
 */
void
ecall_SSL_set_accept_state(SSL *s)
{
    LogEnter(__func__);
#ifdef COMPILE_WITH_INTEL_SGX
	const SSL* out_s = s;

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	s = in_s;
#endif
	SSL_set_accept_state(s);
}
void
SSL_set_accept_state(SSL *s)
{
	s->server = 1;
	s->shutdown = 0;
	s->state = SSL_ST_ACCEPT|SSL_ST_BEFORE;
	s->handshake_func = s->method->ssl_accept;
	/* clear the current cipher */
	ssl_clear_cipher_ctx(s);
	ssl_clear_hash_ctx(&s->read_hash);
	ssl_clear_hash_ctx(&s->write_hash);
}

void
ecall_SSL_set_connect_state(SSL *s) {
    LogEnter(__func__);
#ifdef COMPILE_WITH_INTEL_SGX
	const SSL* out_s = s;

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	s = in_s;
#endif
	SSL_set_connect_state(s);
}
void
SSL_set_connect_state(SSL *s)
{
	s->server = 0;
	s->shutdown = 0;
	s->state = SSL_ST_CONNECT|SSL_ST_BEFORE;
	s->handshake_func = s->method->ssl_connect;
	/* clear the current cipher */
	ssl_clear_cipher_ctx(s);
	ssl_clear_hash_ctx(&s->read_hash);
	ssl_clear_hash_ctx(&s->write_hash);
}

int
ssl_undefined_function(SSL *s)
{
	SSLerr(SSL_F_SSL_UNDEFINED_FUNCTION,
	    ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
	return (0);
}

int
ssl_undefined_void_function(void)
{
	SSLerr(SSL_F_SSL_UNDEFINED_VOID_FUNCTION,
	    ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
	return (0);
}

int
ssl_undefined_const_function(const SSL *s)
{
	SSLerr(SSL_F_SSL_UNDEFINED_CONST_FUNCTION,
	    ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
	return (0);
}

const char *
ssl_version_string(int ver)
{
	switch (ver) {
	case DTLS1_VERSION:
		return (SSL_TXT_DTLS1);
	case TLS1_VERSION:
		return (SSL_TXT_TLSV1);
	case TLS1_1_VERSION:
		return (SSL_TXT_TLSV1_1);
	case TLS1_2_VERSION:
		return (SSL_TXT_TLSV1_2);
	default:
		return ("unknown");
	}
}

int
ecall_SSL_get_version_as_int(const SSL *s)
{
    LogEnter(__func__);
	return s->version;
}
const char *
SSL_get_version(const SSL *s)
{
	return ssl_version_string(s->version);
}

uint16_t
ssl_max_server_version(SSL *s)
{
	uint16_t max_version;

	/*
	 * The SSL method will be changed during version negotiation, as such
	 * we want to use the SSL method from the context.
	 */
	max_version = s->ctx->method->version;

	if (SSL_IS_DTLS(s))
		return (DTLS1_VERSION);

	if ((s->options & SSL_OP_NO_TLSv1_2) == 0 &&
	    max_version >= TLS1_2_VERSION)
		return (TLS1_2_VERSION);
	if ((s->options & SSL_OP_NO_TLSv1_1) == 0 &&
	    max_version >= TLS1_1_VERSION)
		return (TLS1_1_VERSION);
	if ((s->options & SSL_OP_NO_TLSv1) == 0 &&
	    max_version >= TLS1_VERSION)
		return (TLS1_VERSION);

	return (0);
}

#ifdef COMPILE_WITH_INTEL_SGX
void (*SSL_set_info_cb_addr)(const SSL *ssl, int type, int val) = NULL;
void SSL_set_info_fake_callback(const SSL* ssl, int type, int val) {
	if (!SSL_set_info_cb_addr) {
		my_printf("%s:%s;%i Need to implement SSL_set_info callback\n", __FILE__, __LINE__, __func__);
		//TODO
	} else {
		my_printf("%s:%s;%i SSL_set_info_callback not called but fake callback called!\n", __FILE__, __LINE__, __func__);

	}
}
#endif

void ecall_SSL_set_info_callback(SSL *ssl, void* cb) {
    LogEnter(__func__);
#ifdef COMPILE_WITH_INTEL_SGX
	SSL* in_s = ssl;

	hashmap* m = get_ssl_hardening();
	SSL* out_s = (SSL*) hashmapGet(m, (unsigned long)in_s);

	SSL_copy_fields_to_out_struct(in_s, out_s);
	SSL_set_info_cb_addr = (void (*)(const SSL*, int, int))cb;
	SSL_set_info_callback(ssl, &SSL_set_info_fake_callback);
	SSL_copy_fields_to_in_struct(in_s, out_s);
#else
	SSL_set_info_callback(ssl, cb);
#endif
}
void
SSL_set_info_callback(SSL *ssl, void (*cb)(const SSL *ssl, int type, int val))
{
	ssl->info_callback = cb;
}

void (*SSL_get_info_callback(const SSL *ssl))(const SSL *ssl, int type, int val)
{
	return (ssl->info_callback);
}

SSL *
SSL_dup(SSL *s)
{
	STACK_OF(X509_NAME) *sk;
	X509_NAME *xn;
	SSL *ret;
	int i;

	if ((ret = SSL_new(SSL_get_SSL_CTX(s))) == NULL)
		return (NULL);

	ret->version = s->version;
	ret->type = s->type;
	ret->method = s->method;

	if (s->session != NULL) {
		/* This copies session-id, SSL_METHOD, sid_ctx, and 'cert' */
		SSL_copy_session_id(ret, s);
	} else {
		/*
		 * No session has been established yet, so we have to expect
		 * that s->cert or ret->cert will be changed later --
		 * they should not both point to the same object,
		 * and thus we can't use SSL_copy_session_id.
		 */

		ret->method->ssl_free(ret);
		ret->method = s->method;
		ret->method->ssl_new(ret);

		if (s->cert != NULL) {
			if (ret->cert != NULL) {
				ssl_cert_free(ret->cert);
			}
			ret->cert = ssl_cert_dup(s->cert);
			if (ret->cert == NULL)
				goto err;
		}

		SSL_set_session_id_context(ret,
		s->sid_ctx, s->sid_ctx_length);
	}

	ret->options = s->options;
	ret->mode = s->mode;
	SSL_set_max_cert_list(ret, SSL_get_max_cert_list(s));
	SSL_set_read_ahead(ret, SSL_get_read_ahead(s));
	ret->msg_callback = s->msg_callback;
	ret->msg_callback_arg = s->msg_callback_arg;
	SSL_set_verify(ret, SSL_get_verify_mode(s),
	SSL_get_verify_callback(s));
	SSL_set_verify_depth(ret, SSL_get_verify_depth(s));
	ret->generate_session_id = s->generate_session_id;

	SSL_set_info_callback(ret, SSL_get_info_callback(s));

	ret->debug = s->debug;

	/* copy app data, a little dangerous perhaps */
	if (!CRYPTO_dup_ex_data(CRYPTO_EX_INDEX_SSL,
	    &ret->ex_data, &s->ex_data))
		goto err;

	/* setup rbio, and wbio */
	if (s->rbio != NULL) {
		if (!BIO_dup_state(s->rbio,(char *)&ret->rbio))
			goto err;
	}
	if (s->wbio != NULL) {
		if (s->wbio != s->rbio) {
			if (!BIO_dup_state(s->wbio,(char *)&ret->wbio))
				goto err;
		} else
			ret->wbio = ret->rbio;
	}
	ret->rwstate = s->rwstate;
	ret->in_handshake = s->in_handshake;
	ret->handshake_func = s->handshake_func;
	ret->server = s->server;
	ret->renegotiate = s->renegotiate;
	ret->new_session = s->new_session;
	ret->quiet_shutdown = s->quiet_shutdown;
	ret->shutdown = s->shutdown;
	/* SSL_dup does not really work at any state, though */
	ret->state=s->state;
	ret->rstate = s->rstate;

	/*
	 * Would have to copy ret->init_buf, ret->init_msg, ret->init_num,
	 * ret->init_off
	 */
	ret->init_num = 0;

	ret->hit = s->hit;

	X509_VERIFY_PARAM_inherit(ret->param, s->param);

	/* dup the cipher_list and cipher_list_by_id stacks */
	if (s->cipher_list != NULL) {
		if ((ret->cipher_list =
		    sk_SSL_CIPHER_dup(s->cipher_list)) == NULL)
			goto err;
	}
	if (s->cipher_list_by_id != NULL) {
		if ((ret->cipher_list_by_id =
		    sk_SSL_CIPHER_dup(s->cipher_list_by_id)) == NULL)
			goto err;
	}

	/* Dup the client_CA list */
	if (s->client_CA != NULL) {
		if ((sk = sk_X509_NAME_dup(s->client_CA)) == NULL) goto err;
			ret->client_CA = sk;
		for (i = 0; i < sk_X509_NAME_num(sk); i++) {
			xn = sk_X509_NAME_value(sk, i);
			if (sk_X509_NAME_set(sk, i,
			    X509_NAME_dup(xn)) == NULL) {
				X509_NAME_free(xn);
				goto err;
			}
		}
	}

	if (0) {
err:
		if (ret != NULL)
			SSL_free(ret);
		ret = NULL;
	}
	return (ret);
}

void
ssl_clear_cipher_ctx(SSL *s)
{
	EVP_CIPHER_CTX_free(s->enc_read_ctx);
	s->enc_read_ctx = NULL;
	EVP_CIPHER_CTX_free(s->enc_write_ctx);
	s->enc_write_ctx = NULL;

	if (s->aead_read_ctx != NULL) {
		EVP_AEAD_CTX_cleanup(&s->aead_read_ctx->ctx);
		free(s->aead_read_ctx);
		s->aead_read_ctx = NULL;
	}
	if (s->aead_write_ctx != NULL) {
		EVP_AEAD_CTX_cleanup(&s->aead_write_ctx->ctx);
		free(s->aead_write_ctx);
		s->aead_write_ctx = NULL;
	}

}

/* Fix this function so that it takes an optional type parameter */
X509 *
ecall_SSL_get_certificate(const SSL *s) {
    LogEnter(__func__);
#ifdef COMPILE_WITH_INTEL_SGX
	const SSL* out_s = s;

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	return SSL_get_certificate(in_s);
#else
	return SSL_get_certificate(s);
#endif
}
X509 *
SSL_get_certificate(const SSL *s)
{
	if (s->cert != NULL)
		return (s->cert->key->x509);
	else
		return (NULL);
}

/* Fix this function so that it takes an optional type parameter */
void
ecall_SSL_get_privatekey(EVP_PKEY* pkey, SSL *s) {
    LogEnter(__func__);
#ifdef COMPILE_WITH_INTEL_SGX
	const SSL* out_s = s;

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	EVP_PKEY* enclave_pkey = SSL_get_privatekey(in_s);
	memcpy(pkey, enclave_pkey, sizeof(*pkey));
#else
	printf("Cannot call %s without SGX!!!\n", __func__);
#endif
}

EVP_PKEY *
SSL_get_privatekey(SSL *s)
{
	if (s->cert != NULL)
		return (s->cert->key->privatekey);
	else
		return (NULL);
}

SSL_CIPHER *
ecall_SSL_get_current_cipher(const SSL *s)
{
    LogEnter(__func__);
	return (SSL_CIPHER*)SSL_get_current_cipher(s);
}
const SSL_CIPHER *
SSL_get_current_cipher(const SSL *s)
{
	if ((s->session != NULL) && (s->session->cipher != NULL))
		return (s->session->cipher);
	return (NULL);
}
const void *
SSL_get_current_compression(SSL *s)
{
	return (NULL);
}

const void *
SSL_get_current_expansion(SSL *s)
{
	return (NULL);
}

int
ssl_init_wbio_buffer(SSL *s, int push)
{
	BIO	*bbio;

	if (s->bbio == NULL) {
		bbio = BIO_new(BIO_f_buffer());
		if (bbio == NULL)
			return (0);
		s->bbio = bbio;
	} else {
		bbio = s->bbio;
		if (s->bbio == s->wbio)
			s->wbio = BIO_pop(s->wbio);
	}
	(void)BIO_reset(bbio);
/*	if (!BIO_set_write_buffer_size(bbio,16*1024)) */
	if (!BIO_set_read_buffer_size(bbio, 1)) {
		SSLerr(SSL_F_SSL_INIT_WBIO_BUFFER, ERR_R_BUF_LIB);
		return (0);
	}
	if (push) {
		if (s->wbio != bbio)
			s->wbio = BIO_push(bbio, s->wbio);
	} else {
		if (s->wbio == bbio)
			s->wbio = BIO_pop(bbio);
	}
	return (1);
}

void
ssl_free_wbio_buffer(SSL *s)
{
	if (s == NULL)
		return;

	if (s->bbio == NULL)
		return;

	if (s->bbio == s->wbio) {
		/* remove buffering */
		s->wbio = BIO_pop(s->wbio);
	}
	BIO_free(s->bbio);
	s->bbio = NULL;
}

void
SSL_CTX_set_quiet_shutdown(SSL_CTX *ctx, int mode)
{
	ctx->quiet_shutdown = mode;
}

int
SSL_CTX_get_quiet_shutdown(const SSL_CTX *ctx)
{
	return (ctx->quiet_shutdown);
}

void
ecall_SSL_set_quiet_shutdown(SSL *s, int mode) {
    LogEnter(__func__);
	return SSL_set_quiet_shutdown(s, mode);
}
void
SSL_set_quiet_shutdown(SSL *s, int mode)
{
	s->quiet_shutdown = mode;
}

int
SSL_get_quiet_shutdown(const SSL *s)
{
	return (s->quiet_shutdown);
}

void
ecall_SSL_set_shutdown(SSL *s, int mode) {
    LogEnter(__func__);
#ifdef COMPILE_WITH_INTEL_SGX
	SSL* out_s = s;

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	SSL_copy_fields_to_in_struct(in_s, out_s);
	SSL_set_shutdown(in_s, mode);
	SSL_copy_fields_to_out_struct(in_s, out_s);
#else
	SSL_set_shutdown(s, mode);
#endif
}
void
SSL_set_shutdown(SSL *s, int mode)
{
	s->shutdown = mode;
}

int
ecall_SSL_get_shutdown(const SSL *s) {
    LogEnter(__func__);
#ifdef COMPILE_WITH_INTEL_SGX
	SSL* out_s = (SSL*)s;

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	SSL_copy_fields_to_in_struct(in_s, out_s);
	int ret = SSL_get_shutdown((const SSL*)in_s);
	SSL_copy_fields_to_out_struct(in_s, out_s);
	return ret;
#else
	return SSL_get_shutdown(s);
#endif
}
int
SSL_get_shutdown(const SSL *s)
{
	return (s->shutdown);
}

int
SSL_version(const SSL *s)
{
	return (s->version);
}

SSL_CTX *
ecall_SSL_get_SSL_CTX(const SSL *ssl)
{
    LogEnter(__func__);
#ifdef COMPILE_WITH_INTEL_SGX
	SSL* out_s = (SSL*)ssl;

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	SSL_copy_fields_to_in_struct(in_s, out_s);
	SSL_CTX* ret = SSL_get_SSL_CTX((const SSL*)in_s);
	SSL_copy_fields_to_out_struct(in_s, out_s);
	return ret;
#else
	return SSL_get_SSL_CTX(ssl);
#endif
}
SSL_CTX *
SSL_get_SSL_CTX(const SSL *ssl)
{
	return (ssl->ctx);
}

SSL_CTX *
ecall_SSL_set_SSL_CTX(SSL *ssl, SSL_CTX* ctx)
{
    LogEnter(__func__);
	return SSL_set_SSL_CTX(ssl, ctx);
}
SSL_CTX *
SSL_set_SSL_CTX(SSL *ssl, SSL_CTX* ctx)
{
	if (ssl->ctx == ctx)
		return (ssl->ctx);
	if (ctx == NULL)
		ctx = ssl->initial_ctx;
	if (ssl->cert != NULL)
		ssl_cert_free(ssl->cert);
	ssl->cert = ssl_cert_dup(ctx->cert);
	CRYPTO_add(&ctx->references, 1, CRYPTO_LOCK_SSL_CTX);
	SSL_CTX_free(ssl->ctx); /* decrement reference count */
	ssl->ctx = ctx;
	return (ssl->ctx);
}

int
ecall_SSL_CTX_set_default_verify_paths(SSL_CTX *ctx) {
    LogEnter(__func__);
	return SSL_CTX_set_default_verify_paths(ctx);
}
int
SSL_CTX_set_default_verify_paths(SSL_CTX *ctx)
{
	return (X509_STORE_set_default_paths(ctx->cert_store));
}

int
SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile,
    const char *CApath)
{
	return (X509_STORE_load_locations(ctx->cert_store, CAfile, CApath));
}

int
SSL_CTX_load_verify_mem(SSL_CTX *ctx, void *buf, int len)
{
	return (X509_STORE_load_mem(ctx->cert_store, buf, len));
}

int
ecall_SSL_state(const SSL *ssl)
{
    LogEnter(__func__);
#ifdef COMPILE_WITH_INTEL_SGX
	SSL* out_s = (SSL*)ssl;

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	SSL_copy_fields_to_in_struct(in_s, (const SSL*)out_s);
	int ret = SSL_state(in_s);
	SSL_copy_fields_to_out_struct((const SSL*)in_s, out_s);
	return ret;
#else
	return SSL_state(ssl);
#endif
}
int
SSL_state(const SSL *ssl)
{
	return (ssl->state);
}

void
SSL_set_state(SSL *ssl, int state)
{
	ssl->state = state;
}

void
ecall_SSL_set_verify_result(SSL *ssl, long arg)
{
    LogEnter(__func__);
#ifdef COMPILE_WITH_INTEL_SGX
	SSL* out_s = ssl;

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	SSL_copy_fields_to_in_struct(in_s, out_s);
	SSL_set_verify_result(in_s, arg);
	SSL_copy_fields_to_out_struct(in_s, out_s);
#else
	SSL_set_verify_result(ssl, arg);
#endif
}
void
SSL_set_verify_result(SSL *ssl, long arg)
{
	ssl->verify_result = arg;
}

long
ecall_SSL_get_verify_result(const SSL *ssl)
{
    LogEnter(__func__);
#ifdef COMPILE_WITH_INTEL_SGX
	SSL* out_s = (SSL*)ssl;

	hashmap* m = get_ssl_hardening();
	SSL* in_s = (SSL*) hashmapGet(m, (unsigned long)out_s);

	SSL_copy_fields_to_in_struct(in_s, out_s);
	long ret = SSL_get_verify_result((const SSL*)in_s);
	SSL_copy_fields_to_out_struct(in_s, out_s);
	return ret;
#else
	return SSL_get_verify_result(ssl);
#endif
}
long
SSL_get_verify_result(const SSL *ssl)
{
	return (ssl->verify_result);
}

#ifdef COMPILE_WITH_INTEL_SGX
CRYPTO_EX_new *crypto_ex_new_cb_address = NULL;
int fake_crypto_ex_new_cb(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp) {
	if (crypto_ex_new_cb_address != NULL) {
		//make the ocall with callback at crypto_ex_new_cb_address
		//TODO
		my_fprintf(0, "need to call callback crypto_ex_new_cb_address\n");
	}
	return -1;
}

CRYPTO_EX_dup *crypto_ex_dup_cb_address = NULL;
int fake_crypto_ex_dup_cb(CRYPTO_EX_DATA *to, CRYPTO_EX_DATA *from, void *from_d, int idx, long argl, void *argp) {
	if (crypto_ex_dup_cb_address != NULL) {
		//make the ocall with callback at crypto_ex_dup_cb_address
		//TODO
		my_fprintf(0, "need to call callback crypto_ex_dup_cb_address\n");
	}
	return -1;
}

CRYPTO_EX_free *crypto_ex_free_cb_address = NULL;
void fake_crypto_ex_free_cb(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp) {
	if (crypto_ex_free_cb_address != NULL) {
		crypto_ex_free_cb_wrapper(parent, ptr, ad, idx, argl, argp, crypto_ex_free_cb_address);
	}
}
#endif

int
ecall_SSL_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
    CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func) {
    LogEnter(__func__);
#ifdef COMPILE_WITH_INTEL_SGX
	crypto_ex_new_cb_address = new_func;
	new_func = fake_crypto_ex_new_cb;
	crypto_ex_dup_cb_address = dup_func;
	dup_func = fake_crypto_ex_dup_cb;
	crypto_ex_free_cb_address = free_func;
	free_func = fake_crypto_ex_free_cb;
#endif
	return SSL_get_ex_new_index(argl, argp, new_func, dup_func, free_func);
}
int
SSL_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
    CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func)
{
	return (CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_SSL, argl, argp,
	    new_func, dup_func, free_func));
}

int
SSL_set_ex_data(SSL *s, int idx, void *arg)
{
	return (CRYPTO_set_ex_data(&s->ex_data, idx, arg));
}

void *
SSL_get_ex_data(const SSL *s, int idx)
{
	return (CRYPTO_get_ex_data(&s->ex_data, idx));
}

int
ecall_SSL_CTX_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
    CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func) {
    LogEnter(__func__);
	return SSL_CTX_get_ex_new_index(argl, argp, new_func, dup_func, free_func);
}
int
SSL_CTX_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
    CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func)
{
	return (CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_SSL_CTX, argl, argp,
	    new_func, dup_func, free_func));
}

int
ecall_SSL_CTX_set_ex_data(SSL_CTX *s, int idx, void *arg) {
    LogEnter(__func__);
	return SSL_CTX_set_ex_data(s, idx, arg);
}
int
SSL_CTX_set_ex_data(SSL_CTX *s, int idx, void *arg)
{
	return (CRYPTO_set_ex_data(&s->ex_data, idx, arg));
}

void *
ecall_SSL_CTX_get_ex_data(const SSL_CTX *s, int idx) {
    LogEnter(__func__);
	return SSL_CTX_get_ex_data(s, idx);
}
void *
SSL_CTX_get_ex_data(const SSL_CTX *s, int idx)
{
	return (CRYPTO_get_ex_data(&s->ex_data, idx));
}

int
ssl_ok(SSL *s)
{
	return (1);
}

X509_STORE *
ecall_SSL_CTX_get_cert_store(const SSL_CTX *ctx) {
    LogEnter(__func__);
	return SSL_CTX_get_cert_store(ctx);
}
X509_STORE *
SSL_CTX_get_cert_store(const SSL_CTX *ctx)
{
	return (ctx->cert_store);
}

void
SSL_CTX_set_cert_store(SSL_CTX *ctx, X509_STORE *store)
{
	if (ctx->cert_store != NULL)
		X509_STORE_free(ctx->cert_store);
	ctx->cert_store = store;
}

int
SSL_want(const SSL *s)
{
	return (s->rwstate);
}

#ifdef COMPILE_WITH_INTEL_SGX
SSL_SESSION* ocall_get_session_cb_trampoline(SSL* ssl, unsigned char* data, int len, int* copy, void* cb) {
	SSL_SESSION* ret;
	SSL* in_s = ssl;

	hashmap* m = get_ssl_hardening();
	SSL* out_s = (SSL*) hashmapGet(m, (unsigned long)in_s);

	SSL_copy_fields_to_out_struct(in_s, out_s);
	ocall_get_session_cb((void*)&ret, out_s, data, len, copy, cb);
	SSL_copy_fields_to_in_struct(in_s, out_s);

	return ret;
}
#endif

#ifdef COMPILE_WITH_INTEL_SGX
RSA *(*ssl_ctx_set_tmp_rsa_callback_address)(SSL *ssl, int is_export, int keylength) = NULL;
RSA *ssl_ctx_set_tmp_rsa_fake_callback(SSL *ssl, int is_export, int keylength) {
	if (ssl_ctx_set_tmp_rsa_callback_address) {
		//TODO: make ocall
		my_fprintf(0, "need to call callback ssl_ctx_set_tmp_rsa_callback_address\n");
	}
	return NULL;
}
#endif

void ecall_SSL_CTX_set_tmp_rsa_callback(SSL_CTX *ctx, void* cb) {
    LogEnter(__func__);
#ifdef COMPILE_WITH_INTEL_SGX
	ssl_ctx_set_tmp_rsa_callback_address = (RSA *(*)(SSL *ssl, int is_export, int keylength))cb;
	cb = ssl_ctx_set_tmp_rsa_fake_callback;
#endif
	SSL_CTX_set_tmp_rsa_callback(ctx, cb);
}
void
SSL_CTX_set_tmp_rsa_callback(SSL_CTX *ctx, RSA *(*cb)(SSL *ssl, int is_export,
    int keylength))
{
	SSL_CTX_callback_ctrl(ctx, SSL_CTRL_SET_TMP_RSA_CB,(void (*)(void))cb);
}

void
SSL_set_tmp_rsa_callback(SSL *ssl, RSA *(*cb)(SSL *ssl, int is_export,
    int keylength))
{
	SSL_callback_ctrl(ssl, SSL_CTRL_SET_TMP_RSA_CB,(void (*)(void))cb);
}

#ifdef COMPILE_WITH_INTEL_SGX
DH* (*SSL_CTX_set_tmp_dh_cb_address)(SSL *, int, int) = NULL;
DH* SSL_CTX_set_tmp_dh_fake_cb(SSL *ssl, int is_export, int keylength) {
	DH* retval = NULL;

	if (SSL_CTX_set_tmp_dh_cb_address) {
		SSL* in_s = ssl;

		hashmap* m = get_ssl_hardening();
		SSL* out_s = (SSL*) hashmapGet(m, (unsigned long)in_s);

		SSL_copy_fields_to_out_struct(in_s, out_s);
		retval = ocall_SSL_CTX_set_tmp_dh_cb_wrapper(out_s, is_export, keylength, (void*)SSL_CTX_set_tmp_dh_cb_address);
		SSL_copy_fields_to_in_struct(in_s, out_s);
	}

	return retval;
}
#endif

void
ecall_SSL_CTX_set_tmp_dh_callback(SSL_CTX *ctx, void* func)
{
    LogEnter(__func__);
	DH* (*cb)(SSL *, int, int);
#ifdef COMPILE_WITH_INTEL_SGX
	SSL_CTX_set_tmp_dh_cb_address = (DH* (*)(SSL *, int, int))func;
	cb = SSL_CTX_set_tmp_dh_fake_cb;
#else
	cb = (DH* (*)(SSL *, int, int))func;
#endif
	SSL_CTX_set_tmp_dh_callback(ctx, cb);
}

void
SSL_CTX_set_tmp_dh_callback(SSL_CTX *ctx, DH *(*dh)(SSL *ssl, int is_export,
    int keylength))
{
	SSL_CTX_callback_ctrl(ctx, SSL_CTRL_SET_TMP_DH_CB,(void (*)(void))dh);
}

void
SSL_set_tmp_dh_callback(SSL *ssl, DH *(*dh)(SSL *ssl, int is_export,
    int keylength))
{
	SSL_callback_ctrl(ssl, SSL_CTRL_SET_TMP_DH_CB,(void (*)(void))dh);
}

void
SSL_CTX_set_tmp_ecdh_callback(SSL_CTX *ctx, EC_KEY *(*ecdh)(SSL *ssl,
    int is_export, int keylength))
{
	SSL_CTX_callback_ctrl(ctx, SSL_CTRL_SET_TMP_ECDH_CB,
	    (void (*)(void))ecdh);
}

void
SSL_set_tmp_ecdh_callback(SSL *ssl, EC_KEY *(*ecdh)(SSL *ssl, int is_export,
    int keylength))
{
	SSL_callback_ctrl(ssl, SSL_CTRL_SET_TMP_ECDH_CB,(void (*)(void))ecdh);
}


void
SSL_CTX_set_msg_callback(SSL_CTX *ctx, void (*cb)(int write_p, int version,
    int content_type, const void *buf, size_t len, SSL *ssl, void *arg))
{
	SSL_CTX_callback_ctrl(ctx, SSL_CTRL_SET_MSG_CALLBACK,
	    (void (*)(void))cb);
}

void
SSL_set_msg_callback(SSL *ssl, void (*cb)(int write_p, int version,
    int content_type, const void *buf, size_t len, SSL *ssl, void *arg))
{
	SSL_callback_ctrl(ssl, SSL_CTRL_SET_MSG_CALLBACK, (void (*)(void))cb);
}

void
ssl_clear_hash_ctx(EVP_MD_CTX **hash)
{
	if (*hash)
		EVP_MD_CTX_destroy(*hash);
	*hash = NULL;
}

void
SSL_set_debug(SSL *s, int debug)
{
	s->debug = debug;
}

int
SSL_cache_hit(SSL *s)
{
	return (s->hit);
}

IMPLEMENT_OBJ_BSEARCH_GLOBAL_CMP_FN(SSL_CIPHER, SSL_CIPHER, ssl_cipher_id);
