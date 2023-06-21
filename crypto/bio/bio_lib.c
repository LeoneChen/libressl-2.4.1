#if defined(__cplusplus)
extern "C"{
#endif
void SGXSanLogEnter(const char *str);
#if defined(__cplusplus)
}
#endif
#define LogEnter SGXSanLogEnter
/* $OpenBSD: bio_lib.c,v 1.21 2014/07/25 06:05:32 doug Exp $ */
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

#include <errno.h>
#include <stdio.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/stack.h>

#include "tls_processing_interface.h"

#ifdef COMPILE_WITH_INTEL_SGX
#include "sgx_error.h"
#include "sgx_thread.h"
#include "sgx_trts.h"
#include "sgx_spinlock.h"
#include "hashmap.h"
#include "enclaveshim_ocalls.h"

extern sgx_status_t ocall_malloc(void** retval, size_t size);
sgx_status_t ocall_bio_create(int* retval, BIO* b, void* cb);
#endif

#ifdef COMPILE_WITH_INTEL_SGX

struct bio_methods_sgx_cb {
	BIO_METHOD* real_methods;
	BIO_METHOD* fake_methods;
};

static int bio_methods_initialized = 0;
static hashmap* bio_methods_map = NULL;
sgx_spinlock_t bio_methods_map_lock = SGX_SPINLOCK_INITIALIZER;

hashmap* get_bio_methods_map() {
	int expected = 0;
	int desired = 1;
	if (__atomic_compare_exchange_n(&bio_methods_initialized, &expected, desired, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
		bio_methods_map = hashmapCreate(23);
	}
	while (!bio_methods_map) {
		// burn cycles
	}

	hashmap* m = (hashmap*)hashmapGet(bio_methods_map, (unsigned long)sgx_thread_self());
	if (!m) {
		m = hashmapCreate(251);
		sgx_spin_lock(&bio_methods_map_lock);
		//	need a lock on the insert, just to be safe. However each thread will acquire the lock only once during its execution
		hashmapInsert(bio_methods_map, (const void*)m, (unsigned long)sgx_thread_self());
		sgx_spin_unlock(&bio_methods_map_lock);
	}

	return m;
}

int bio_fake_bwrite(BIO *b, const char *buf, int len) {
	int retval = 0;

	hashmap* biomethods = get_bio_methods_map();
	struct bio_methods_sgx_cb* sgx_cb_methods = (struct bio_methods_sgx_cb*)hashmapGet(biomethods, (unsigned long)b);

	if (sgx_cb_methods) {
		retval = execute_async_bio_write(b, (char*)buf, len, (void*)sgx_cb_methods->real_methods->bwrite);
	} else {
		my_fprintf(0, "%s:%s:%i %lu No bio_methods_sgx_cb for bio %p\n", __FILE__, __func__, __LINE__, (unsigned long)sgx_thread_self(), b);
	}
	return retval;
}
int bio_fake_bread(BIO *b, char *buf, int len) {
	int retval = 0;

	hashmap* biomethods = get_bio_methods_map();
	struct bio_methods_sgx_cb* sgx_cb_methods = (struct bio_methods_sgx_cb*)hashmapGet(biomethods, (unsigned long)b);

	if (sgx_cb_methods) {
		retval = execute_async_bio_read(b, buf, len, (void*)sgx_cb_methods->real_methods->bread);
	} else {
		my_fprintf(0, "%s:%s:%i %lu No bio_methods_sgx_cb for bio %p\n", __FILE__, __func__, __LINE__, (unsigned long)sgx_thread_self(), b);
	}
	return retval;
}
int bio_fake_bputs(BIO *b, const char *buf) {
	my_fprintf(0, "need to call %s in %s:%i\n", __func__, __FILE__, __LINE__);
	return 0;
}
int bio_fake_bgets(BIO *b, char *buf, int len) {
	my_fprintf(0, "need to call %s in %s:%i\n", __func__, __FILE__, __LINE__);
	return 0;
}
long bio_fake_ctrl(BIO *b, int cmd, long argl, void *arg) {
	long retval = 0;

#ifdef COMPILE_OPTIMISATION_FOR_APACHE
	// optimisation: call the ctrl method only for important commands
	if (cmd != BIO_CTRL_FLUSH && cmd != BIO_CTRL_SET_CLOSE && cmd != BIO_CTRL_GET_CLOSE) {
		return 0;
	}
#endif

	hashmap* biomethods = get_bio_methods_map();
	struct bio_methods_sgx_cb* sgx_cb_methods = (struct bio_methods_sgx_cb*)hashmapGet(biomethods, (unsigned long)b);

	if (sgx_cb_methods) {
		retval = execute_async_bio_ctrl(b, cmd, argl, arg, (void*)sgx_cb_methods->real_methods->ctrl);
	} else {
		my_fprintf(0, "%s:%s:%i %lu No bio_methods_sgx_cb for bio %p\n", __FILE__, __func__, __LINE__, (unsigned long)sgx_thread_self(), b);
	}
	return retval;
}
int bio_fake_create(BIO *b) {
	int retval = 0;

	hashmap* biomethods = get_bio_methods_map();
	struct bio_methods_sgx_cb* sgx_cb_methods = (struct bio_methods_sgx_cb*)hashmapGet(biomethods, (unsigned long)b);

	if (sgx_cb_methods && sgx_cb_methods->real_methods->create) {
		sgx_status_t ret = ocall_bio_create(&retval, b, (void*)sgx_cb_methods->real_methods->create);
		if (ret != SGX_SUCCESS) {
			my_fprintf(0, "%s:%s:%i ret = %i\n", __FILE__, __func__, __LINE__, ret);
		}
	} else {
		my_fprintf(0, "%s:%s:%i %lu No bio_methods_sgx_cb for bio %p\n", __FILE__, __func__, __LINE__, (unsigned long)sgx_thread_self(), b);
	}
	return retval;
}
int bio_fake_destroy(BIO *b) {
	int retval = 0;

	hashmap* biomethods = get_bio_methods_map();
	struct bio_methods_sgx_cb* sgx_cb_methods = (struct bio_methods_sgx_cb*)hashmapGet(biomethods, (unsigned long)b);

	if (sgx_cb_methods && sgx_cb_methods->real_methods->destroy) {
		retval = execute_async_bio_destroy(b, (void*)sgx_cb_methods->real_methods->destroy);
	} else {
		my_fprintf(0, "%s:%s:%i %lu No bio_methods_sgx_cb for bio %p\n", __FILE__, __func__, __LINE__, (unsigned long)sgx_thread_self(), b);
	}
	return retval;
}
#endif

BIO *
ecall_BIO_new(BIO_METHOD *method, int* method_in_enclave) {
    LogEnter(__func__);
#ifdef COMPILE_WITH_INTEL_SGX
	if (sgx_is_within_enclave(method, sizeof(*method))) {
		*method_in_enclave = 1;
		return BIO_new(method);
	}
	*method_in_enclave = 0;

	BIO* ret = NULL;
	struct bio_methods_sgx_cb* sgx_cb_methods = NULL;
	if (method) {
		sgx_cb_methods = (struct bio_methods_sgx_cb*)malloc(sizeof(*sgx_cb_methods));
		sgx_cb_methods->real_methods = method;
		sgx_cb_methods->fake_methods = (BIO_METHOD*)malloc(sizeof(*sgx_cb_methods->fake_methods));
		sgx_cb_methods->fake_methods->type = method->type;
		sgx_cb_methods->fake_methods->name = method->name;
		sgx_cb_methods->fake_methods->bwrite = bio_fake_bwrite;
		sgx_cb_methods->fake_methods->bread = bio_fake_bread;
		sgx_cb_methods->fake_methods->bputs = bio_fake_bputs;
		sgx_cb_methods->fake_methods->bgets = bio_fake_bgets;
		sgx_cb_methods->fake_methods->ctrl = bio_fake_ctrl;
		sgx_cb_methods->fake_methods->create = bio_fake_create;
		sgx_cb_methods->fake_methods->destroy = bio_fake_destroy;
		sgx_cb_methods->fake_methods->callback_ctrl = NULL;
		method = sgx_cb_methods->fake_methods;
	}

	// we need to copy the BIO_new() method because it can call our bio_fake_create callback and at this point
	// we have not inserted anything in the map for that new BIO.

	// the BIO is allocated from the bio pool
	ret = execute_bio_ocall_malloc(sizeof(*ret));

	hashmap* biomethods = NULL;
	if (method) {
		biomethods = get_bio_methods_map();
		hashmapInsert(biomethods, (const void*)sgx_cb_methods, (unsigned long)ret);
	}

	if (!BIO_set_from_ecall(ret, method)) {
		if (method) {
			hashmapRemove(biomethods, (unsigned long)ret);
			free(sgx_cb_methods->fake_methods);
			free(sgx_cb_methods);
		}

		execute_bio_ocall_free(ret);
		ret = NULL;
	}

	return (ret);
#else
	*method_in_enclave = 0;
	return BIO_new(method);
#endif
}
BIO *
BIO_new(BIO_METHOD *method)
{
	BIO *ret = NULL;

#ifdef COMPILE_WITH_INTEL_SGX
	ret = (BIO*)execute_bio_ocall_malloc(sizeof(BIO)); // allocate the BIO outside of the enclave
#else
	ret = malloc(sizeof(BIO));
#endif
	if (ret == NULL) {
		BIOerr(BIO_F_BIO_NEW, ERR_R_MALLOC_FAILURE);
		return (NULL);
	}
	if (!BIO_set(ret, method)) {
#ifdef COMPILE_WITH_INTEL_SGX
		execute_bio_ocall_free(ret);
#else
		free(ret);
#endif
		ret = NULL;
	}
	return (ret);
}

int
BIO_set_from_ecall(BIO *bio, BIO_METHOD *method)
{
	bio->method = method;
	bio->callback = NULL;
	bio->cb_arg = NULL;
	bio->init = 0;
	bio->shutdown = 1;
	bio->flags = 0;
	bio->retry_reason = 0;
	bio->num = 0;
	bio->ptr = NULL;
	bio->prev_bio = NULL;
	bio->next_bio = NULL;
	bio->references = 1;
	bio->num_read = 0L;
	bio->num_write = 0L;
	CRYPTO_new_ex_data(CRYPTO_EX_INDEX_BIO, bio, &bio->ex_data);
	//do not call the create callback, we do that once we return from the ecall
	return (1);
}

int
BIO_set(BIO *bio, BIO_METHOD *method)
{
	bio->method = method;
	bio->callback = NULL;
	bio->cb_arg = NULL;
	bio->init = 0;
	bio->shutdown = 1;
	bio->flags = 0;
	bio->retry_reason = 0;
	bio->num = 0;
	bio->ptr = NULL;
	bio->prev_bio = NULL;
	bio->next_bio = NULL;
	bio->references = 1;
	bio->num_read = 0L;
	bio->num_write = 0L;
	CRYPTO_new_ex_data(CRYPTO_EX_INDEX_BIO, bio, &bio->ex_data);
	if (method->create != NULL)
		if (!method->create(bio)) {
			CRYPTO_free_ex_data(CRYPTO_EX_INDEX_BIO, bio,
			    &bio->ex_data);
			return (0);
		}
	return (1);
}

int ecall_BIO_free(BIO *a) {
    LogEnter(__func__);
	return BIO_free(a);
}

int
BIO_free(BIO *a)
{
	int i;

	if (a == NULL)
		return (0);

	i = CRYPTO_add(&a->references, -1, CRYPTO_LOCK_BIO);
	if (i > 0)
		return (1);
	if ((a->callback != NULL) &&
	    ((i = (int)a->callback(a, BIO_CB_FREE, NULL, 0, 0L, 1L)) <= 0))
		return (i);

	CRYPTO_free_ex_data(CRYPTO_EX_INDEX_BIO, a, &a->ex_data);

	if (a->method != NULL && a->method->destroy != NULL)
		a->method->destroy(a);

#ifdef COMPILE_WITH_INTEL_SGX
	hashmap* biomethods = get_bio_methods_map();
	struct bio_methods_sgx_cb* sgx_cb_methods = hashmapRemove(biomethods, (unsigned long)a);
	if (sgx_cb_methods) {
		free(sgx_cb_methods->fake_methods);
		free(sgx_cb_methods);
	}
#endif

#ifdef COMPILE_WITH_INTEL_SGX
	execute_bio_ocall_free(a);
#else
	free(a);
#endif
	return (1);
}

void
BIO_vfree(BIO *a)
{
	BIO_free(a);
}

void
BIO_clear_flags(BIO *b, int flags)
{
	b->flags &= ~flags;
}

int
BIO_test_flags(const BIO *b, int flags)
{
	return (b->flags & flags);
}

void
BIO_set_flags(BIO *b, int flags)
{
	b->flags |= flags;
}

long
(*BIO_get_callback(const BIO *b))(struct bio_st *, int, const char *, int,
    long, long)
{
	return b->callback;
}

void
BIO_set_callback(BIO *b, long (*cb)(struct bio_st *, int, const char *, int,
    long, long))
{
	b->callback = cb;
}

void
BIO_set_callback_arg(BIO *b, char *arg)
{
	b->cb_arg = arg;
}

char *
BIO_get_callback_arg(const BIO *b)
{
	return b->cb_arg;
}

const char *
BIO_method_name(const BIO *b)
{
	return b->method->name;
}

int
BIO_method_type(const BIO *b)
{
	return b->method->type;
}

int
BIO_read(BIO *b, void *out, int outl)
{
	int i;
	long (*cb)(BIO *, int, const char *, int, long, long);

	if ((b == NULL) || (b->method == NULL) || (b->method->bread == NULL)) {
		BIOerr(BIO_F_BIO_READ, BIO_R_UNSUPPORTED_METHOD);
		return (-2);
	}

	cb = b->callback;
	if ((cb != NULL) &&
	    ((i = (int)cb(b, BIO_CB_READ, out, outl, 0L, 1L)) <= 0))
		return (i);

	if (!b->init) {
		BIOerr(BIO_F_BIO_READ, BIO_R_UNINITIALIZED);
		return (-2);
	}

	i = b->method->bread(b, out, outl);

	if (i > 0)
		b->num_read += (unsigned long)i;

	if (cb != NULL)
		i = (int)cb(b, BIO_CB_READ|BIO_CB_RETURN, out, outl,
		    0L, (long)i);
	return (i);
}

int
BIO_write(BIO *b, const void *in, int inl)
{
	int i;
	long (*cb)(BIO *, int, const char *, int, long, long);

	if (b == NULL)
		return (0);

	cb = b->callback;
	if ((b->method == NULL) || (b->method->bwrite == NULL)) {
		BIOerr(BIO_F_BIO_WRITE, BIO_R_UNSUPPORTED_METHOD);
		return (-2);
	}

	if ((cb != NULL) &&
	    ((i = (int)cb(b, BIO_CB_WRITE, in, inl, 0L, 1L)) <= 0))
		return (i);

	if (!b->init) {
		BIOerr(BIO_F_BIO_WRITE, BIO_R_UNINITIALIZED);
		return (-2);
	}

	i = b->method->bwrite(b, in, inl);

	if (i > 0)
		b->num_write += (unsigned long)i;

	if (cb != NULL)
		i = (int)cb(b, BIO_CB_WRITE|BIO_CB_RETURN, in, inl,
		    0L, (long)i);
	return (i);
}

int
BIO_puts(BIO *b, const char *in)
{
	int i;
	long (*cb)(BIO *, int, const char *, int, long, long);

	if ((b == NULL) || (b->method == NULL) || (b->method->bputs == NULL)) {
		BIOerr(BIO_F_BIO_PUTS, BIO_R_UNSUPPORTED_METHOD);
		return (-2);
	}

	cb = b->callback;

	if ((cb != NULL) &&
	    ((i = (int)cb(b, BIO_CB_PUTS, in, 0, 0L, 1L)) <= 0))
		return (i);

	if (!b->init) {
		BIOerr(BIO_F_BIO_PUTS, BIO_R_UNINITIALIZED);
		return (-2);
	}

	i = b->method->bputs(b, in);

	if (i > 0)
		b->num_write += (unsigned long)i;

	if (cb != NULL)
		i = (int)cb(b, BIO_CB_PUTS|BIO_CB_RETURN, in, 0, 0L, (long)i);
	return (i);
}

int
BIO_gets(BIO *b, char *in, int inl)
{
	int i;
	long (*cb)(BIO *, int, const char *, int, long, long);

	if ((b == NULL) || (b->method == NULL) || (b->method->bgets == NULL)) {
		BIOerr(BIO_F_BIO_GETS, BIO_R_UNSUPPORTED_METHOD);
		return (-2);
	}

	cb = b->callback;

	if ((cb != NULL) &&
	    ((i = (int)cb(b, BIO_CB_GETS, in, inl, 0L, 1L)) <= 0))
		return (i);

	if (!b->init) {
		BIOerr(BIO_F_BIO_GETS, BIO_R_UNINITIALIZED);
		return (-2);
	}

	i = b->method->bgets(b, in, inl);

	if (cb != NULL)
		i = (int)cb(b, BIO_CB_GETS|BIO_CB_RETURN, in, inl, 0L, (long)i);
	return (i);
}

int
BIO_indent(BIO *b, int indent, int max)
{
	if (indent < 0)
		indent = 0;
	if (indent > max)
		indent = max;
	while (indent--)
		if (BIO_puts(b, " ") != 1)
			return 0;
	return 1;
}

long
ecall_BIO_int_ctrl(BIO *b, int cmd, long larg, int iarg)
{
    LogEnter(__func__);
	return BIO_int_ctrl(b, cmd, larg, iarg);
}

#ifdef COMPILE_WITH_INTEL_SGX
int* outside_iarg_int_ctrl = NULL;
#endif

long
BIO_int_ctrl(BIO *b, int cmd, long larg, int iarg)
{
	// in the case of Squid we need to check the type of the BIO
	// to log only the messages between the client and the proxy
	if (cmd == BIO_C_SET_FD) {
		tls_processing_set_ssl_type(b, larg);
	}
#ifdef COMPILE_WITH_INTEL_SGX
	// BIO_int_ctrl can make an ocall with a pointer to a copy of iarg, so we need memory outside of the enclave
	if (!outside_iarg_int_ctrl) {
		ocall_malloc((void**)&outside_iarg_int_ctrl, sizeof(*outside_iarg_int_ctrl));
	}
	*outside_iarg_int_ctrl = iarg;
	return BIO_ctrl(b, cmd, larg, (char *)outside_iarg_int_ctrl);
#else
	int i = iarg;
	return (BIO_ctrl(b, cmd, larg, (char *)&i));
#endif

}

char *
BIO_ptr_ctrl(BIO *b, int cmd, long larg)
{
	char *p = NULL;

	if (BIO_ctrl(b, cmd, larg, (char *)&p) <= 0)
		return (NULL);
	else
		return (p);
}

long
ecall_BIO_ctrl(BIO *b, int cmd, long larg, void *parg) {
    LogEnter(__func__);
	return BIO_ctrl(b, cmd, larg, parg);
}
long
BIO_ctrl(BIO *b, int cmd, long larg, void *parg)
{
	long ret;
	long (*cb)(BIO *, int, const char *, int, long, long);

	if (b == NULL)
		return (0);

	if ((b->method == NULL) || (b->method->ctrl == NULL)) {
		BIOerr(BIO_F_BIO_CTRL, BIO_R_UNSUPPORTED_METHOD);
		return (-2);
	}

	cb = b->callback;

	if ((cb != NULL) &&
	    ((ret = cb(b, BIO_CB_CTRL, parg, cmd, larg, 1L)) <= 0))
		return (ret);

	ret = b->method->ctrl(b, cmd, larg, parg);

	if (cb != NULL)
		ret = cb(b, BIO_CB_CTRL|BIO_CB_RETURN, parg, cmd, larg, ret);
	return (ret);
}

long
BIO_callback_ctrl(BIO *b, int cmd,
    void (*fp)(struct bio_st *, int, const char *, int, long, long))
{
	long ret;
	long (*cb)(BIO *, int, const char *, int, long, long);

	if (b == NULL)
		return (0);

	if ((b->method == NULL) || (b->method->callback_ctrl == NULL)) {
		BIOerr(BIO_F_BIO_CALLBACK_CTRL, BIO_R_UNSUPPORTED_METHOD);
		return (-2);
	}

	cb = b->callback;

	if ((cb != NULL) &&
	    ((ret = cb(b, BIO_CB_CTRL, (void *)&fp, cmd, 0, 1L)) <= 0))
		return (ret);

	ret = b->method->callback_ctrl(b, cmd, fp);

	if (cb != NULL)
		ret = cb(b, BIO_CB_CTRL|BIO_CB_RETURN, (void *)&fp, cmd, 0, ret);
	return (ret);
}

/* It is unfortunate to duplicate in functions what the BIO_(w)pending macros
 * do; but those macros have inappropriate return type, and for interfacing
 * from other programming languages, C macros aren't much of a help anyway. */
size_t
BIO_ctrl_pending(BIO *bio)
{
	return BIO_ctrl(bio, BIO_CTRL_PENDING, 0, NULL);
}

size_t
BIO_ctrl_wpending(BIO *bio)
{
	return BIO_ctrl(bio, BIO_CTRL_WPENDING, 0, NULL);
}


/* put the 'bio' on the end of b's list of operators */
BIO *
BIO_push(BIO *b, BIO *bio)
{
	BIO *lb;

	if (b == NULL)
		return (bio);
	lb = b;
	while (lb->next_bio != NULL)
		lb = lb->next_bio;
	lb->next_bio = bio;
	if (bio != NULL)
		bio->prev_bio = lb;
	/* called to do internal processing */
	BIO_ctrl(b, BIO_CTRL_PUSH, 0, lb);
	return (b);
}

/* Remove the first and return the rest */
BIO *
BIO_pop(BIO *b)
{
	BIO *ret;

	if (b == NULL)
		return (NULL);
	ret = b->next_bio;

	BIO_ctrl(b, BIO_CTRL_POP, 0, b);

	if (b->prev_bio != NULL)
		b->prev_bio->next_bio = b->next_bio;
	if (b->next_bio != NULL)
		b->next_bio->prev_bio = b->prev_bio;

	b->next_bio = NULL;
	b->prev_bio = NULL;
	return (ret);
}

BIO *
BIO_get_retry_BIO(BIO *bio, int *reason)
{
	BIO *b, *last;

	b = last = bio;
	for (;;) {
		if (!BIO_should_retry(b))
			break;
		last = b;
		b = b->next_bio;
		if (b == NULL)
			break;
	}
	if (reason != NULL)
		*reason = last->retry_reason;
	return (last);
}

int
BIO_get_retry_reason(BIO *bio)
{
	return (bio->retry_reason);
}

BIO *
BIO_find_type(BIO *bio, int type)
{
	int mt, mask;

	if (!bio)
		return NULL;
	mask = type & 0xff;
	do {
		if (bio->method != NULL) {
			mt = bio->method->type;
			if (!mask) {
				if (mt & type)
					return (bio);
			} else if (mt == type)
				return (bio);
		}
		bio = bio->next_bio;
	} while (bio != NULL);
	return (NULL);
}

BIO *
BIO_next(BIO *b)
{
	if (!b)
		return NULL;
	return b->next_bio;
}

void
BIO_free_all(BIO *bio)
{
	BIO *b;
	int ref;

	while (bio != NULL) {
		b = bio;
		ref = b->references;
		bio = bio->next_bio;
		BIO_free(b);
		/* Since ref count > 1, don't free anyone else. */
		if (ref > 1)
			break;
	}
}

BIO *
BIO_dup_chain(BIO *in)
{
	BIO *ret = NULL, *eoc = NULL, *bio, *new_bio;

	for (bio = in; bio != NULL; bio = bio->next_bio) {
		if ((new_bio = BIO_new(bio->method)) == NULL)
			goto err;
		new_bio->callback = bio->callback;
		new_bio->cb_arg = bio->cb_arg;
		new_bio->init = bio->init;
		new_bio->shutdown = bio->shutdown;
		new_bio->flags = bio->flags;

		/* This will let SSL_s_sock() work with stdin/stdout */
		new_bio->num = bio->num;

		if (!BIO_dup_state(bio, (char *)new_bio)) {
			BIO_free(new_bio);
			goto err;
		}

		/* copy app data */
		if (!CRYPTO_dup_ex_data(CRYPTO_EX_INDEX_BIO,
		    &new_bio->ex_data, &bio->ex_data))
			goto err;

		if (ret == NULL) {
			eoc = new_bio;
			ret = eoc;
		} else {
			BIO_push(eoc, new_bio);
			eoc = new_bio;
		}
	}
	return (ret);
err:
	BIO_free(ret);
	return (NULL);

}

void
BIO_copy_next_retry(BIO *b)
{
	BIO_set_flags(b, BIO_get_retry_flags(b->next_bio));
	b->retry_reason = b->next_bio->retry_reason;
}

int
BIO_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
    CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func)
{
	return CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_BIO, argl, argp,
	    new_func, dup_func, free_func);
}

int
BIO_set_ex_data(BIO *bio, int idx, void *data)
{
	return (CRYPTO_set_ex_data(&(bio->ex_data), idx, data));
}

void *
BIO_get_ex_data(BIO *bio, int idx)
{
	return (CRYPTO_get_ex_data(&(bio->ex_data), idx));
}

unsigned long
BIO_number_read(BIO *bio)
{
	if (bio)
		return bio->num_read;
	return 0;
}

unsigned long
BIO_number_written(BIO *bio)
{
	if (bio)
		return bio->num_write;
	return 0;
}
