/* $OpenBSD: buf_str.c,v 1.8 2014/04/26 13:07:16 jsing Exp $ */
/*
 * Copyright (c) 2014 Bob Beck
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/buffer.h>
#include <openssl/err.h>

/*
 * XXX these functions accept a NULL arg and return NULL
 * when the standard ones do not. we should at an appropriate
 * time change these to find the bad callers
 */

#ifdef COMPILE_WITH_INTEL_SGX
extern char *my_strdup(const char *s);
extern char *my_strndup(const char *s, size_t n);
#else
#define my_strdup(s) strdup(s)
#define my_strndup(s, n) strndup(s, n)
#endif

char *
BUF_strdup(const char *str)
{
	char *ret = NULL;

	if (str != NULL) {
		if (!(ret = my_strdup(str)))
			BUFerr(BUF_F_BUF_STRDUP, ERR_R_MALLOC_FAILURE);
	}
	return ret;
}

char *
BUF_strndup(const char *str, size_t siz)
{
	char *ret = NULL;

	if (str != NULL) {
		if (!(ret = my_strndup(str, siz)))
			BUFerr(BUF_F_BUF_STRNDUP, ERR_R_MALLOC_FAILURE);
	}
	return ret;
}

void *
BUF_memdup(const void *data, size_t siz)
{
	void *ret = NULL;

	if (data != NULL) {
		if (!(ret = malloc(siz)))
			BUFerr(BUF_F_BUF_MEMDUP, ERR_R_MALLOC_FAILURE);
		else
			(void) memcpy(ret, data, siz);
	}
	return ret;
}

size_t
BUF_strlcpy(char *dst, const char *src, size_t size)
{
	return strlcpy(dst, src, size);
}

size_t
BUF_strlcat(char *dst, const char *src, size_t size)
{
	return strlcat(dst, src, size);
}
