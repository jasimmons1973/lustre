// SPDX-License-Identifier: GPL-2.0
/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2019, 2020, Whamcloud.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef _LUSTRE_CRYPTO_H_
#define _LUSTRE_CRYPTO_H_

#include <linux/fscrypt.h>

struct ll_sb_info;
#ifdef CONFIG_FS_ENCRYPTION
int ll_set_encflags(struct inode *inode, void *encctx, u32 encctxlen,
		    bool preload);
bool ll_sbi_has_test_dummy_encryption(struct ll_sb_info *sbi);
bool ll_sbi_has_encrypt(struct ll_sb_info *sbi);
void ll_sbi_set_encrypt(struct ll_sb_info *sbi, bool set);
#else
static inline int ll_set_encflags(struct inode *inode, void *encctx,
				  u32 encctxlen, bool preload)
{
	return 0;
}

static inline bool ll_sbi_has_test_dummy_encryption(struct ll_sb_info *sbi)
{
	return false;
}

static inline bool ll_sbi_has_encrypt(struct ll_sb_info *sbi)
{
	return false;
}

static inline void ll_sbi_set_encrypt(struct ll_sb_info *sbi, bool set) { }
#endif
/* sizeof(struct fscrypt_context_v2) = 40 */
#define LLCRYPT_ENC_CTX_SIZE 40

/* Encoding/decoding routines inspired from yEnc principles.
 * We just take care of a few critical characters:
 * NULL, LF, CR, /, DEL and =.
 * If such a char is found, it is replaced with '=' followed by
 * the char value + 64.
 * All other chars are left untouched.
 * Efficiency of this encoding depends on the occurences of the
 * critical chars, but statistically on binary data it can be much higher
 * than base64 for instance.
 */
static inline int critical_encode(const u8 *src, int len, char *dst)
{
	u8 *p = (u8 *)src, *q = dst;

	while (p - src < len) {
		/* escape NULL, LF, CR, /, DEL and = */
		if (unlikely(*p == 0x0 || *p == 0xA || *p == 0xD ||
			     *p == '/' || *p == 0x7F || *p == '=')) {
			*(q++) = '=';
			*(q++) = *(p++) + 64;
		} else {
			*(q++) = *(p++);
		}
	}

	return (char *)q - dst;
}

/* returns the number of chars encoding would produce */
static inline int critical_chars(const u8 *src, int len)
{
	u8 *p = (u8 *)src;
	int newlen = len;

	while (p - src < len) {
		/* NULL, LF, CR, /, DEL and = cost an additional '=' */
		if (unlikely(*p == 0x0 || *p == 0xA || *p == 0xD ||
			     *p == '/' || *p == 0x7F || *p == '='))
			newlen++;
		p++;
	}

	return newlen;
}

/* decoding routine - returns the number of chars in output */
static inline int critical_decode(const u8 *src, int len, char *dst)
{
	u8 *p = (u8 *)src, *q = dst;

	while (p - src < len) {
		if (unlikely(*p == '=')) {
			*(q++) = *(++p) - 64;
			p++;
		} else {
			*(q++) = *(p++);
		}
	}

	return (char *)q - dst;
}

/* Extracts the second-to-last ciphertext block */
#define LLCRYPT_FNAME_DIGEST(name, len)					\
	((name) + round_down((len) - FS_CRYPTO_BLOCK_SIZE - 1,		\
			     FS_CRYPTO_BLOCK_SIZE))
#define LLCRYPT_FNAME_DIGEST_SIZE	FS_CRYPTO_BLOCK_SIZE

#endif /* _LUSTRE_CRYPTO_H_ */
