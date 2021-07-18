// SPDX-License-Identifier: GPL-2.0
/* GPL HEADER START
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
 * version 2 along with this program; If not, see http://www.gnu.org/licenses
 *
 * Please  visit http://www.xyratex.com/contact if you need additional
 * information or have any questions.
 *
 * GPL HEADER END
 */

/*
 * Copyright 2012 Xyratex Technology Limited
 */

#ifndef _LIBCFS_CRYPTO_H
#define _LIBCFS_CRYPTO_H

#include <linux/string.h>
struct page;

struct cfs_crypto_hash_type {
	char		*cht_name;	/*< hash algorithm name, equal to
					 * format name for crypto api
					 */
	unsigned int	cht_key;	/*< init key by default (valid for
					 * 4 bytes context like crc32, adler
					 */
	unsigned int	cht_size;	/**< hash digest size */
};

enum cfs_crypto_hash_alg {
	CFS_HASH_ALG_NULL	= 0,
	CFS_HASH_ALG_ADLER32,
	CFS_HASH_ALG_CRC32,
	CFS_HASH_ALG_CRC32C,
	/* hashes before here will be speed-tested at module load */
	CFS_HASH_ALG_MD5,
	CFS_HASH_ALG_SHA1,
	CFS_HASH_ALG_SHA256,
	CFS_HASH_ALG_SHA384,
	CFS_HASH_ALG_SHA512,
	CFS_HASH_ALG_MAX,
	CFS_HASH_ALG_SPEED_MAX	= CFS_HASH_ALG_MD5,
	CFS_HASH_ALG_UNKNOWN	= 0xff
};

static struct cfs_crypto_hash_type hash_types[] = {
	[CFS_HASH_ALG_NULL] = {
		.cht_name	= "null",
		.cht_key	= 0,
		.cht_size	= 0
	},
	[CFS_HASH_ALG_ADLER32] = {
		.cht_name	= "adler32",
		.cht_key	= 1,
		.cht_size	= 4
	},
	[CFS_HASH_ALG_CRC32] = {
		.cht_name	= "crc32",
		.cht_key	= ~0,
		.cht_size	= 4
	},
	[CFS_HASH_ALG_CRC32C] = {
		.cht_name	= "crc32c",
		.cht_key	= ~0,
		.cht_size	= 4
	},
	[CFS_HASH_ALG_MD5] = {
		.cht_name	= "md5",
		.cht_key	= 0,
		.cht_size	= 16
	},
	[CFS_HASH_ALG_SHA1] = {
		.cht_name	= "sha1",
		.cht_key	= 0,
		.cht_size	= 20
	},
	[CFS_HASH_ALG_SHA256] = {
		.cht_name	= "sha256",
		.cht_key	= 0,
		.cht_size	= 32
	},
	[CFS_HASH_ALG_SHA384] = {
		.cht_name	= "sha384",
		.cht_key	= 0,
		.cht_size	= 48
	},
	[CFS_HASH_ALG_SHA512] = {
		.cht_name	= "sha512",
		.cht_key	= 0,
		.cht_size	= 64
	},
	[CFS_HASH_ALG_MAX] = {
		.cht_name	= NULL,
		.cht_key	= 0,
		.cht_size	= 64
	},
};

/* Maximum size of hash_types[].cht_size */
#define CFS_CRYPTO_HASH_DIGESTSIZE_MAX	64

/**
 * Return hash algorithm information for the specified algorithm identifier
 *
 * Hash information includes algorithm name, initial seed, hash size.
 *
 * Return:	cfs_crypto_hash_type for valid ID (CFS_HASH_ALG_*)
 *		NULL for unknown algorithm identifier
 */
static inline const struct cfs_crypto_hash_type *
cfs_crypto_hash_type(enum cfs_crypto_hash_alg hash_alg)
{
	struct cfs_crypto_hash_type *ht;

	if (hash_alg < CFS_HASH_ALG_MAX) {
		ht = &hash_types[hash_alg];
		if (ht->cht_name)
			return ht;
	}
	return NULL;
}

/*  Array of hash algorithm speed in MByte per second */
extern int cfs_crypto_hash_speeds[CFS_HASH_ALG_MAX];

/**
 * Return hash name for hash algorithm identifier
 *
 * @hash_alg	hash alrgorithm id (CFS_HASH_ALG_*)
 *
 * Return:	string name of known hash algorithm
 *		"unknown" if hash algorithm is unknown
 */
static inline const char *
cfs_crypto_hash_name(enum cfs_crypto_hash_alg hash_alg)
{
	const struct cfs_crypto_hash_type *ht;

	ht = cfs_crypto_hash_type(hash_alg);
	if (ht)
		return ht->cht_name;
	return "unknown";
}

/**
 * Return digest size for hash algorithm type
 *
 * @hash_alg	hash alrgorithm id (CFS_HASH_ALG_*)
 *
 * Return:	hash algorithm digest size in bytes
 *		0 if hash algorithm type is unknown
 */
static inline int cfs_crypto_hash_digestsize(enum cfs_crypto_hash_alg hash_alg)
{
	const struct cfs_crypto_hash_type *ht;

	ht = cfs_crypto_hash_type(hash_alg);
	if (ht)
		return ht->cht_size;
	return 0;
}

/**
 * Find hash algorithm ID for the specified algorithm name
 *
 * Return:	hash algorithm ID for valid ID (CFS_HASH_ALG_*)
 *		CFS_HASH_ALG_UNKNOWN for unknown algorithm name
 */
static inline unsigned char cfs_crypto_hash_alg(const char *algname)
{
	enum cfs_crypto_hash_alg hash_alg;

	for (hash_alg = 0; hash_alg < CFS_HASH_ALG_MAX; hash_alg++)
		if (!strcmp(hash_types[hash_alg].cht_name, algname))
			return hash_alg;

	return CFS_HASH_ALG_UNKNOWN;
}

int cfs_crypto_hash_digest(enum cfs_crypto_hash_alg hash_alg,
			   const void *buf, unsigned int buf_len,
			   unsigned char *key, unsigned int key_len,
			   unsigned char *hash, unsigned int *hash_len);

struct ahash_request *
cfs_crypto_hash_init(enum cfs_crypto_hash_alg hash_alg,
		     unsigned char *key, unsigned int key_len);
int cfs_crypto_hash_update_page(struct ahash_request *desc,
				struct page *page, unsigned int offset,
				unsigned int len);
int cfs_crypto_hash_update(struct ahash_request *desc, const void *buf,
			   unsigned int buf_len);
int cfs_crypto_hash_final(struct ahash_request *desc,
			  unsigned char *hash, unsigned int *hash_len);
int cfs_crypto_register(void);
void cfs_crypto_unregister(void);
int cfs_crypto_hash_speed(enum cfs_crypto_hash_alg hash_alg);
#endif
