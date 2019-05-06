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
 * Copyright (c) 2013, 2014, Intel Corporation.
 * Use is subject to license terms.
 *
 * Author: Di Wang <di.wang@intel.com>
 */

#include <uapi/linux/lustre/lustre_idl.h>
#include <obd.h>
#include <lustre_linkea.h>

int linkea_data_new(struct linkea_data *ldata, struct lu_buf *buf)
{
	buf->lb_buf = kzalloc(PAGE_SIZE, GFP_NOFS);
	if (!buf->lb_buf)
		return -ENOMEM;
	buf->lb_len = PAGE_SIZE;
	ldata->ld_buf = buf;
	ldata->ld_leh = ldata->ld_buf->lb_buf;
	ldata->ld_leh->leh_magic = LINK_EA_MAGIC;
	ldata->ld_leh->leh_len = sizeof(struct link_ea_header);
	ldata->ld_leh->leh_reccount = 0;
	ldata->ld_leh->leh_overflow_time = 0;
	ldata->ld_leh->leh_padding = 0;
	return 0;
}
EXPORT_SYMBOL(linkea_data_new);

static int linkea_init(struct linkea_data *ldata)
{
	struct link_ea_header *leh;

	LASSERT(ldata->ld_buf);
	leh = ldata->ld_buf->lb_buf;
	if (leh->leh_magic == __swab32(LINK_EA_MAGIC)) {
		leh->leh_magic = LINK_EA_MAGIC;
		leh->leh_reccount = __swab32(leh->leh_reccount);
		leh->leh_len = __swab64(leh->leh_len);
		leh->leh_overflow_time = __swab32(leh->leh_overflow_time);
		leh->leh_padding = __swab32(leh->leh_padding);
		/* individual entries are swabbed by linkea_entry_unpack() */
	}

	if (leh->leh_magic != LINK_EA_MAGIC)
		return -EINVAL;

	if (leh->leh_reccount == 0 && leh->leh_overflow_time == 0)
		return -ENODATA;

	ldata->ld_leh = leh;
	return 0;
}

int linkea_init_with_rec(struct linkea_data *ldata)
{
	int rc;

	rc = linkea_init(ldata);
	if (!rc && ldata->ld_leh->leh_reccount == 0)
		rc = -ENODATA;

	return rc;
}
EXPORT_SYMBOL(linkea_init_with_rec);

void linkea_entry_unpack(const struct link_ea_entry *lee, int *reclen,
			 struct lu_name *lname, struct lu_fid *pfid)
{
	LASSERT(lee);

	*reclen = (lee->lee_reclen[0] << 8) | lee->lee_reclen[1];
	memcpy(pfid, &lee->lee_parent_fid, sizeof(*pfid));
	fid_be_to_cpu(pfid, pfid);
	if (lname) {
		lname->ln_name = lee->lee_name;
		lname->ln_namelen = *reclen - sizeof(struct link_ea_entry);
	}
}
EXPORT_SYMBOL(linkea_entry_unpack);
