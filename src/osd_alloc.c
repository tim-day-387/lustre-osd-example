// SPDX-License-Identifier: GPL-2.0

/*
 * Author: Timothy Day <tday141@gmail.com>
 */

#include <libcfs/libcfs.h>
#include <obd_support.h>
#include <obd.h>
#include <obd_class.h>

#include "osd_internal.h"

void osd_buf_free(struct osd_buf *buf)
{
	unsigned int i;

	LASSERT(buf);

	if (!buf->ob_buf)
		return;

	LASSERT(buf->ob_len > 0);

	vunmap(buf->ob_buf);

	for (i = 0; i < buf->ob_npages; i++)
		if (buf->ob_pages[i])
			__free_page(buf->ob_pages[i]);

	OBD_FREE(buf->ob_pages, sizeof(struct page *) * buf->ob_npages);
	memset(buf, 0, sizeof(struct osd_buf));
}

static unsigned int get_npages(size_t size)
{
	unsigned int result = size / PAGE_SIZE;

	if (size % PAGE_SIZE != 0)
		result++;

	return result;
}

void osd_buf_alloc(struct osd_buf *buf, size_t size)
{
	unsigned int npages;
	unsigned int i;

	LASSERT(buf);
	LASSERT(buf->ob_buf == NULL);
	LASSERT(buf->ob_len == 0);
	LASSERT(buf->ob_pages == NULL);
	LASSERT(buf->ob_npages == 0);

	npages = get_npages(size);

	OBD_ALLOC(buf->ob_pages, sizeof(struct page *) * npages);
	if (!buf->ob_pages)
		return;

	memset(buf->ob_pages, 0, sizeof(struct page *) * npages);
	buf->ob_npages = npages;
	buf->ob_len = size;

	for (i = 0; i < npages; i++) {
		buf->ob_pages[i] = alloc_page(GFP_NOFS);

		if (!buf->ob_pages[i])
			goto free_pages;
	}

	buf->ob_buf = vmap(buf->ob_pages, npages,
			   VM_MAP, PAGE_KERNEL);
	if (!buf->ob_buf)
		goto free_pages;

	return;

free_pages:
	for (i = 0; i < npages; i++)
		if (buf->ob_pages[i])
			__free_page(buf->ob_pages[i]);

	OBD_FREE(buf->ob_pages, sizeof(struct page *) * npages);
	memset(buf, 0, sizeof(struct osd_buf));
}

int osd_buf_check_and_grow(struct osd_buf *buf, size_t len)
{
	struct osd_buf nbuf;

	if (len <= buf->ob_len)
		return 0;

	memset(&nbuf, 0, sizeof(struct osd_buf));

	osd_buf_alloc(&nbuf, len);
	if (!nbuf.ob_buf)
		return -ENOMEM;

	if (buf->ob_buf)
		memcpy(nbuf.ob_buf, buf->ob_buf, buf->ob_len);

	osd_buf_free(buf);
	memcpy(buf, &nbuf, sizeof(struct osd_buf));

	return 0;
}

int osd_buf_cpy_ptr(struct osd_buf *dst, void *src, size_t len,
		    loff_t off)
{
	size_t size = len + off;
	int rc = 0;

	if (!dst->ob_buf)
		osd_buf_alloc(dst, size);

	if (!dst->ob_buf)
		return -ENOMEM;

	rc = osd_buf_check_and_grow(dst, size);
	if (rc)
		return rc;

	memcpy(dst->ob_buf + off, src, len);

	return 0;
}
