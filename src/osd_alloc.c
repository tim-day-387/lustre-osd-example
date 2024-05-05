// SPDX-License-Identifier: GPL-2.0

/*
 * Author: Timothy Day <tday141@gmail.com>
 */

#include <libcfs/libcfs.h>
#include <obd_support.h>
#include <obd.h>
#include <obd_class.h>

#include "osd_internal.h"

int lu_buf_cpy_ptr(struct lu_buf *dst, void *src, size_t len,
		   loff_t off)
{
	size_t size = len + off;
	int rc = 0;

	if (!dst->lb_buf)
		lu_buf_alloc(dst, size);

	if (!dst->lb_buf)
		return -ENOMEM;

	rc = lu_buf_check_and_grow(dst, size);
	if (rc)
		return rc;

	memcpy(dst->lb_buf + off, src, len);

	return 0;
}

void osd_buf_free(struct osd_buf *buf)
{
	unsigned int i;

	LASSERT(buf);

	if (!buf->ob_pages)
		return;

	LASSERT(buf->ob_npages > 0);

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

int osd_buf_alloc(struct osd_buf *buf, size_t size)
{
	unsigned int npages;
	unsigned int i;

	LASSERT(buf);
	LASSERT(buf->ob_len == 0);
	LASSERT(buf->ob_pages == NULL);
	LASSERT(buf->ob_npages == 0);

	npages = get_npages(size);

	OBD_ALLOC(buf->ob_pages, sizeof(struct page *) * npages);
	if (!buf->ob_pages)
		return -ENOMEM;

	memset(buf->ob_pages, 0, sizeof(struct page *) * npages);
	buf->ob_npages = npages;
	buf->ob_len = size;

	for (i = 0; i < npages; i++) {
		buf->ob_pages[i] = alloc_page(GFP_NOFS & ~__GFP_HIGHMEM);

		if (!buf->ob_pages[i])
			goto free_pages;
	}

	return 0;

free_pages:
	for (i = 0; i < npages; i++)
		if (buf->ob_pages[i])
			__free_page(buf->ob_pages[i]);

	OBD_FREE(buf->ob_pages, sizeof(struct page *) * npages);
	memset(buf, 0, sizeof(struct osd_buf));

	return -ENOMEM;
}

int osd_buf_check_and_grow(struct osd_buf *buf, size_t len)
{
	struct page **tmp_pages;
	unsigned int npages;
	unsigned int i;

	LASSERT(buf);

	npages = get_npages(len);

	if (npages <= buf->ob_npages)
		return 0;

	if (!buf->ob_pages)
		return osd_buf_alloc(buf, len);

	OBD_ALLOC(tmp_pages, sizeof(struct page *) * npages);
	if (!tmp_pages)
		return -ENOMEM;

	memset(tmp_pages, 0, sizeof(struct page *) * npages);
	memcpy(tmp_pages, buf->ob_pages, sizeof(struct page *) * buf->ob_npages);

	for (i = buf->ob_npages; i < npages; i++) {
		tmp_pages[i] = alloc_page(GFP_NOFS & ~__GFP_HIGHMEM);

		if (!tmp_pages[i])
			goto free_pages;
	}

	OBD_FREE(buf->ob_pages, sizeof(struct page *) * buf->ob_npages);
	buf->ob_pages = tmp_pages;
	buf->ob_npages = npages;
	buf->ob_len = len;

	return 0;

free_pages:
	for (i = buf->ob_npages; i < npages; i++)
		if (tmp_pages[i])
			__free_page(tmp_pages[i]);

	OBD_FREE(tmp_pages, sizeof(struct page *) * npages);

	return -ENOMEM;
}

int osd_buf_read(struct osd_buf *src, void *dst, size_t len,
		 loff_t off)
{
	unsigned int startp = off / PAGE_SIZE;
	unsigned int i;
	size_t poff = off % PAGE_SIZE;
	size_t read = 0;
	size_t read_size;

	if (startp > src->ob_npages)
		return -EBADR;

	for (i = startp; i < src->ob_npages; i++) {
		read_size = len < (PAGE_SIZE - poff) ? len :
			(PAGE_SIZE - poff);
		if (!read_size)
			break;

		memcpy(dst + read,
		       page_address(src->ob_pages[i]) + poff,
		       read_size);

		poff = 0;
		len -= read_size;
		read += read_size;
	}

	return 0;
}

int osd_buf_write(struct osd_buf *dst, void *src, size_t len,
		  loff_t off)
{
	unsigned int startp = off / PAGE_SIZE;
	unsigned int i;
	size_t size = len + off;
	size_t poff = off % PAGE_SIZE;
	size_t written = 0;
	size_t write_size;
	int rc = 0;

	rc = osd_buf_check_and_grow(dst, size);
	if (rc)
		return rc;

	for (i = startp; i < dst->ob_npages; i++) {
		write_size = len < (PAGE_SIZE - poff) ? len :
			(PAGE_SIZE - poff);
		if (!write_size)
			break;

		memcpy(page_address(dst->ob_pages[i]) + poff,
		       src + written, write_size);

		poff = 0;
		len -= write_size;
		written += write_size;
	}

	return 0;
}
