// SPDX-License-Identifier: GPL-2.0

/*
 * Author: Timothy Day <tday141@gmail.com>
 */

#define DEBUG_SUBSYSTEM S_OSD

#include <libcfs/libcfs.h>
#include <obd_support.h>
#include <lustre_net.h>
#include <obd.h>
#include <obd_class.h>
#include <lustre_disk.h>
#include <lustre_fid.h>
#include <lustre_quota.h>

#include "osd_internal.h"

static ssize_t osd_read(const struct lu_env *env, struct dt_object *dt,
			struct lu_buf *buf, loff_t *pos)
{
	struct osd_object *osd = osd_obj(dt);
	struct osd_data *data = osd->oo_data;
	struct osd_buf *sbuf = &data->od_buf;
	ssize_t avail;
	ssize_t size;
	int rc;

	down(&osd->oo_sem_data);

	avail = *pos >= sbuf->ob_len ? 0 :
		sbuf->ob_len - *pos;
	size = buf->lb_len > avail ? avail :
		buf->lb_len;

	ENTRY;

	if (size > avail) {
		up(&osd->oo_sem_data);
		RETURN(-EBADR);
	}

	rc = osd_buf_read(sbuf, buf->lb_buf, size, *pos);
	if (rc) {
		up(&osd->oo_sem_data);
		RETURN(-EBADR);
	}

	*pos += size;
	up(&osd->oo_sem_data);

	OSD_TRACE(dt);
	OSD_DEBUG("TLSZ=%li,OFFSET=%lli,READSZ=%li,AVAIL=%li\n",
		  sbuf->ob_len, *pos, size, avail);
	RETURN(size);
}

/*
 * TODO: We have no need to declare transactions ahead of time.
 * Instead, leave this as a stub function - omitting it induces
 * a crash.
 */
static ssize_t osd_declare_write(const struct lu_env *env, struct dt_object *dt,
				 const struct lu_buf *buf, loff_t pos,
				 struct thandle *th)
{
	NOT_IMPLEMENTED(0);
}

static ssize_t osd_write(const struct lu_env *env, struct dt_object *dt,
			 const struct lu_buf *sbuf, loff_t *pos,
			 struct thandle *th)
{
	struct osd_object *osd = osd_obj(dt);
	struct osd_data *data = osd->oo_data;
	struct osd_buf *dbuf = &data->od_buf;
	int rc = 0;

	ENTRY_TH(th);

	down(&osd->oo_sem_data);
	rc = osd_buf_write(dbuf, sbuf->lb_buf, sbuf->lb_len, *pos);
	if (rc) {
		up(&osd->oo_sem_data);
		RETURN_TH(th, rc);
	}

	*pos += sbuf->lb_len;
	if (*pos > dbuf->ob_len)
		dbuf->ob_len = *pos;
	up(&osd->oo_sem_data);

	OSD_TRACE(dt);
	OSD_DEBUG("TLSZ=%li,OFFSET=%lli,WRITESZ=%li\n",
		  data->od_buf.ob_len,
		  *pos, sbuf->lb_len);
	RETURN_TH(th, sbuf->lb_len);
}

static int osd_bufs_put(const struct lu_env *env, struct dt_object *dt,
			struct niobuf_local *lnb, int npages)
{
	int i;

	ENTRY;
	OSD_TRACE(dt);

	for (i = 0; i < npages; i++)
		lnb->lnb_page = NULL;

	RETURN(0);
}

/*
 * TODO: Split this into read/write, similar to openZFS OSD!
 */
static int osd_bufs_get(const struct lu_env *env, struct dt_object *dt,
			loff_t offset, ssize_t len, struct niobuf_local *lnb,
			int maxlnb, enum dt_bufs_type rw)
{
	struct osd_object *obj = osd_dt_obj(dt);
	struct osd_data *data = obj->oo_data;
	struct osd_buf *buf = &data->od_buf;
	size_t nbuf_sz = offset + len;
	loff_t eof;
	int i = offset / PAGE_SIZE;
	int plen, poff;
	int npages = 0;
	int rc = 0;

	ENTRY;
	OSD_TRACE(dt);
	OSD_DEBUG("OFFSET=%lli,OPSZ=%li,OP=%s\n",
		  offset, len,
		  (rw & DT_BUFS_TYPE_WRITE) ? "WRITE" : "READ");

	down(&obj->oo_sem_data);
	rc = osd_buf_check_and_grow(buf, nbuf_sz);
	if (rc) {
		up(&obj->oo_sem_data);
		RETURN(rc);
	}

	eof = data->od_attr.la_size;
	if (!eof && (rw & DT_BUFS_TYPE_READ)) {
		lnb->lnb_file_offset = 0;
		lnb->lnb_page_offset = 0;
		lnb->lnb_len = 0;
		lnb->lnb_flags = 0;
		lnb->lnb_page = NULL;
		lnb->lnb_rc = 0;
		up(&obj->oo_sem_data);
		return 1;
	}

	while (len > 0) {
		poff = offset % PAGE_SIZE;
		plen = PAGE_SIZE - poff;

		if (plen > len)
			plen = len;

		if (unlikely(npages >= maxlnb))
			GOTO(out_err, rc = -EOVERFLOW);

		lnb->lnb_file_offset = offset;
		lnb->lnb_page_offset = poff;

		// TODO: This is a hack!
		if (rw & DT_BUFS_TYPE_READ) {
			if (eof < (offset + plen))
				plen = eof - offset;
		}

		lnb->lnb_len = plen;
		lnb->lnb_flags = 0;

		if (unlikely(i >= buf->ob_npages))
			GOTO(out_err, rc = -EOVERFLOW);

		lnb->lnb_page = buf->ob_pages[i];
		lnb->lnb_rc = 0;

		offset += plen;
		len -= plen;
		npages++;
		lnb++;
		i++;

		OSD_DEBUG("OFFSET=%lli,OPSZ=%li\n",
			  offset, len);
	}

	up(&obj->oo_sem_data);
	RETURN(npages);

out_err:
	if (npages > 0)
		osd_bufs_put(env, dt, lnb - npages, npages);

	up(&obj->oo_sem_data);
	RETURN(rc);
}

static int osd_read_prep(const struct lu_env *env, struct dt_object *dt,
			 struct niobuf_local *lnb, int npages)
{
	struct osd_object *obj = osd_dt_obj(dt);
	struct osd_data *data = obj->oo_data;
	loff_t eof;
	int i;

	ENTRY;
	OSD_TRACE(dt);

	eof = data->od_attr.la_size;

	for (i = 0; i < npages; i++) {
		if (unlikely(lnb[i].lnb_rc < 0))
			continue;

		lnb[i].lnb_rc = lnb[i].lnb_len;

		if (lnb[i].lnb_file_offset + lnb[i].lnb_len >= eof) {
			/* send complete pages all the time */
			if (eof <= lnb[i].lnb_file_offset)
				lnb[i].lnb_rc = 0;

			/* all subsequent rc should be 0 */
			while (++i < npages)
				lnb[i].lnb_rc = 0;

			break;
		}
	}

	RETURN(0);
}

static int osd_write_prep(const struct lu_env *env, struct dt_object *dt,
			  struct niobuf_local *lnb, int npages)
{
	ENTRY;
	OSD_TRACE(dt);
	RETURN(0);
}

/*
 * TODO: We have no need to declare transactions ahead of time.
 * Instead, leave this as a stub function - omitting it induces
 * a crash.
 */
static int osd_declare_write_commit(const struct lu_env *env,
				    struct dt_object *dt,
				    struct niobuf_local *lnb, int npages,
				    struct thandle *th)
{
	NOT_IMPLEMENTED(0);
}

static int osd_write_commit(const struct lu_env *env, struct dt_object *dt,
			    struct niobuf_local *lnb, int npages,
			    struct thandle *th, __u64 user_size)
{
	struct osd_object *obj = osd_dt_obj(dt);
	struct osd_data *data = obj->oo_data;
	uint64_t new_size = 0;
	int i;

	ENTRY_TH(th);
	OSD_TRACE(dt);

	/* If la_size is already bigger than specified user_size,
	 * ignore user_size
	 */
	if (data->od_attr.la_size > user_size)
		user_size = 0;


	for (i = 0; i < npages; i++) {
		OSD_DEBUG("write %u bytes at %u\n",
			  (unsigned) lnb[i].lnb_len,
			  (unsigned) lnb[i].lnb_file_offset);

		if (lnb[i].lnb_rc)
			continue;

		if (new_size < lnb[i].lnb_file_offset + lnb[i].lnb_len)
			new_size = lnb[i].lnb_file_offset + lnb[i].lnb_len;

		if (lnb[i].lnb_page == NULL)
			continue;
	}

	if (unlikely(new_size == 0)) {
		/* No pages to write, no transno is needed */
		th->th_local = 1;

		/* It is important to return 0 even when all lnb_rc == -ENOSPC
		 * since ofd_commitrw_write() retries several times on ENOSPC
		 */
		RETURN(0);
	}

	/* If file has grown, take user_size into account */
	if (user_size && new_size > user_size)
		new_size = user_size;

	if (data->od_attr.la_size < new_size)
		data->od_attr.la_size = new_size;

	RETURN_TH(th, 0);
}

/*
 * TODO: We have no need to declare transactions ahead of time.
 * Instead, leave this as a stub function - omitting it induces
 * a crash.
 */
static int osd_declare_punch(const struct lu_env *env, struct dt_object *dt,
			     __u64 start, __u64 end, struct thandle *handle)
{
	NOT_IMPLEMENTED(0);
}

static int osd_punch(const struct lu_env *env, struct dt_object *dt,
		     __u64 start, __u64 end, struct thandle *th)
{
	ENTRY_TH(th);
	OSD_TRACE(dt);
	RETURN_TH(th, 0);
}

static int osd_ladvise(const struct lu_env *env, struct dt_object *dt,
		       __u64 start, __u64 end, enum lu_ladvise_type advice)
{
	ENTRY;
	OSD_TRACE(dt);
	RETURN(0);
}

/*
 * TODO: We have no need to declare transactions ahead of time.
 * Instead, leave this as a stub function - omitting it induces
 * a crash.
 */
static int osd_declare_fallocate(const struct lu_env *env,
				 struct dt_object *dt, __u64 start, __u64 end,
				 int mode, struct thandle *th)
{
	NOT_IMPLEMENTED(0);
}

static int osd_fallocate(const struct lu_env *env, struct dt_object *dt,
			 __u64 start, __u64 end, int mode, struct thandle *th)
{
	ENTRY_TH(th);
	OSD_TRACE(dt);
	RETURN_TH(th, 0);
}

static loff_t osd_lseek(const struct lu_env *env, struct dt_object *dt,
			loff_t offset, int whence)
{
	ENTRY;
	OSD_TRACE(dt);
	RETURN(0);
}

const struct dt_body_operations osd_body_ops = {
	.dbo_read			= osd_read,
	.dbo_declare_write		= osd_declare_write,
	.dbo_write			= osd_write,
	.dbo_bufs_get			= osd_bufs_get,
	.dbo_bufs_put			= osd_bufs_put,
	.dbo_write_prep			= osd_write_prep,
	.dbo_declare_write_commit	= osd_declare_write_commit,
	.dbo_write_commit		= osd_write_commit,
	.dbo_read_prep			= osd_read_prep,
	.dbo_declare_punch		= osd_declare_punch,
	.dbo_punch			= osd_punch,
	.dbo_ladvise			= osd_ladvise,
	.dbo_declare_fallocate		= osd_declare_fallocate,
	.dbo_fallocate			= osd_fallocate,
	.dbo_lseek			= osd_lseek,
};
