// SPDX-License-Identifier: GPL-2.0

/*
 * Author: Timothy Day <tday141@gmail.com>
 */

#ifndef _OSD_INTERNAL_H
#define _OSD_INTERNAL_H

#include <linux/refcount.h>
#include <dt_object.h>
#include <md_object.h>
#include <lustre_quota.h>
#include <lustre_scrub.h>
#include <obd.h>

#define MAXNAMELEN 1000
#define OSD_MAX_CACHE_SIZE OBD_OBJECT_EOF
#define OSD_MAGIC 12345
#define OSD_BLK_SIZE 1024

extern const struct dt_index_operations osd_acct_index_ops;
extern const struct lu_device_operations osd_lu_ops;
extern const struct dt_index_operations osd_dir_ops;

extern const struct dt_object_operations osd_obj_ops;
extern const struct lu_object_operations osd_lu_obj_ops;
extern const struct dt_object_operations osd_obj_otable_it_ops;

extern const struct dt_device_operations osd_dt_ops;

extern const struct dt_index_operations osd_index_ops;
extern const struct dt_body_operations osd_body_ops;

extern const struct rhashtable_params osd_data_params;

extern int verbose_debug;

struct osd_buf {
	size_t			ob_len;
	struct page	      **ob_pages;
	unsigned int		ob_npages;
};

struct osd_device {
	/* super-class */
	struct dt_device	 od_dt_dev;

	/* info about underlying file system */
	struct objset		*od_os;

	unsigned int		 od_dev_set_rdonly:1, /* osd_ro() called */
				 od_xattr_in_sa:1,
				 od_is_ost:1,
				 od_in_init:1,
				 od_posix_acl:1,
				 od_nonrotational:1,
				 od_sync_on_lseek:1;

	int			 od_index_backup_stop;

	char			 od_mntdev[128];
	char			 od_svname[128];

	int			 od_connects;
	int			 od_index;
	struct lu_site		 od_site;

	struct rhashtable	 od_data_hash;

	struct osd_otable_it	*od_otable_it;
	unsigned long long	 od_readcache_max_filesize;

	struct lu_client_seq	*od_cl_seq;
};

struct osd_thandle {
	struct thandle		 ot_super;

	struct list_head	 ot_commit_dcb_list;
	struct list_head	 ot_stop_dcb_list;

	/* Used for tracking osd_thandle in logging */
	int			 ot_tracking_num;
};

struct osd_object {
	struct dt_object	 oo_dt;

	/* Used for tracking osd_objects in logging */
	int			 oo_tracking_num;
	int			 oo_is_index;

	/* used to implement osd_*_{lock|unlock} */
	struct rw_semaphore	 oo_sem;

	/* Used to protect osd_data osd_buf from
	 * concurrent grow/shrink. ldlm should protect
	 * concurrent data access, but not how we
	 * manage memory.
	 *
	 * Also, serialize some updates: destroy vs. others,
	 * xattr_set, object block size change etc
	 *
	 * TODO: Find a better way!
	 */
	struct semaphore	 oo_guard;

	__u32			 oo_destroyed:1;

	/* data osd_object refers to */
	struct osd_data		*oo_data;

	struct lu_object_header *oo_header;
};

struct osd_data {
	struct lu_fid		od_fid;
	struct rhash_head	od_hash;

	/* File metadata */
	struct lu_attr		od_attr;

	/* File xattrs */
	struct list_head	od_xattr_list;

	/* Used for regular objects */
	struct osd_buf		od_buf;

	/* Used only for index objects */
	struct list_head	od_index_list;
	size_t			od_keysize_max;
	size_t			od_recsize_max;
	__u64			od_last_ind;

	/* Used for tracking osd_data in logging */
	int			od_tracking_num;
};

struct osd_index_data {
	struct lu_buf		oi_key;
	struct lu_buf		oi_value;
	struct list_head	oi_list;
	__u64			oi_hash;
};

struct osd_it {
	struct list_head	*oit_cursor;
	struct osd_object	*oit_obj;

	/* Used for tracking osd_it in logging */
	int			 oit_tracking_num;
};

struct named_oid {
	unsigned long	 oid;
	char		*name;
};

static inline struct lu_device *osd2lu_dev(struct osd_device *osd)
{
	return &osd->od_dt_dev.dd_lu_dev;
}

static inline const struct lu_object *lu_dt_obj(const struct dt_object *d)
{
	return &d->do_lu;
}

/*
 * Convert upper layer devices to osd_device
 */

static inline struct osd_device *osd_dt_dev(const struct dt_device *dt)
{
	return container_of(dt, struct osd_device, od_dt_dev);
}

static inline struct osd_device *osd_lu_dev(const struct lu_device *lu)
{
	return osd_dt_dev(container_of(lu, struct dt_device, dd_lu_dev));
}

static inline void *osd_default_dev(void *obj)
{
	return NULL;
}

#define osd_dev(obj)						\
	_Generic((obj),						\
		const struct dt_device *: osd_dt_dev,		\
		struct dt_device *: osd_dt_dev,			\
		const struct lu_device *: osd_lu_dev,		\
		struct lu_device *: osd_lu_dev,			\
		default: osd_default_dev			\
	)(obj)

/*
 * Convert upper layer objects to osd_object
 */

static inline struct osd_object *osd_lu_obj(const struct lu_object *lu)
{
	return container_of(lu, struct osd_object, oo_dt.do_lu);
}

static inline struct osd_object *osd_dt_obj(const struct dt_object *dt)
{
	return osd_lu_obj(&dt->do_lu);
}

static inline void *osd_default_obj(void *obj)
{
	return NULL;
}

#define osd_obj(obj)						\
	_Generic((obj),						\
		const struct dt_object *: osd_dt_obj,		\
		struct dt_object *: osd_dt_obj,			\
		const struct lu_object *: osd_lu_obj,		\
		struct lu_object *: osd_lu_obj,			\
		default: osd_default_obj			\
	)(obj)

static inline struct osd_device *osd_obj2dev(const struct osd_object *o)
{
	return osd_dev(o->oo_dt.do_lu.lo_dev);
}

static inline struct seq_server_site *osd_seq_site(struct osd_device *osd)
{
	return osd->od_dt_dev.dd_lu_dev.ld_site->ld_seq_site;
}

static inline int osd_remote_fid(struct osd_device *osd, const struct lu_fid *fid)
{
	struct seq_server_site *ss = osd_seq_site(osd);

	/* FID seqs not in FLDB, must be local seq */
	if (unlikely(!fid_seq_in_fldb(fid_seq(fid))))
		return 0;

	/* If FLD is not being initialized yet, it only happens during the
	 * initialization, likely during mgs initialization, and we assume
	 * this is local FID.
	 */
	if (!ss || !ss->ss_server_fld)
		return 0;

	/*
	 * Only check the local FLDB here
	 *
	 * TODO: The local FLD isn't implemented
	 * yet - this requires a generic index
	 * mechanism first.
	 */
	// if (osd_seq_exists(env, osd, fid_seq(fid)))
	//	RETURN(0);

	return 1;
}

/*
 * Function declarations
 */

int osd_data_find_or_create(const struct lu_env *env, struct osd_object *obj,
			    const struct lu_fid *fid);
void osd_data_free(void *data_input, void *args);
int osd_get_object_count(void);

/*
 * Custom buffer functions
 */

void osd_buf_free(struct osd_buf *buf);
int osd_buf_alloc(struct osd_buf *buf, size_t size);
int osd_buf_check_and_grow(struct osd_buf *buf, size_t len);
int osd_buf_read(struct osd_buf *src, void *dst, size_t len,
		 loff_t off);
int osd_buf_write(struct osd_buf *dst, void *src, size_t len,
		  loff_t off);
int lu_buf_cpy_ptr(struct lu_buf *dst, void *src, size_t len,
		   loff_t off);

static inline int lu_buf_cpy(struct lu_buf *dst,
			     const struct lu_buf *src,
			     loff_t off)
{
	return lu_buf_cpy_ptr(dst, src->lb_buf, src->lb_len, off);
}

/*
 * Custom Lustre debugging macros
 */

#define D_OSD_MEM (verbose_debug ? D_WARNING : D_TRACE)

#define OSD_DEBUG(format, ...)						\
	__CDEBUG_WITH_LOC(__FILE__, __func__, __LINE__,			\
			  D_OSD_MEM, NULL, format, ## __VA_ARGS__)

#define OSD_DEBUG_FID(fid, format, ...)					\
	__CDEBUG_WITH_LOC(__FILE__, __func__, __LINE__,			\
			  D_OSD_MEM, NULL, "f="DFID format, PFID(fid),	\
			  ## __VA_ARGS__)

/*
 * Print out the condition of osd_objects and functions
 */

static inline void osd_oo_trace(const struct osd_object *oo,
				struct libcfs_debug_msg_data *msgdata)
{
	libcfs_debug_msg(msgdata, "TRACE n=%i\n", oo->oo_tracking_num);
}

static inline void osd_dt_trace(const struct dt_object *dt,
				struct libcfs_debug_msg_data *msgdata)
{
	struct osd_object *oo = osd_obj(dt);
	struct osd_data *data = oo->oo_data;

	libcfs_debug_msg(msgdata, "TRACE n=%i e=%i ind=%i f=" DFID " r=%i rd=%i:%i\n",
			 oo->oo_tracking_num,
			 dt_object_exists(dt),
			 oo->oo_is_index,
			 PFID(lu_object_fid(lu_dt_obj(dt))),
			 osd_remote_fid(osd_obj2dev(oo), lu_object_fid(lu_dt_obj(dt))),
			 (data ? S_ISREG(data->od_attr.la_mode) : 0),
			 (data ? S_ISDIR(data->od_attr.la_mode) : 0));
}

static inline void osd_lu_trace(const struct lu_object *lu,
				struct libcfs_debug_msg_data *msgdata)
{
	struct osd_object *oo = osd_obj(lu);
	struct osd_data *data = oo->oo_data;

	libcfs_debug_msg(msgdata, "TRACE n=%i e=%i ind=%i f=" DFID " r=%i rd=%i:%i\n",
			 oo->oo_tracking_num,
			 lu_object_exists(lu),
			 oo->oo_is_index,
			 PFID(lu_object_fid(lu)),
			 osd_remote_fid(osd_obj2dev(oo), lu_object_fid(lu)),
			 (data ? S_ISREG(data->od_attr.la_mode) : 0),
			 (data ? S_ISDIR(data->od_attr.la_mode) : 0));
}

static inline void osd_default_trace(void *obj,
				     struct libcfs_debug_msg_data *msgdata)
{
	libcfs_debug_msg(msgdata, "OSD_TRACE\n");
}

#define OSD_TRACE_LINE(obj, msg)				\
	_Generic((obj),						\
		const struct osd_object *: osd_oo_trace,	\
		struct osd_object *: osd_oo_trace,		\
		const struct dt_object *: osd_dt_trace,		\
		struct dt_object *: osd_dt_trace,		\
		const struct lu_object *: osd_lu_trace,		\
		struct lu_object *: osd_lu_trace,		\
		default: osd_default_trace			\
	)(obj, msg)

#define __OSD_TRACE_LINE(file, func, line, mask, cdls, obj)		\
do {									\
	static struct libcfs_debug_msg_data msgdata;			\
									\
	if (cfs_cdebug_show(mask, DEBUG_SUBSYSTEM)) {			\
		LIBCFS_DEBUG_MSG_DATA_INIT(file, func, line,		\
					   &msgdata, mask, cdls);	\
		OSD_TRACE_LINE(obj, &msgdata);				\
	}								\
} while (0)

#define OSD_TRACE(obj)							\
	__OSD_TRACE_LINE(__FILE__, __func__, __LINE__,			\
			 D_OSD_MEM, NULL, obj)

#define OSD_IT_TRACE(it)						\
do {									\
	struct osd_object *tmp_obj = it->oit_obj;			\
	struct osd_index_data *tmp_entry = container_of(it->oit_cursor,	\
						    struct osd_index_data, \
						    oi_list);		\
	char *tmp_name = (char *)tmp_entry->oi_key.lb_buf;		\
									\
	OSD_DEBUG("name=%s hash=%llu\n", tmp_name, tmp_entry->oi_hash);	\
	OSD_TRACE(&tmp_obj->oo_dt);					\
} while (0)

#define TRANS_START(th)							\
do {									\
	struct osd_thandle *oh_tmp;					\
									\
	oh_tmp = container_of_safe(th, struct osd_thandle, ot_super);	\
	OSD_DEBUG("START trans=%i\n",					\
		  oh_tmp->ot_tracking_num);				\
} while (0)

#define TRANS_STOP(th)							\
do {									\
	struct osd_thandle *oh_tmp;					\
									\
	oh_tmp = container_of_safe(th, struct osd_thandle, ot_super);	\
	OSD_DEBUG("STOP trans=%i\n",					\
		  oh_tmp->ot_tracking_num);				\
} while (0)

#define ENTRY_TH(th)							\
do {									\
	struct osd_thandle *oh_tmp;					\
									\
	oh_tmp = container_of_safe(th, struct osd_thandle, ot_super);	\
	OSD_DEBUG("ENTRY trans=%i\n",					\
		  oh_tmp->ot_tracking_num);				\
} while (0)

#define EXIT_TH(th)							\
do {									\
	struct osd_thandle *oh_tmp;					\
									\
	oh_tmp = container_of_safe(th, struct osd_thandle, ot_super);	\
	OSD_DEBUG("EXIT trans=%i\n",					\
		  oh_tmp->ot_tracking_num);				\
} while (0)

#define RETURN_TH(th, rc)						\
do {									\
	struct osd_thandle *oh_tmp;					\
	typeof(rc) __rc = (rc);						\
									\
	oh_tmp = container_of_safe(th, struct osd_thandle, ot_super);	\
	OSD_DEBUG("EXIT trans=%i (rc ~ %lu, %ld, %#lx)\n",		\
		  oh_tmp->ot_tracking_num,				\
		  (long)__rc, (long)__rc, (long)__rc);			\
	return rc;							\
} while (0)

#define NOT_IMPLEMENTED(rc)					   \
do {								   \
	typeof(rc) __rc = (rc);					   \
	OSD_DEBUG("NOT_IMPLEMENTED (rc ~ %lu, %ld, %#lx)\n",	   \
		  (long)__rc, (long)__rc, (long)__rc);		   \
	return rc;						   \
} while (0)

/*
 * Redefine common tracing macros to dump a bunch
 * of information out to dmesg logs
 */

#undef ENTRY
#define ENTRY						\
do {							\
	OSD_DEBUG("ENTRY\n");				\
} while (0)

#undef EXIT
#define EXIT						\
do {							\
	OSD_DEBUG("EXIT\n");				\
} while (0)

#undef RETURN
#define RETURN(rc)						   \
do {								   \
	typeof(rc) __rc = (rc);					   \
	OSD_DEBUG("EXIT (rc ~ %lu, %ld, %#lx)\n",		   \
		  (long)__rc, (long)__rc, (long)__rc);		   \
	return rc;						   \
} while (0)

#endif /* _OSD_INTERNAL_H */
