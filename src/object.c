// SPDX-License-Identifier: GPL-2.0

/*
 * Author: Timothy Day <tday141@gmail.com>
 */

#include <linux/errno.h>
#include <libcfs/libcfs.h>
#include <obd_support.h>
#include <lustre_net.h>
#include <obd.h>
#include <obd_class.h>
#include <lustre_disk.h>
#include <lustre_fid.h>

#include "common.h"

static int osd_index_try(const struct lu_env *env, struct dt_object *dt,
			 const struct dt_index_features *feat)
{
	struct osd_object *obj = osd_obj(dt);
	struct osd_data *data = obj->oo_data;

	ENTRY;
	OSD_TRACE(dt);

	/* Declare this object as an index */
	obj->oo_is_index = 1;

	if (likely(feat == &dt_directory_features)) {
		dt->do_index_ops = &osd_dir_ops;
		OSD_DEBUG("osd_dir_ops\n");
		RETURN(0);
	} else if (unlikely(feat == &dt_acct_features)) {
		dt->do_index_ops = &osd_acct_index_ops;
		OSD_DEBUG("osd_acct_index_ops\n");
		RETURN(0);
	} else if (unlikely(feat == &dt_otable_features)) {
		/* TODO: This is a hack to mount OSD */
		dt->do_index_ops = &osd_index_ops;
		LCONSOLE_ERROR("LFSCK is not supported for in-memory OSD\n");
		RETURN(0);
	} else {
		dt->do_index_ops = &osd_index_ops;
		data->od_keysize_max = feat->dif_keysize_max;
		data->od_recsize_max = feat->dif_recsize_max;
		OSD_DEBUG("osd_index_ops\n");
		RETURN(0);
	}

	RETURN(-EINVAL);
}

static int osd_object_init(const struct lu_env *env, struct lu_object *l,
			   const struct lu_object_conf *conf)
{
	struct osd_object *obj = osd_obj(l);
	struct osd_data *data;
	int rc;

	ENTRY;
	OSD_TRACE(l);

	rc = osd_data_find_or_create(env, obj, lu_object_fid(l));
	if (rc)
		RETURN(rc);

	obj->oo_dt.do_body_ops = &osd_body_ops;
	data = obj->oo_data;
	obj->oo_dt.do_lu.lo_header->loh_attr |= data->od_attr.la_mode & S_IFMT;

	RETURN(0);
}

static void osd_object_free(const struct lu_env *env, struct lu_object *l)
{
	struct osd_object *obj = osd_obj(l);
	struct lu_object_header *h = obj->oo_header;

	ENTRY;
	OSD_TRACE(l);

	dt_object_fini(&obj->oo_dt);

	OBD_FREE_PTR(obj);
	if (unlikely(h))
		lu_object_header_free(h);

	EXIT;
}

/*
 * TODO: We have no need to declare transactions ahead of time.
 * Instead, leave this as a stub function - omitting it induces
 * a crash.
 */
static int osd_declare_destroy(const struct lu_env *env, struct dt_object *dt,
			       struct thandle *th)
{
	NOT_IMPLEMENTED(0);
}

static int osd_destroy(const struct lu_env *env, struct dt_object *dt,
		       struct thandle *th)
{
	struct osd_object *obj = osd_obj(dt);
	struct osd_device *osd = osd_obj2dev(obj);
	struct osd_data *data;

	ENTRY_TH(th);
	OSD_TRACE(dt);

	down(&obj->oo_guard);

	if (unlikely(!dt_object_exists(dt) || obj->oo_destroyed)) {
		up(&obj->oo_guard);
		RETURN_TH(th, -ENOENT);
	}

	data = obj->oo_data;
	rhashtable_remove_fast(&osd->od_data_hash,
			       &data->od_hash,
			       osd_data_params);
	osd_data_free(data, NULL);
	obj->oo_data = NULL;
	up(&obj->oo_guard);
	set_bit(LU_OBJECT_HEARD_BANSHEE, &dt->do_lu.lo_header->loh_flags);
	obj->oo_destroyed = 1;

	RETURN_TH(th, 0);
}

static void osd_read_lock(const struct lu_env *env, struct dt_object *dt,
			  unsigned int role)
{
	struct osd_object *obj = osd_obj(dt);

	ENTRY;
	down_read_nested(&obj->oo_sem, role);
	OSD_TRACE(dt);
	EXIT;
}

static void osd_write_lock(const struct lu_env *env, struct dt_object *dt,
			   unsigned int role)
{
	struct osd_object *obj = osd_obj(dt);

	ENTRY;
	down_write_nested(&obj->oo_sem, role);
	OSD_TRACE(dt);
	EXIT;
}

static void osd_read_unlock(const struct lu_env *env, struct dt_object *dt)
{
	struct osd_object *obj = osd_obj(dt);

	ENTRY;
	up_read(&obj->oo_sem);
	OSD_TRACE(dt);
	EXIT;
}

static void osd_write_unlock(const struct lu_env *env, struct dt_object *dt)
{
	struct osd_object *obj = osd_obj(dt);

	ENTRY;
	up_write(&obj->oo_sem);
	OSD_TRACE(dt);
	EXIT;
}

static int osd_write_locked(const struct lu_env *env, struct dt_object *dt)
{
	struct osd_object *obj = osd_obj(dt);
	int rc = 1;

	ENTRY;

	if (down_write_trylock(&obj->oo_sem)) {
		rc = 0;
		up_write(&obj->oo_sem);
	}

	OSD_TRACE(dt);
	RETURN(rc);
}

static int osd_attr_get(const struct lu_env *env, struct dt_object *dt,
			struct lu_attr *attr)
{
	struct osd_object *obj = osd_obj(dt);
	struct osd_data *data = obj->oo_data;
	struct lu_attr *od_attr = &data->od_attr;
	struct osd_buf *buf = &data->od_buf;

	ENTRY;
	OSD_TRACE(dt);

	down(&obj->oo_guard);

	if (unlikely(!dt_object_exists(dt) || obj->oo_destroyed)) {
		up(&obj->oo_guard);
		RETURN(-ENOENT);
	}

	od_attr->la_valid |= LA_ATIME | LA_MTIME | LA_CTIME | LA_MODE |
		LA_SIZE | LA_BLOCKS | LA_UID | LA_GID |
		LA_PROJID | LA_FLAGS | LA_NLINK | LA_RDEV |
		LA_BLKSIZE | LA_TYPE | LA_BTIME;
	od_attr->la_size = buf->ob_len;

	obj->oo_dt.do_lu.lo_header->loh_attr |= data->od_attr.la_mode & S_IFMT;
	*attr = data->od_attr;
	up(&obj->oo_guard);

	OSD_DEBUG("LA_SIZE=%llu\n", attr->la_size);
	RETURN(0);
}

/*
 * TODO: We have no need to declare transactions ahead of time.
 * Instead, leave this as a stub function - omitting it induces
 * a crash.
 */
static int osd_declare_attr_set(const struct lu_env *env,
				struct dt_object *dt,
				const struct lu_attr *attr,
				struct thandle *handle)
{
	NOT_IMPLEMENTED(0);
}

static int osd_attr_set(const struct lu_env *env, struct dt_object *dt,
			const struct lu_attr *la, struct thandle *th)
{
	struct osd_object *obj = osd_obj(dt);
	struct osd_data *data = obj->oo_data;
	struct lu_attr *od_attr = &data->od_attr;
	__u64 valid = la->la_valid;
	int rc = 0;

	ENTRY_TH(th);
	OSD_TRACE(dt);

	down(&obj->oo_guard);

	if (unlikely(!dt_object_exists(dt) || obj->oo_destroyed)) {
		up(&obj->oo_guard);
		RETURN_TH(th, -ENOENT);
	}

	/* Only allow set size for regular file */
	if (!S_ISREG(dt->do_lu.lo_header->loh_attr))
		valid &= ~(LA_SIZE | LA_BLOCKS);

	if (valid & LA_CTIME && la->la_ctime == od_attr->la_ctime)
		valid &= ~LA_CTIME;

	if (valid & LA_MTIME && la->la_mtime == od_attr->la_mtime)
		valid &= ~LA_MTIME;

	if (valid & LA_ATIME && la->la_atime == od_attr->la_atime)
		valid &= ~LA_ATIME;

	if (valid == 0)
		GOTO(out, rc = 0);

	if (valid & LA_ATIME)
		od_attr->la_atime = la->la_atime;

	if (valid & LA_MTIME)
		od_attr->la_mtime = la->la_mtime;

	if (valid & LA_CTIME)
		od_attr->la_ctime = la->la_ctime;

	if (valid & LA_MODE)
		od_attr->la_mode = (od_attr->la_mode & S_IFMT) |
			(la->la_mode & ~S_IFMT);

	if (valid & LA_SIZE)
		od_attr->la_size = la->la_size;

	if (valid & LA_NLINK)
		od_attr->la_nlink = la->la_nlink;

	if (valid & LA_RDEV)
		od_attr->la_rdev = la->la_rdev;

	if (valid & LA_UID)
		od_attr->la_uid = la->la_uid;

	if (valid & LA_GID)
		od_attr->la_gid = la->la_gid;

out:
	up(&obj->oo_guard);
	RETURN_TH(th, rc);
}

static void osd_ah_init(const struct lu_env *env, struct dt_allocation_hint *ah,
			struct dt_object *parent, struct dt_object *child,
			umode_t child_mode)
{
	ENTRY;
	LASSERT(ah);

	ah->dah_parent = parent;

	if (likely(parent))
		OSD_DEBUG("parent FID = " DFID "\n", PFID(lu_object_fid(&parent->do_lu)));
	else
		OSD_DEBUG("parent FID = NULL\n");

	OSD_DEBUG("child FID = " DFID "\n", PFID(lu_object_fid(&child->do_lu)));

	if (parent && !dt_object_remote(parent)) {
		struct osd_object *pobj = osd_dt_obj(parent);
		const struct lu_fid *fid = lu_object_fid(&pobj->oo_dt.do_lu);

		osd_data_find_or_create(env, pobj, fid);
	}

	EXIT;
}

/*
 * TODO: We have no need to declare transactions ahead of time.
 * Instead, leave this as a stub function - omitting it induces
 * a crash.
 */
static int osd_declare_create(const struct lu_env *env, struct dt_object *dt,
			      struct lu_attr *attr,
			      struct dt_allocation_hint *hint,
			      struct dt_object_format *dof,
			      struct thandle *handle)
{
	NOT_IMPLEMENTED(0);
}

static int osd_create(const struct lu_env *env, struct dt_object *dt,
		      struct lu_attr *attr, struct dt_allocation_hint *hint,
		      struct dt_object_format *dof, struct thandle *th)
{
	struct osd_object *obj = osd_obj(dt);
	struct osd_data *data = obj->oo_data;

	ENTRY_TH(th);

	down(&obj->oo_guard);
	obj->oo_dt.do_lu.lo_header->loh_attr |= LOHA_EXISTS;

	data->od_attr = *attr;
	data->od_attr.la_size = 0;
	data->od_attr.la_nlink = 1;
	data->od_attr.la_valid |= LA_SIZE | LA_NLINK | LA_TYPE;

	if (!(data->od_attr.la_valid & LA_FLAGS))
		data->od_attr.la_flags = 0;

	obj->oo_dt.do_lu.lo_header->loh_attr |= data->od_attr.la_mode & S_IFMT;

	switch (dof->dof_type) {
	case DFT_DIR:
		obj->oo_dt.do_lu.lo_header->loh_attr |= S_IFDIR;
		data->od_attr.la_mode |= S_IFDIR;
		break;
	case DFT_REGULAR:
		obj->oo_dt.do_lu.lo_header->loh_attr |= S_IFREG;
		data->od_attr.la_mode |= S_IFREG;
		break;
	case DFT_SYM:
		break;
	case DFT_NODE:
		break;
	case DFT_INDEX:
		break;
	default:
		break;
	}

	up(&obj->oo_guard);
	OSD_TRACE(dt);
	RETURN_TH(th, 0);
}

/*
 * TODO: We have no need to declare transactions ahead of time.
 * Instead, leave this as a stub function - omitting it induces
 * a crash.
 */
static int osd_declare_ref_add(const struct lu_env *env, struct dt_object *dt,
			       struct thandle *th)
{
	NOT_IMPLEMENTED(0);
}

static int osd_ref_add(const struct lu_env *env, struct dt_object *dt,
		       struct thandle *th)
{
	struct osd_object *obj = osd_obj(dt);
	struct osd_data *data = obj->oo_data;
	struct lu_attr *od_attr = &data->od_attr;
	int rc = 0;

	ENTRY_TH(th);
	OSD_TRACE(dt);

	down(&obj->oo_guard);
	if (unlikely(!dt_object_exists(dt) || obj->oo_destroyed))
		rc = -ENOENT;
	else
		od_attr->la_nlink++;
	up(&obj->oo_guard);
	RETURN_TH(th, rc);
}

/*
 * TODO: We have no need to declare transactions ahead of time.
 * Instead, leave this as a stub function - omitting it induces
 * a crash.
 */
static int osd_declare_ref_del(const struct lu_env *env, struct dt_object *dt,
			       struct thandle *handle)
{
	NOT_IMPLEMENTED(0);
}

static int osd_ref_del(const struct lu_env *env, struct dt_object *dt,
		       struct thandle *th)
{
	struct osd_object *obj = osd_obj(dt);
	struct osd_data *data = obj->oo_data;
	struct lu_attr *od_attr = &data->od_attr;
	int rc = 0;

	ENTRY_TH(th);
	OSD_TRACE(dt);

	down(&obj->oo_guard);
	if (unlikely(!dt_object_exists(dt) || obj->oo_destroyed))
		rc = -ENOENT;
	else
		od_attr->la_nlink--;
	up(&obj->oo_guard);
	RETURN_TH(th, rc);
}

static int osd_xattr_get(const struct lu_env *env, struct dt_object *dt,
			 struct lu_buf *buf, const char *name)
{
	struct osd_object *obj = osd_obj(dt);
	struct osd_data *data = obj->oo_data;
	struct osd_index_data *entry;

	ENTRY;
	OSD_TRACE(dt);

	OSD_DEBUG("xattr - %s\n", name);

	down(&obj->oo_guard);
	list_for_each_entry(entry, &data->od_xattr_list,
			    oi_list) {
		if (!strcmp(name, entry->oi_key.lb_buf)) {
			if (!buf->lb_len || !buf->lb_buf) {
				up(&obj->oo_guard);
				RETURN(entry->oi_value.lb_len);
			}

			if (buf->lb_len < entry->oi_value.lb_len) {
				up(&obj->oo_guard);
				RETURN(-ERANGE);
			}

			if (entry->oi_value.lb_len == 0) {
				up(&obj->oo_guard);
				RETURN(1);
			}

			memcpy(buf->lb_buf, entry->oi_value.lb_buf,
			       buf->lb_len);
			up(&obj->oo_guard);
			RETURN(entry->oi_value.lb_len);
		}
	}

	up(&obj->oo_guard);
	RETURN(-ENODATA);
}

/*
 * TODO: We have no need to declare transactions ahead of time.
 * Instead, leave this as a stub function - omitting it induces
 * a crash.
 */
static int osd_declare_xattr_set(const struct lu_env *env, struct dt_object *dt,
				 const struct lu_buf *buf, const char *name,
				 int fl, struct thandle *handle)
{
	NOT_IMPLEMENTED(0);
}

static int osd_xattr_set(const struct lu_env *env, struct dt_object *dt,
			 const struct lu_buf *buf, const char *name, int fl,
			 struct thandle *th)
{
	struct osd_index_data *entry, *tmp;
	struct osd_object *obj = osd_obj(dt);
	struct osd_data *data = obj->oo_data;
	int rc = 0;

	ENTRY_TH(th);

	OSD_DEBUG("xattr - %s\n", name);

	down(&obj->oo_guard);
	list_for_each_entry(tmp, &data->od_xattr_list,
			    oi_list) {
		if (!strcmp(name, tmp->oi_key.lb_buf)) {
			if (fl & LU_XATTR_CREATE) {
				up(&obj->oo_guard);
				RETURN(-EEXIST);
			}

			rc = lu_buf_cpy(&tmp->oi_value, buf, 0);
			up(&obj->oo_guard);
			RETURN_TH(th, rc);
		}
	}

	if (fl & LU_XATTR_REPLACE) {
		up(&obj->oo_guard);
		RETURN(-EEXIST);
	}

	OBD_ALLOC_PTR(entry);
	if (!entry) {
		up(&obj->oo_guard);
		RETURN_TH(th, -ENOMEM);
	}

	rc = lu_buf_cpy(&entry->oi_value, buf, 0);
	if (rc)
		GOTO(out_free_entry, rc);

	rc = lu_buf_cpy_ptr(&entry->oi_key, (void *)name,
			    strlen(name) + 1, 0);
	if (rc)
		GOTO(out_free_value, rc);

	list_add(&entry->oi_list, &data->od_xattr_list);

	OSD_TRACE(dt);
	up(&obj->oo_guard);
	RETURN_TH(th, rc);

out_free_value:
	lu_buf_free(&entry->oi_value);

out_free_entry:
	OBD_FREE_PTR(entry);

	OSD_TRACE(dt);
	up(&obj->oo_guard);
	RETURN_TH(th, rc);
}

/*
 * TODO: We have no need to declare transactions ahead of time.
 * Instead, leave this as a stub function - omitting it induces
 * a crash.
 */
static int osd_declare_xattr_del(const struct lu_env *env, struct dt_object *dt,
				 const char *name, struct thandle *handle)
{
	NOT_IMPLEMENTED(0);
}

static int osd_xattr_del(const struct lu_env *env, struct dt_object *dt,
			 const char *name, struct thandle *th)
{
	ENTRY_TH(th);
	OSD_TRACE(dt);
	RETURN_TH(th, 0);
}

static int osd_xattr_list(const struct lu_env *env, struct dt_object *dt,
			  const struct lu_buf *lb)
{
	ENTRY;
	OSD_TRACE(dt);
	RETURN(0);
}

static int osd_object_sync(const struct lu_env *env, struct dt_object *dt,
			   __u64 start, __u64 end)
{
	NOT_IMPLEMENTED(0);
}

static int osd_invalidate(const struct lu_env *env, struct dt_object *dt)
{
	NOT_IMPLEMENTED(0);
}

/*
 * TODO: This appears to return false for every OSD implementation
 * I've seen. This can likely be removed altogether.
 */
static bool osd_check_stale(struct dt_object *dt)
{
	return false;
}

const struct dt_object_operations osd_obj_ops = {
	.do_read_lock		= osd_read_lock,
	.do_write_lock		= osd_write_lock,
	.do_read_unlock		= osd_read_unlock,
	.do_write_unlock	= osd_write_unlock,
	.do_write_locked	= osd_write_locked,
	.do_attr_get		= osd_attr_get,
	.do_declare_attr_set	= osd_declare_attr_set,
	.do_attr_set		= osd_attr_set,
	.do_ah_init		= osd_ah_init,
	.do_declare_create	= osd_declare_create,
	.do_create		= osd_create,
	.do_declare_destroy	= osd_declare_destroy,
	.do_destroy		= osd_destroy,
	.do_index_try		= osd_index_try,
	.do_declare_ref_add	= osd_declare_ref_add,
	.do_ref_add		= osd_ref_add,
	.do_declare_ref_del	= osd_declare_ref_del,
	.do_ref_del		= osd_ref_del,
	.do_xattr_get		= osd_xattr_get,
	.do_declare_xattr_set	= osd_declare_xattr_set,
	.do_xattr_set		= osd_xattr_set,
	.do_declare_xattr_del	= osd_declare_xattr_del,
	.do_xattr_del		= osd_xattr_del,
	.do_xattr_list		= osd_xattr_list,
	.do_object_sync		= osd_object_sync,
	.do_invalidate		= osd_invalidate,
	.do_check_stale		= osd_check_stale,
};

const struct lu_object_operations osd_lu_obj_ops = {
	.loo_object_init	= osd_object_init,
	.loo_object_free	= osd_object_free,
};
