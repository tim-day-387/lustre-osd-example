// SPDX-License-Identifier: GPL-2.0

/*
 * Author: Timothy Day <tday141@gmail.com>
 */

#include <libcfs/libcfs.h>
#include <obd_support.h>
#include <lustre_net.h>
#include <obd.h>
#include <obd_class.h>
#include <lustre_disk.h>
#include <lustre_fid.h>

#include "osd_internal.h"

static int osd_index_lookup(const struct lu_env *env, struct dt_object *dt,
			    struct dt_rec *rec, const struct dt_key *key)
{
	struct osd_object *osd = osd_obj(dt);
	struct osd_data *data = osd->oo_data;
	struct osd_index_data *entry;
	size_t keysize = data->od_keysize_max;
	size_t recsize = data->od_recsize_max;

	ENTRY;
	OSD_TRACE(dt);

	list_for_each_entry(entry, &data->od_index_list,
			    oi_list) {
		if (!memcmp(key, entry->oi_key.lb_buf, keysize)) {
			memcpy(rec, entry->oi_value.lb_buf,
			       recsize);
			RETURN(1);
		}
	}

	RETURN(0);
}

/*
 * TODO: We have no need to declare transactions ahead of time.
 * Instead, leave this as a stub function - omitting it induces
 * a crash.
 */
static int osd_declare_index_insert(const struct lu_env *env,
				    struct dt_object *dt,
				    const struct dt_rec *rec,
				    const struct dt_key *key,
				    struct thandle *th)
{
	NOT_IMPLEMENTED(0);
}

static int osd_index_insert(const struct lu_env *env, struct dt_object *dt,
			    const struct dt_rec *rec, const struct dt_key *key,
			    struct thandle *th)
{
	struct osd_index_data *entry;
	struct osd_object *osd = osd_obj(dt);
	struct osd_data *data = osd->oo_data;
	size_t keysize = data->od_keysize_max;
	size_t recsize = data->od_recsize_max;
	int rc = 0;

	ENTRY_TH(th);

	OBD_ALLOC_PTR(entry);
	if (!entry)
		RETURN_TH(th, -ENOMEM);

	rc = lu_buf_cpy_ptr(&entry->oi_value, (void *)rec,
			    recsize, 0);
	if (rc)
		GOTO(out_free_entry, rc);

	rc = lu_buf_cpy_ptr(&entry->oi_key, (void *)key,
			    keysize, 0);
	if (rc)
		GOTO(out_free_value, rc);

	list_add(&entry->oi_list, &data->od_index_list);

	OSD_TRACE(dt);
	RETURN_TH(th, rc);

out_free_value:
	lu_buf_free(&entry->oi_value);

out_free_entry:
	OBD_FREE_PTR(entry);

	OSD_TRACE(dt);
	RETURN_TH(th, rc);
}

/*
 * TODO: We have no need to declare transactions ahead of time.
 * Instead, leave this as a stub function - omitting it induces
 * a crash.
 */
static int osd_declare_index_delete(const struct lu_env *env,
				    struct dt_object *dt,
				    const struct dt_key *key,
				    struct thandle *th)
{
	NOT_IMPLEMENTED(0);
}

static int osd_index_delete(const struct lu_env *env, struct dt_object *dt,
			    const struct dt_key *key, struct thandle *th)
{
	NOT_IMPLEMENTED(0);
}

static struct dt_it *osd_index_it_init(const struct lu_env *env,
				       struct dt_object *dt,
				       __u32 unused)
{
	struct osd_object *obj = osd_obj(dt);
	struct osd_data *data = obj->oo_data;
	struct osd_it *it;

	ENTRY;

	if (obj->oo_destroyed)
		RETURN(ERR_PTR(-ENOENT));

	OBD_ALLOC_PTR(it);
	if (!it)
		RETURN(ERR_PTR(-ENOMEM));

	it->oit_cursor = &data->od_index_list;
	it->oit_obj = obj;
	get_random_bytes(&it->oit_tracking_num, sizeof(int));

	RETURN((struct dt_it *)it);
}

static void osd_index_it_fini(const struct lu_env *env, struct dt_it *di)
{
	struct osd_it *it = (struct osd_it *)di;

	ENTRY;
	OBD_FREE_PTR(it);
	EXIT;
}

static int osd_index_it_get(const struct lu_env *env, struct dt_it *di,
			    const struct dt_key *key)
{
	struct osd_it *it = (struct osd_it *)di;
	struct osd_object *obj = it->oit_obj;
	struct osd_data *data = obj->oo_data;
	struct osd_index_data *entry;
	size_t keysize = data->od_keysize_max;

	ENTRY;

	list_for_each_entry(entry, &data->od_index_list,
			    oi_list) {
		if (!memcmp(key, entry->oi_key.lb_buf, keysize)) {
			it->oit_cursor = &entry->oi_list;
			RETURN(0);
		}
	}

	RETURN(-EIO);
}

static void osd_index_it_put(const struct lu_env *env, struct dt_it *di)
{
	ENTRY;
	EXIT;
}

static int osd_index_it_next(const struct lu_env *env, struct dt_it *di)
{
	struct osd_it *it = (struct osd_it *)di;
	struct osd_object *obj = it->oit_obj;
	struct osd_data *data = obj->oo_data;

	ENTRY;

	it->oit_cursor = it->oit_cursor->next;

	if (list_is_head(it->oit_cursor, &data->od_index_list))
		RETURN(1);

	RETURN(0);
}

static struct dt_key *osd_index_it_key(const struct lu_env *env,
				       const struct dt_it *di)
{
	struct osd_it *it = (struct osd_it *)di;
	struct osd_index_data *entry;

	ENTRY;

	entry = container_of(it->oit_cursor,
			     struct osd_index_data,
			     oi_list);

	RETURN(entry->oi_key.lb_buf);
}

static int osd_index_it_key_size(const struct lu_env *env,
				 const struct dt_it *di)
{
	struct osd_it *it = (struct osd_it *)di;
	struct osd_object *obj = it->oit_obj;
	struct osd_data *data = obj->oo_data;

	ENTRY;
	RETURN(data->od_keysize_max);
}

static int osd_index_it_rec(const struct lu_env *env, const struct dt_it *di,
			    struct dt_rec *rec, __u32 attr)
{
	struct osd_it *it = (struct osd_it *)di;
	struct osd_object *obj = it->oit_obj;
	struct osd_data *data = obj->oo_data;
	struct osd_index_data *entry;
	size_t recsize = data->od_recsize_max;

	ENTRY;

	entry = container_of(it->oit_cursor,
			     struct osd_index_data,
			     oi_list);

	memcpy(rec, entry->oi_value.lb_buf, recsize);
	RETURN(0);
}

static int osd_index_it_rec_size(const struct lu_env *env, const struct dt_it *di,
				 __u32 attr)
{
	struct osd_it *it = (struct osd_it *)di;
	struct osd_object *obj = it->oit_obj;
	struct osd_data *data = obj->oo_data;

	ENTRY;
	RETURN(data->od_recsize_max);
}

static __u64 osd_index_it_store(const struct lu_env *env,
				const struct dt_it *di)
{
	struct osd_it *it = (struct osd_it *)di;
	struct osd_index_data *entry;

	ENTRY;

	entry = container_of(it->oit_cursor,
			     struct osd_index_data,
			     oi_list);

	RETURN(entry->oi_hash);
}

static int osd_index_it_load(const struct lu_env *env, const struct dt_it *di,
			     __u64 hash)
{
	struct osd_it *it = (struct osd_it *)di;
	struct osd_object *obj = it->oit_obj;
	struct osd_data *data = obj->oo_data;

	ENTRY;

	if (!hash) {
		it->oit_cursor = &data->od_index_list;
		it->oit_cursor = it->oit_cursor->next;

		if (list_is_head(it->oit_cursor, &data->od_index_list))
			RETURN(0);

		RETURN(1);
	} else {
		RETURN(-EIO);
	}
}

const struct dt_index_operations osd_index_ops = {
	.dio_lookup		= osd_index_lookup,
	.dio_declare_insert	= osd_declare_index_insert,
	.dio_insert		= osd_index_insert,
	.dio_declare_delete	= osd_declare_index_delete,
	.dio_delete		= osd_index_delete,
	.dio_it	= {
		.init		= osd_index_it_init,
		.fini		= osd_index_it_fini,
		.get		= osd_index_it_get,
		.put		= osd_index_it_put,
		.next		= osd_index_it_next,
		.key		= osd_index_it_key,
		.key_size	= osd_index_it_key_size,
		.rec		= osd_index_it_rec,
		.rec_size	= osd_index_it_rec_size,
		.store		= osd_index_it_store,
		.load		= osd_index_it_load
	}
};

static int osd_dir_lookup(const struct lu_env *env, struct dt_object *dt,
			  struct dt_rec *rec, const struct dt_key *key)
{
	struct osd_object *obj = osd_obj(dt);
	struct osd_data *data = obj->oo_data;
	struct osd_index_data *entry;
	char *name = (char *)key;

	ENTRY;
	OSD_TRACE(dt);

	OSD_DEBUG("key - %s\n", name);

	if (obj->oo_destroyed)
		RETURN(-ENOENT);

	list_for_each_entry(entry, &data->od_index_list,
			    oi_list) {
		if (!strcmp(name, entry->oi_key.lb_buf)) {
			memcpy(rec, entry->oi_value.lb_buf,
			       sizeof(struct lu_fid));
			RETURN(1);
		}
	}

	RETURN(0);
}

static int osd_dir_insert(const struct lu_env *env, struct dt_object *dt,
			  const struct dt_rec *rec, const struct dt_key *key,
			  struct thandle *th)
{
	const struct dt_insert_rec *in_rec;
	const struct lu_fid *fid;
	struct osd_index_data *entry;
	struct osd_object *osd = osd_obj(dt);
	struct osd_data *data = osd->oo_data;
	char *name = (char *)key;
	size_t keysize = strlen(name) + 1;
	size_t recsize = sizeof(struct lu_fid);
	int rc = 0;

	ENTRY_TH(th);

	OBD_ALLOC_PTR(entry);
	if (!entry)
		RETURN_TH(th, -ENOMEM);

	in_rec = (struct dt_insert_rec *)rec;
	fid = in_rec->rec_fid;
	data->od_last_ind += 1;
	entry->oi_hash = data->od_last_ind;

	rc = lu_buf_cpy_ptr(&entry->oi_value, (void *)fid,
			    recsize, 0);
	if (rc)
		GOTO(out_free_entry, rc);

	rc = lu_buf_cpy_ptr(&entry->oi_key, (void *)name,
			    keysize, 0);
	if (rc)
		GOTO(out_free_value, rc);

	list_add_tail(&entry->oi_list, &data->od_index_list);

	OSD_DEBUG("key=%s,value=" DFID "\n", name, PFID(fid));
	OSD_TRACE(dt);
	RETURN_TH(th, rc);

out_free_value:
	lu_buf_free(&entry->oi_value);

out_free_entry:
	OBD_FREE_PTR(entry);

	OSD_DEBUG("key=%s,value=" DFID "\n", name, PFID(fid));
	OSD_TRACE(dt);
	RETURN_TH(th, rc);
}

static int osd_dir_delete(const struct lu_env *env, struct dt_object *dt,
			  const struct dt_key *key, struct thandle *th)
{
	struct osd_object *osd = osd_obj(dt);
	struct osd_data *data = osd->oo_data;
	struct osd_index_data *entry, *tmp;
	char *name = (char *)key;

	ENTRY_TH(th);
	OSD_TRACE(dt);

	OSD_DEBUG("key - %s\n", name);

	list_for_each_entry_safe(entry, tmp, &data->od_index_list,
				 oi_list) {
		if (!strcmp(name, entry->oi_key.lb_buf)) {
			list_del(&entry->oi_list);
			lu_buf_free(&entry->oi_key);
			lu_buf_free(&entry->oi_value);
			OBD_FREE_PTR(entry);
			RETURN_TH(th, 0);
		}
	}

	RETURN_TH(th, 0);
}

static int osd_dir_it_get(const struct lu_env *env, struct dt_it *di,
			  const struct dt_key *key)
{
	struct osd_it *it = (struct osd_it *)di;
	struct osd_object *obj = it->oit_obj;
	struct osd_data *data = obj->oo_data;
	struct osd_index_data *entry = container_of(it->oit_cursor,
						    struct osd_index_data,
						    oi_list);
	char *name = (char *)entry->oi_key.lb_buf;

	ENTRY;
	OSD_IT_TRACE(it);

	if (list_is_head(it->oit_cursor, &data->od_index_list))
		RETURN(1);

	list_for_each_entry(entry, &data->od_index_list,
			    oi_list) {
		if (!strcmp(name, entry->oi_key.lb_buf)) {
			it->oit_cursor = &entry->oi_list;
			RETURN(1);
		}
	}

	RETURN(-EIO);
}

static void osd_dir_it_put(const struct lu_env *env, struct dt_it *di)
{
	ENTRY;
	EXIT;
}

static int osd_dir_it_next(const struct lu_env *env, struct dt_it *di)
{
	struct osd_it *it = (struct osd_it *)di;
	struct osd_object *obj = it->oit_obj;
	struct osd_data *data = obj->oo_data;

	ENTRY;
	OSD_IT_TRACE(it);

	it->oit_cursor = it->oit_cursor->next;

	if (list_is_head(it->oit_cursor, &data->od_index_list))
		RETURN(1);

	RETURN(0);
}

static struct dt_key *osd_dir_it_key(const struct lu_env *env,
				     const struct dt_it *di)
{
	struct osd_it *it = (struct osd_it *)di;
	struct osd_index_data *entry = container_of(it->oit_cursor,
						    struct osd_index_data,
						    oi_list);
	char *name = (char *)entry->oi_key.lb_buf;

	ENTRY;
	OSD_IT_TRACE(it);
	RETURN((struct dt_key *)name);
}

static int osd_dir_it_key_size(const struct lu_env *env,
			       const struct dt_it *di)
{
	struct osd_it *it = (struct osd_it *)di;
	struct osd_index_data *entry = container_of(it->oit_cursor,
						    struct osd_index_data,
						    oi_list);
	char *name = (char *)entry->oi_key.lb_buf;
	size_t keysize = strlen(name) + 1;

	ENTRY;
	OSD_IT_TRACE(it);
	RETURN(keysize);
}

static inline void osd_it_append_attrs(struct lu_dirent *ent, __u32 attr,
				       int len, __u16 type)
{
	const unsigned int align = sizeof(struct luda_type) - 1;
	struct luda_type *lt;

	/* check if file type is required */
	if (attr & LUDA_TYPE) {
		len = (len + align) & ~align;
		lt = (void *)ent->lde_name + len;
		ent->lde_attrs |= LUDA_TYPE;

		/* TODO: Only LFSCK looks at this */
		lt->lt_type = 0;
	}

	ent->lde_attrs = cpu_to_le32(ent->lde_attrs);
}

static int osd_dir_it_rec(const struct lu_env *env, const struct dt_it *di,
			  struct dt_rec *rec, __u32 attr)
{
	struct lu_dirent *lde = (struct lu_dirent *)rec;
	struct osd_it *it = (struct osd_it *)di;
	struct osd_object *obj = it->oit_obj;
	struct osd_index_data *entry = container_of(it->oit_cursor,
						    struct osd_index_data,
						    oi_list);
	struct osd_data *data = obj->oo_data;
	struct lu_fid fid;
	char *name = (char *)entry->oi_key.lb_buf;
	int namelen;

	ENTRY;
	OSD_IT_TRACE(it);

	/* TODO: Technically, the list_head isn't a real entry. But
	 * doing nothing can induce a crash or issues with the client.
	 * So, just return the entry for the current directory. ZFS
	 * seems to do the same.
	 */
	if (list_is_head(it->oit_cursor, &data->od_index_list)) {
		lde->lde_hash = cpu_to_le64(0);
		strcpy(lde->lde_name, ".");
		lde->lde_namelen = cpu_to_le16(1);
		fid_cpu_to_le(&lde->lde_fid,
			      lu_object_fid(lu_dt_obj(&obj->oo_dt)));
		lde->lde_attrs = LUDA_FID;
		osd_it_append_attrs(lde, attr, 1, 0);
		lde->lde_reclen = cpu_to_le16(lu_dirent_calc_size(1, attr));
		RETURN(0);
	}

	memcpy(&fid, entry->oi_value.lb_buf, sizeof(struct lu_fid));

	lde->lde_attrs = 0;
	lde->lde_hash = entry->oi_hash;

	namelen = strlen(name);
	if (namelen > NAME_MAX)
		RETURN(-EOVERFLOW);

	strcpy(lde->lde_name, name);
	lde->lde_namelen = cpu_to_le16(namelen);

	fid_cpu_to_le(&lde->lde_fid, &fid);
	lde->lde_attrs = LUDA_FID;

	osd_it_append_attrs(lde, attr, namelen, 0);
	lde->lde_reclen = cpu_to_le16(lu_dirent_calc_size(namelen, attr));

	RETURN(0);
}

static int osd_dir_it_rec_size(const struct lu_env *env, const struct dt_it *di,
			       __u32 attr)
{
	struct osd_it *it = (struct osd_it *)di;
	struct osd_index_data *entry = container_of(it->oit_cursor,
						    struct osd_index_data,
						    oi_list);
	char *name = (char *)entry->oi_key.lb_buf;
	int namelen;
	int rc;

	ENTRY;
	OSD_IT_TRACE(it);

	namelen = strlen(name);
	if (namelen > NAME_MAX)
		RETURN(-EOVERFLOW);

	rc = lu_dirent_calc_size(namelen, attr);

	RETURN(rc);
}

static __u64 osd_dir_it_store(const struct lu_env *env,
			      const struct dt_it *di)
{
	struct osd_it *it = (struct osd_it *)di;
	struct osd_index_data *entry;
	struct osd_object *obj = it->oit_obj;
	struct osd_data *data = obj->oo_data;
	char *name;

	ENTRY;
	OSD_IT_TRACE(it);

	entry = container_of(it->oit_cursor,
			     struct osd_index_data,
			     oi_list);

	name = (char *)entry->oi_key.lb_buf;

	if (list_is_head(it->oit_cursor, &data->od_index_list))
		RETURN(0);

	if (name[0] == '.' && name[1] == 0)
		RETURN(0);

	if (name[0] == '.' && name[1] == '.' && name[2] == 0)
		RETURN(0);

	RETURN(entry->oi_hash);
}

static int osd_dir_it_load(const struct lu_env *env, const struct dt_it *di,
			   __u64 hash)
{
	struct osd_it *it = (struct osd_it *)di;
	struct osd_object *obj = it->oit_obj;
	struct osd_data *data = obj->oo_data;

	ENTRY;

	if (!hash) {
		it->oit_cursor = &data->od_index_list;
		it->oit_cursor = it->oit_cursor->next;

		if (list_is_head(it->oit_cursor, &data->od_index_list))
			RETURN(0);

		RETURN(1);
	} else {
		RETURN(-EIO);
	}
}

const struct dt_index_operations osd_dir_ops = {
	.dio_lookup         = osd_dir_lookup,
	.dio_declare_insert = osd_declare_index_insert,
	.dio_insert         = osd_dir_insert,
	.dio_declare_delete = osd_declare_index_delete,
	.dio_delete         = osd_dir_delete,
	.dio_it     = {
		.init     = osd_index_it_init,
		.fini     = osd_index_it_fini,
		.get      = osd_dir_it_get,
		.put      = osd_dir_it_put,
		.next     = osd_dir_it_next,
		.key      = osd_dir_it_key,
		.key_size = osd_dir_it_key_size,
		.rec      = osd_dir_it_rec,
		.rec_size = osd_dir_it_rec_size,
		.store    = osd_dir_it_store,
		.load     = osd_dir_it_load
	}
};
