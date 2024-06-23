// SPDX-License-Identifier: GPL-2.0

/*
 * Author: Timothy Day <tday141@gmail.com>
 */

#include <libcfs/linux/linux-hash.h>
#include <libcfs/libcfs.h>
#include <obd_support.h>
#include <lustre_net.h>
#include <obd.h>
#include <obd_class.h>
#include <lustre_disk.h>
#include <lustre_fid.h>

#include "common.h"

static atomic_t object_count = ATOMIC_INIT(0);

void osd_data_free(void *data_input, void *args)
{
	struct osd_data *data = data_input;
	struct osd_index_data *entry, *tmp;

	OSD_DEBUG_FID(&data->od_fid, " data_num=%i size=%lu\n",
		      data->od_tracking_num, data->od_buf.ob_len);

	if (data->od_buf.ob_len)
		osd_buf_free(&data->od_buf);

	list_for_each_entry_safe(entry, tmp, &data->od_index_list,
				 oi_list) {
		list_del(&entry->oi_list);

		if (entry->oi_key.lb_len)
			lu_buf_free(&entry->oi_key);

		if (entry->oi_value.lb_len)
			lu_buf_free(&entry->oi_value);

		OBD_FREE_PTR(entry);
	}

	list_for_each_entry_safe(entry, tmp, &data->od_xattr_list,
				 oi_list) {
		list_del(&entry->oi_list);

		if (entry->oi_key.lb_len)
			lu_buf_free(&entry->oi_key);

		if (entry->oi_value.lb_len)
			lu_buf_free(&entry->oi_value);

		OBD_FREE_PTR(entry);
	}

	OBD_FREE_PTR(data);
}

int osd_get_object_count(void)
{
	return atomic_read(&object_count);
}

int osd_data_find_or_create(const struct lu_env *env, struct osd_object *obj,
			    const struct lu_fid *fid)
{
	struct osd_device *osd = osd_obj2dev(obj);
	struct osd_data *data;
	struct osd_data *ret;

	ENTRY;

	rcu_read_lock();
	OBD_ALLOC_PTR(data);
	data->od_fid = *fid;
	memset(&data->od_buf, 0, sizeof(struct osd_buf));
	INIT_LIST_HEAD(&data->od_index_list);
	INIT_LIST_HEAD(&data->od_xattr_list);
	data->od_last_ind = 0;

	/* Random number to track osd_object */
	get_random_bytes(&data->od_tracking_num, sizeof(int));

	ret = rhashtable_lookup_get_insert_fast(&osd->od_data_hash,
						&data->od_hash,
						osd_data_params);
	if (IS_ERR(ret)) {
		OBD_FREE_PTR(data);
		rcu_read_unlock();
		return PTR_ERR(ret);
	}

	if (ret) {
		OBD_FREE_PTR(data);
		obj->oo_dt.do_lu.lo_header->loh_attr |= LOHA_EXISTS;
		data = ret;
	} else {
		atomic_inc(&object_count);
	}

	obj->oo_data = data;

	OSD_DEBUG_FID(fid, " data_num=%i size=%lu\n",
		      obj->oo_data->od_tracking_num,
		      data->od_buf.ob_len);

	if (unlikely(fid_is_fs_root(fid))) {
		OSD_DEBUG_FID(fid, " fid is fs root\n");
		obj->oo_dt.do_lu.lo_header->loh_attr |= S_IFDIR;
		obj->oo_dt.do_lu.lo_header->loh_attr |= LOHA_EXISTS;
	}

	rcu_read_unlock();
	RETURN(0);
}
