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
#include <uapi/linux/lustre/lustre_param.h>
#include <md_object.h>

#include "osd_internal.h"

int verbose_debug;

static int osd_root_get(const struct lu_env *env,
			struct dt_device *dev, struct lu_fid *f)
{
	ENTRY;
	lu_local_obj_fid(f, OSD_FS_ROOT_OID);
	RETURN(0);
}

static int osd_trans_cb_add(struct thandle *th, struct dt_txn_commit_cb *dcb)
{
	struct osd_thandle *oh = container_of(th, struct osd_thandle,
					      ot_super);

	ENTRY_TH(th);

	LASSERT(dcb->dcb_magic == TRANS_COMMIT_CB_MAGIC);
	LASSERT(&dcb->dcb_func);

	if (dcb->dcb_flags & DCB_TRANS_STOP)
		list_add(&dcb->dcb_linkage, &oh->ot_stop_dcb_list);
	else
		list_add(&dcb->dcb_linkage, &oh->ot_commit_dcb_list);

	RETURN_TH(th, 0);
}

static int osd_trans_start(const struct lu_env *env, struct dt_device *d,
			   struct thandle *th)
{
	NOT_IMPLEMENTED(0);
}

static void osd_trans_commit_cb(struct osd_thandle *oh, int result)
{
	struct thandle *th = &oh->ot_super;
	struct dt_txn_commit_cb *dcb, *tmp;

	/* call per-transaction callbacks if any */
	list_for_each_entry_safe(dcb, tmp, &oh->ot_commit_dcb_list,
				 dcb_linkage) {
		LASSERTF(dcb->dcb_magic == TRANS_COMMIT_CB_MAGIC,
			 "commit callback entry: magic=%x name='%s'\n",
			 dcb->dcb_magic, dcb->dcb_name);
		list_del_init(&dcb->dcb_linkage);
		dcb->dcb_func(NULL, th, dcb, result);
	}
}

static void osd_trans_stop_cb(struct osd_thandle *oh, int result)
{
	struct thandle *th = &oh->ot_super;
	struct dt_txn_commit_cb *dcb, *tmp;

	/* call per-transaction stop callbacks if any */
	list_for_each_entry_safe(dcb, tmp, &oh->ot_stop_dcb_list,
				 dcb_linkage) {
		LASSERTF(dcb->dcb_magic == TRANS_COMMIT_CB_MAGIC,
			 "commit callback entry: magic=%x name='%s'\n",
			 dcb->dcb_magic, dcb->dcb_name);
		list_del_init(&dcb->dcb_linkage);
		dcb->dcb_func(NULL, th, dcb, result);
	}
}

static int osd_trans_stop(const struct lu_env *env, struct dt_device *dt,
			  struct thandle *th)
{
	struct osd_thandle *oh;
	int rc = 0;

	ENTRY;
	TRANS_STOP(th);

	oh = container_of_safe(th, struct osd_thandle, ot_super);
	osd_trans_stop_cb(oh, rc);
	osd_trans_commit_cb(oh, rc);
	OBD_FREE_PTR(oh);

	RETURN(rc);
}

static struct thandle *osd_trans_create(const struct lu_env *env,
					struct dt_device *dt)
{
	struct osd_thandle *oh;
	struct thandle *th;

	ENTRY;

	OBD_ALLOC_PTR(oh);
	if (!oh)
		RETURN(ERR_PTR(-ENOMEM));

	th = &oh->ot_super;
	th->th_dev = dt;
	th->th_result = 0;
	INIT_LIST_HEAD(&oh->ot_commit_dcb_list);
	INIT_LIST_HEAD(&oh->ot_stop_dcb_list);

	/* Random number to track osd_object */
	get_random_bytes(&oh->ot_tracking_num, sizeof(int));

	TRANS_START(th);
	RETURN(th);
}

int osd_statfs(const struct lu_env *env, struct dt_device *d,
	       struct obd_statfs *osfs, struct obd_statfs_info *info)
{
	uint64_t bshift;

	ENTRY;

	memset(osfs, 0, sizeof(*osfs));

	osfs->os_type = OSD_MAGIC;
	osfs->os_bsize = ONE_MB_BRW_SIZE;
	bshift = fls64(osfs->os_bsize) - 1;

	osfs->os_blocks = (ONE_MB_BRW_SIZE * OSD_BLK_SIZE) >> bshift;
	osfs->os_bfree = (ONE_MB_BRW_SIZE * OSD_BLK_SIZE) >> bshift;
	osfs->os_bavail = (ONE_MB_BRW_SIZE * OSD_BLK_SIZE) >> bshift;

	osfs->os_ffree = 1024 * 1024;
	osfs->os_files = osfs->os_ffree + osd_get_object_count();

	osfs->os_namelen = MAXNAMELEN;
	osfs->os_maxbytes = OBD_OBJECT_EOF;

	RETURN(0);
}

static void osd_conf_get(const struct lu_env *env,
			 const struct dt_device *dev,
			 struct dt_device_param *param)
{
	struct osd_device *osd = osd_dev(dev);

	ENTRY;

	param->ddp_max_name_len	= MAXNAMELEN;
	param->ddp_max_nlink = 1 << 31;
	param->ddp_symlink_max = PATH_MAX;
	param->ddp_mount_type = LDD_MT_MEM;
	param->ddp_mntopts = MNTOPT_USERXATTR;
	param->ddp_max_extent_blks = OSD_BLK_SIZE;
	param->ddp_extent_tax = 6 * OSD_BLK_SIZE;

	if (osd->od_posix_acl)
		param->ddp_mntopts |= MNTOPT_ACL;

	param->ddp_max_ea_size = OBD_MAX_EA_SIZE;
	param->ddp_maxbytes = MAX_LFS_FILESIZE;
	param->ddp_inodespace = 4096;
	param->ddp_brw_size = ONE_MB_BRW_SIZE;

	EXIT;
}

static int osd_ro(const struct lu_env *env, struct dt_device *d)
{
	NOT_IMPLEMENTED(0);
}

static int osd_reserve_or_free_quota(const struct lu_env *env,
				     struct dt_device *dev,
				     struct lquota_id_info *qi)
{
	NOT_IMPLEMENTED(0);
}

/*
 * We write everything to physical memory, therefore we have nothing
 * to sync.
 */
static int osd_sync(const struct lu_env *env, struct dt_device *d)
{
	NOT_IMPLEMENTED(0);
}

/*
 * We write everything to physical memory, therefore we have nothing
 * to sync.
 */
static int osd_commit_async(const struct lu_env *env, struct dt_device *dev)
{
	NOT_IMPLEMENTED(0);
}

const struct dt_device_operations osd_dt_ops = {
	.dt_root_get		  = osd_root_get,
	.dt_statfs		  = osd_statfs,
	.dt_trans_create	  = osd_trans_create,
	.dt_trans_start		  = osd_trans_start,
	.dt_trans_stop		  = osd_trans_stop,
	.dt_trans_cb_add	  = osd_trans_cb_add,
	.dt_conf_get		  = osd_conf_get,
	.dt_ro			  = osd_ro,
	.dt_reserve_or_free_quota = osd_reserve_or_free_quota,
	.dt_sync		  = osd_sync,
	.dt_commit_async	  = osd_commit_async,
};

static int osd_mount(const struct lu_env *env, struct osd_device *osd,
		     struct lustre_cfg *cfg)
{
	char *mntdev = lustre_cfg_string(cfg, 1);
	char *str = lustre_cfg_string(cfg, 2);
	char *svname = lustre_cfg_string(cfg, 4);
	time64_t interval = AS_DEFAULT;
	const char *opts;
	bool resetoi = false;
	int rc;

	ENTRY;

	if (osd->od_os)
		RETURN(0);

	if (!mntdev || !svname)
		RETURN(-EINVAL);

	rc = strscpy(osd->od_mntdev, mntdev, sizeof(osd->od_mntdev));
	if (rc < 0)
		RETURN(rc);

	rc = strscpy(osd->od_svname, svname, sizeof(osd->od_svname));
	if (rc < 0)
		RETURN(rc);

	opts = lustre_cfg_string(cfg, 3);

	osd->od_index_backup_stop = 0;
	osd->od_index = -1;
	rc = server_name2index(osd->od_svname, &osd->od_index, NULL);

	str = strstr(str, ":");
	if (str) {
		unsigned long flags;

		rc = kstrtoul(str + 1, 10, &flags);
		if (rc)
			RETURN(-EINVAL);

		if (test_bit(LMD_FLG_DEV_RDONLY, &flags)) {
			osd->od_dt_dev.dd_rdonly = 1;
			LCONSOLE_WARN("%s: set dev_rdonly on this device\n",
				      svname);
		}

		if (test_bit(LMD_FLG_NOSCRUB, &flags))
			interval = AS_NEVER;
	}

	if (server_name_is_ost(osd->od_svname))
		osd->od_is_ost = 1;

	osd->od_readcache_max_filesize = OSD_MAX_CACHE_SIZE;

	rc = lu_site_init(&osd->od_site, osd2lu_dev(osd));

	if (rc)
		goto err;

	osd->od_site.ls_bottom_dev = osd2lu_dev(osd);

	rc = lu_site_init_finish(&osd->od_site);
	if (rc)
		goto err;

	if (opts && strstr(opts, "resetoi"))
		resetoi = true;

	/* parse mount option "noacl", and enable ACL by default */
	if (!opts || !strstr(opts, "noacl"))
		osd->od_posix_acl = 1;

	RETURN(0);

err:
	RETURN(rc);
}

static void osd_fid_fini(const struct lu_env *env, struct osd_device *osd)
{
	if (osd->od_cl_seq == NULL)
		return;

	seq_client_fini(osd->od_cl_seq);
	OBD_FREE_PTR(osd->od_cl_seq);
	osd->od_cl_seq = NULL;
}

static int osd_shutdown(const struct lu_env *env, struct osd_device *o)
{
	ENTRY;
	osd_fid_fini(env, o);
	RETURN(0);
}

static int osd_process_config(const struct lu_env *env,
			      struct lu_device *d, struct lustre_cfg *cfg)
{
	struct osd_device *o = osd_dev(d);
	int count;
	int rc;

	ENTRY;

	switch (cfg->lcfg_command) {
	case LCFG_SETUP:
		rc = osd_mount(env, o, cfg);
		break;
	case LCFG_CLEANUP:
		/*
		 * For the case LCFG_PRE_CLEANUP is not called in advance,
		 * that may happen if hit failure during mount process.
		 */
		lu_dev_del_linkage(d->ld_site, d);
		rc = osd_shutdown(env, o);
		break;
	case LCFG_PARAM:
		LASSERT(&o->od_dt_dev);
		count = class_modify_config(cfg, PARAM_OSD,
					    &o->od_dt_dev.dd_kobj);
		if (count < 0)
			count = class_modify_config(cfg, PARAM_OST,
						    &o->od_dt_dev.dd_kobj);
		rc = count > 0 ? 0 : count;
		break;
	case LCFG_PRE_CLEANUP:
		rc = 0;
		break;
	default:
		CERROR("Unknown command: %d\n", cfg->lcfg_command);
		rc = -ENOSYS;
	}

	RETURN(rc);
}

static int osd_recovery_complete(const struct lu_env *env, struct lu_device *d)
{
	NOT_IMPLEMENTED(0);
}

static int osd_fid_init(const struct lu_env *env, struct osd_device *osd)
{
	struct seq_server_site *ss = osd_seq_site(osd);
	int rc = 0;

	ENTRY;
	if (osd->od_is_ost || osd->od_cl_seq != NULL)
		RETURN(0);

	if (unlikely(ss == NULL))
		RETURN(-ENODEV);

	OBD_ALLOC_PTR(osd->od_cl_seq);
	if (osd->od_cl_seq == NULL)
		RETURN(-ENOMEM);

	seq_client_init(osd->od_cl_seq, NULL, LUSTRE_SEQ_METADATA,
			osd->od_svname, ss->ss_server_seq);

	if (ss->ss_node_id == 0) {
		/*
		 * If the OSD on the sequence controller(MDT0), then allocate
		 * sequence here, otherwise allocate sequence after connected
		 * to MDT0 (see mdt_register_lwp_callback()).
		 */
		rc = seq_server_alloc_meta(osd->od_cl_seq->lcs_srv,
				   &osd->od_cl_seq->lcs_space, env);
	}

	RETURN(rc);
}

static int osd_prepare(const struct lu_env *env, struct lu_device *pdev,
		       struct lu_device *dev)
{
	struct osd_device *osd = osd_dev(dev);
	int rc = 0;

	rc = osd_fid_init(env, osd);

	RETURN(rc);
}

static int osd_fid_alloc(const struct lu_env *env, struct lu_device *d,
			 struct lu_fid *fid, struct lu_object *parent,
			 const struct lu_name *name)
{
	struct osd_device *osd = osd_dev(d);

	return seq_client_alloc_fid(env, osd->od_cl_seq, fid);
}

struct lu_object *osd_object_alloc(const struct lu_env *env,
				   const struct lu_object_header *hdr,
				   struct lu_device *ld)
{
	struct osd_object *oo;

	ENTRY;

	OBD_ALLOC_PTR(oo);
	if (oo) {
		struct lu_object *lu;
		struct lu_object_header *luh;
		struct osd_device *osd = osd_dev(ld);

		lu = &oo->oo_dt.do_lu;
		if (unlikely(osd->od_in_init)) {
			OBD_ALLOC_PTR(luh);
			if (!luh) {
				OBD_FREE_PTR(oo);
				RETURN(NULL);
			}

			lu_object_header_init(luh);
			lu_object_init(lu, luh, ld);
			lu_object_add_top(luh, lu);
			oo->oo_header = luh;
		} else {
			dt_object_init(&oo->oo_dt, NULL, ld);
			oo->oo_header = NULL;
		}

		oo->oo_dt.do_ops = &osd_obj_ops;
		lu->lo_ops = &osd_lu_obj_ops;
		init_rwsem(&oo->oo_sem);
		sema_init(&oo->oo_sem_data, 1);
		spin_lock_init(&oo->oo_guard);

		/* Random number to track osd_object */
		get_random_bytes(&oo->oo_tracking_num, sizeof(int));

		OSD_TRACE(oo);

		RETURN(lu);
	}

	RETURN(NULL);
}

const struct lu_device_operations osd_lu_ops = {
	.ldo_object_alloc	= osd_object_alloc,
	.ldo_process_config	= osd_process_config,
	.ldo_recovery_complete	= osd_recovery_complete,
	.ldo_prepare		= osd_prepare,
	.ldo_fid_alloc		= osd_fid_alloc,
};

const struct rhashtable_params osd_data_params = {
	.key_len        = sizeof(struct lu_fid),
	.key_offset     = offsetof(struct osd_data, od_fid),
	.head_offset    = offsetof(struct osd_data, od_hash),
	.hashfn         = lu_fid_hash,
	.automatic_shrinking = true,
};

static struct lu_device *osd_device_alloc(const struct lu_env *env,
					  struct lu_device_type *t,
					  struct lustre_cfg *cfg)
{
	struct osd_device *osd;
	struct lu_device *ld;
	int rc;

	ENTRY;

	OBD_ALLOC_PTR(osd);
	if (!osd)
		RETURN(ERR_PTR(-ENOMEM));

	ld = osd2lu_dev(osd);

	rc = dt_device_init(&osd->od_dt_dev, t);
	if (unlikely(rc)) {
		OBD_FREE_PTR(osd);
		goto out;
	}

	lu_env_refill((struct lu_env *)env);

	ld->ld_ops = &osd_lu_ops;
	osd->od_dt_dev.dd_ops = &osd_dt_ops;

	rc = rhashtable_init(&osd->od_data_hash,
			     &osd_data_params);
	if (rc)
		goto out;

	rc = osd_mount(env, osd, cfg);
	if (rc)
		goto out_hash_free;

	RETURN(ld);

out_hash_free:
	rhashtable_free_and_destroy(&osd->od_data_hash,
				    &osd_data_free,
				    NULL);

out:
	RETURN(ERR_PTR(rc));
}

static struct lu_device *osd_device_free(const struct lu_env *env,
					 struct lu_device *d)
{
	struct osd_device *o = osd_dev(d);

	ENTRY;

	/* XXX: make osd top device in order to release reference */
	if (d->ld_site) {
		d->ld_site->ls_top_dev = d;
		lu_site_purge(env, d->ld_site, -1);
		lu_site_print(env, d->ld_site, &d->ld_site->ls_obj_hash.nelems,
			      D_ERROR, lu_cdebug_printer);
	}

	if (o->od_site.ls_bottom_dev)
		lu_site_fini(&o->od_site);

	dt_device_fini(&o->od_dt_dev);

	rhashtable_free_and_destroy(&o->od_data_hash,
				    &osd_data_free,
				    NULL);

	OBD_FREE_PTR(o);

	RETURN(NULL);
}

static int osd_device_init(const struct lu_env *env, struct lu_device *d,
			   const char *name, struct lu_device *next)
{
	NOT_IMPLEMENTED(0);
}

static struct lu_device *osd_device_fini(const struct lu_env *env,
					 struct lu_device *d)
{
	NOT_IMPLEMENTED(NULL);
}

static const struct lu_device_type_operations osd_device_type_ops = {
	.ldto_device_alloc	= osd_device_alloc,
	.ldto_device_free	= osd_device_free,

	.ldto_device_init	= osd_device_init,
	.ldto_device_fini	= osd_device_fini
};

static struct lu_device_type osd_device_type = {
	.ldt_tags     = LU_DEVICE_DT,
	.ldt_name     = LUSTRE_OSD_MEM_NAME,
	.ldt_ops      = &osd_device_type_ops,
	.ldt_ctx_tags = LCT_LOCAL
};

static int osd_obd_connect(const struct lu_env *env, struct obd_export **exp,
			   struct obd_device *obd, struct obd_uuid *cluuid,
			   struct obd_connect_data *data, void *localdata)
{
	struct osd_device *osd = osd_dev(obd->obd_lu_dev);
	struct lustre_handle conn;
	int rc;

	ENTRY;

	CDEBUG(D_CONFIG, "connect #%d\n", osd->od_connects);

	rc = class_connect(&conn, obd, cluuid);
	if (rc)
		RETURN(rc);

	*exp = class_conn2export(&conn);
	osd->od_connects++;

	RETURN(0);
}

static int osd_obd_disconnect(struct obd_export *exp)
{
	struct obd_device *obd = exp->exp_obd;
	struct osd_device *osd = osd_dev(obd->obd_lu_dev);
	int rc, release = 0;

	ENTRY;

	osd->od_connects--;
	if (osd->od_connects == 0)
		release = 1;

	rc = class_disconnect(exp);

	if (rc == 0 && release)
		class_manual_cleanup(obd);

	RETURN(rc);
}

static const struct obd_ops osd_obd_device_ops = {
	.o_owner	= THIS_MODULE,
	.o_connect	= osd_obd_connect,
	.o_disconnect	= osd_obd_disconnect,
};

static int __init osd_init(void)
{
	return class_register_type(&osd_obd_device_ops, NULL, true,
				   LUSTRE_OSD_MEM_NAME, &osd_device_type);
}

static void __exit osd_exit(void)
{
	class_unregister_type(LUSTRE_OSD_MEM_NAME);
}

module_param(verbose_debug, int, 0644);
MODULE_PARM_DESC(verbose_debug, "Dump debug logs to kernel log.");

MODULE_AUTHOR("Timothy Day");
MODULE_DESCRIPTION("Lustre In-Memory Object Storage Device");
MODULE_VERSION(LUSTRE_VERSION_STRING);
MODULE_LICENSE("GPL");

module_init(osd_init);
module_exit(osd_exit);
