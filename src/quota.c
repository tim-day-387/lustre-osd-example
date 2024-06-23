// SPDX-License-Identifier: GPL-2.0

/*
 * Author: Timothy Day <tday141@gmail.com>
 */

#include <dt_object.h>
#include <lustre_quota.h>
#include <obd.h>

#include "common.h"

static int osd_acct_index_lookup(const struct lu_env *env,
				 struct dt_object *dtobj,
				 struct dt_rec *dtrec,
				 const struct dt_key *dtkey)
{
	ENTRY;
	RETURN(0);
}

static struct dt_it *osd_it_acct_init(const struct lu_env *env,
				      struct dt_object *dt,
				      __u32 attr)
{
	ENTRY;
	RETURN(NULL);
}

static void osd_it_acct_fini(const struct lu_env *env, struct dt_it *di)
{
	ENTRY;
	EXIT;
}

static int osd_it_acct_next(const struct lu_env *env, struct dt_it *di)
{
	ENTRY;
	RETURN(0);
}

static struct dt_key *osd_it_acct_key(const struct lu_env *env,
				      const struct dt_it *di)
{
	ENTRY;
	RETURN(NULL);
}

static int osd_it_acct_key_size(const struct lu_env *env,
				const struct dt_it *di)
{
	ENTRY;
	RETURN(0);
}

static int osd_it_acct_rec(const struct lu_env *env,
			   const struct dt_it *di,
			   struct dt_rec *dtrec, __u32 attr)
{
	ENTRY;
	RETURN(0);
}

static __u64 osd_it_acct_store(const struct lu_env *env,
			       const struct dt_it *di)
{
	ENTRY;
	RETURN(0);
}

static int osd_it_acct_load(const struct lu_env *env,
			    const struct dt_it *di, __u64 hash)
{
	ENTRY;
	RETURN(0);
}

static int osd_it_acct_get(const struct lu_env *env, struct dt_it *di,
			   const struct dt_key *key)
{
	ENTRY;
	RETURN(0);
}

static void osd_it_acct_put(const struct lu_env *env, struct dt_it *di)
{
	ENTRY;
	EXIT;
}

const struct dt_index_operations osd_acct_index_ops = {
	.dio_lookup = osd_acct_index_lookup,
	.dio_it     = {
		.init		= osd_it_acct_init,
		.fini		= osd_it_acct_fini,
		.get		= osd_it_acct_get,
		.put		= osd_it_acct_put,
		.next		= osd_it_acct_next,
		.key		= osd_it_acct_key,
		.key_size	= osd_it_acct_key_size,
		.rec		= osd_it_acct_rec,
		.store		= osd_it_acct_store,
		.load		= osd_it_acct_load
	}
};
