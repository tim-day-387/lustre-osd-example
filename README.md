# lustre-osd-example

Implement a simple in-memory OSD device for Lustre. This enables
Lustre servers to be run without any backing filesystem, such as
ldiskfs or openZFS.

Object Handling:
 Object data is stored in osd_data structs. Data is allocated
 in Lustre buffers. Regular objects use a single osd_buf. osd_buf
 are implemented by allocating physical pages and vmap'ing them
 into a contiguous virtual address space.

 Index objects use a linked list of lu_buf. Some indices have
 entries generated on the fly.

 Data is mapped to osd_object (which are ephemeral) via the
 Object Index (OI, in osd_oi.c).

Testing:
 A new test script, sanity-osd.sh has been provided to simplify
 OSD debugging. It allows for testing individual MGT, MDT, and OST
 targets and enables running llog unit tests against the OSD. A
 subnet of sanity.sh runs (and passes) on a full OSD mem filesystem.

Debugging:
- Added a limited amount of custom OSD debugging (to trace osd, lu,
  and dt objects along with their FIDs and state). This can be
  dumped to the kernel log via 'verbose_debug' parameter.
- Use special ENV variables to control the mount helper to enable
  fine tuned control.

Progress:
- Implemented hash table mapping FIDs to data buffers (osd_oi.c)
- Implemented osd_statfs()
- Remove LFSCK and lprocfs cruft (for now?)
- Remove osd_declare_* functions
- Multiple OSD mounts and service starts! Clients mount!
- Used generics in osd as much as possible
- Generic lu_buf operations (convert to vmmap?)
- Implemented reads/writes, index operations (dir, generic),
  and iterators
- Implemented xattr handling
- Implemented dir index!
- Correctly save attributes of osd_objects to osd_data
- All llog kunit tests pass!
- Some basic sanity.sh tests pass with MDT!
- Basic test-framework.sh support (can create FS with either
  osd-mem OSS, MDS, or both)
- Fixing many checkpatch.pl issues
- Streamline code to avoid useless stub functions, cruft
- MGT target works! (can send llogs, configurations, register
  other targets against it)
- MDT target mostly works! (can create files, dirs, symlinks)
- OSS target mostly works! (can create files, the data is the
  same after cache flush, and mount/umount)

There is a TODO file with more verbose notes and planned
documentation updates.
