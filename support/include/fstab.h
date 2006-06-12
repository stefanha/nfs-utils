#ifndef _NFS_FSTAB_H
#define _NFS_FSTAB_H

#include "nfs_mntent.h"

int mtab_is_writable(void);
int mtab_does_not_exist(void);

struct mntentchn {
	struct mntentchn *nxt, *prev;
	nfs_mntent_t m;
};

struct mntentchn *mtab_head (void);
struct mntentchn *getmntoptfile (const char *file);
struct mntentchn *getmntdirbackward (const char *dir, struct mntentchn *mc);
struct mntentchn *getmntdevbackward (const char *dev, struct mntentchn *mc);

void lock_mtab (void);
void unlock_mtab (void);
void update_mtab (const char *special, nfs_mntent_t *with);

#endif /* _NFS_FSTAB_H */

