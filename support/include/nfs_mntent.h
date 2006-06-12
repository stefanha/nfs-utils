/*
 * 2006-06-08 Amit Gud <agud@redhat.com>
 * - Moved code snippets here from util-linux/mount/my_mntent.h
 */

#ifndef _NFS_MNTENT_H
#define _NFS_MNTENT_H

typedef struct nfs_mntent_s {
	const char *mnt_fsname;
	const char *mnt_dir;
	const char *mnt_type;
	const char *mnt_opts;
	int mnt_freq;
	int mnt_passno;
} nfs_mntent_t;

#define ERR_MAX 5

typedef struct mntFILEstruct {
	FILE *mntent_fp;
	char *mntent_file;
	int mntent_lineno;
	int mntent_errs;
	int mntent_softerrs;
} mntFILE;

mntFILE *nfs_setmntent (const char *file, char *mode);
void nfs_endmntent (mntFILE *mfp);
int nfs_addmntent (mntFILE *mfp, nfs_mntent_t *mnt);
struct nfs_mntent *my_getmntent (mntFILE *mfp);
nfs_mntent_t *nfs_getmntent (mntFILE *mfp);

#endif /* _NFS_MNTENT_H */
