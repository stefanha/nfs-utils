/*
 * QUOTA    An implementation of the diskquota system for the LINUX
 *          operating system. QUOTA is implemented using the BSD systemcall
 *          interface as the means of communication with the user level.
 *          Should work for all filesystems because of integration into the
 *          VFS layer of the operating system.
 *          This is based on the Melbourne quota system wich uses both user and
 *          group quota files.
 *
 *          This part does the lookup of the info.
 *
 * Version: $Id: rquota_server.c,v 2.9 1996/11/17 16:59:46 mvw Exp mvw $
 *
 * Author:  Marco van Wieringen <mvw@planets.elm.net>
 *
 *          This program is free software; you can redistribute it and/or
 *          modify it under the terms of the GNU General Public License
 *          as published by the Free Software Foundation; either version
 *          2 of the License, or (at your option) any later version.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <rpc/rpc.h>
#include "rquota.h"
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/param.h>
/* Unfortunately we cannot trust sys/quota.h to have
 * what we need, either the old interface could be missing
 * (SLES9) or the new (SLES8 and others).
 * So we will just put it explicitly below
 */
#if 0
#include <sys/quota.h>
#endif
#include <sys/mount.h>
#include <dirent.h>
#include <paths.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "mntent.h"
#include "xmalloc.h"

#define TYPE_EXTENDED	0x01
#define ACTIVE		0x02

#ifndef MNTTYPE_AUTOFS
#define MNTTYPE_AUTOFS	"autofs"
#endif

#ifndef BLOCK_SIZE
#define BLOCK_SIZE 1024
#endif

#define MAXQUOTAS 2
#define USRQUOTA  0		/* element used for user quotas */
#define GRPQUOTA  1		/* element used for group quotas */

struct dqblk {
	u_int32_t dqb_bhardlimit;   /* absolute limit on disk blks alloc */
	u_int32_t dqb_bsoftlimit;   /* preferred limit on disk blks */
	u_int32_t dqb_curblocks;    /* current block count */
	u_int32_t dqb_ihardlimit;   /* maximum # allocated inodes */
	u_int32_t dqb_isoftlimit;   /* preferred inode limit */
	u_int32_t dqb_curinodes;    /* current # allocated inodes */
	time_t dqb_btime;           /* time limit for excessive disk use */
	time_t dqb_itime;           /* time limit for excessive files */
};

struct if_dqblk {
        u_int64_t dqb_bhardlimit;
        u_int64_t dqb_bsoftlimit;
        u_int64_t dqb_curspace;
        u_int64_t dqb_ihardlimit;
        u_int64_t dqb_isoftlimit;
        u_int64_t dqb_curinodes;
        u_int64_t dqb_btime;
        u_int64_t dqb_itime;
        u_int32_t dqb_valid;
};

#define SUBCMDMASK  0x00ff
#define SUBCMDSHIFT 8
#define QCMD(cmd, type)  (((cmd) << SUBCMDSHIFT) | ((type) & SUBCMDMASK))

#define Q_GETQUOTA 0x0300	/* get limits and usage */
#define Q_SETQUOTA 0x0400	/* set limits and usage */

#define Q_GETFMT   0x800004     /* get quota format used on given filesystem */
#define Q_GETQUOTA_NEW 0x800007 /* get user quota structure */
#define Q_SETQUOTA_NEW 0x800008 /* set user quota structure */
#define dqoff(UID)      ((loff_t)((UID) * sizeof (struct dqblk)))

extern int quotactl (int __cmd, const char *__special, int __id,
		     caddr_t __addr) __THROW;
/*
 * Global unix authentication credentials.
 */
extern struct authunix_parms *unix_cred;

int in_group (gid_t *gids, u_int len, gid_t gid)
{
   int cnt = 0;

   while (cnt < len) {
      if (gids[cnt] == gid)
         return 1;
      cnt++;
   }
   return 0;
}

getquota_rslt *getquotainfo(int flags, caddr_t *argp, struct svc_req *rqstp)
{
   static getquota_rslt result;
   union {
      getquota_args *args;
      ext_getquota_args *ext_args;
   } arguments;
   FILE *fp;
   struct mntent *mnt;
   char *pathname, *qfpathname;
   int fd, err, id, type;
   struct stat stm, stn;
   struct rquota *rquota;
   struct if_dqblk dqb;

   /*
    * First check authentication.
    */
   if (flags & TYPE_EXTENDED) {
      arguments.ext_args = (ext_getquota_args *)argp;
      id = arguments.ext_args->gqa_id;
      type = arguments.ext_args->gqa_type;
      pathname = arguments.ext_args->gqa_pathp;

      if (type == USRQUOTA && unix_cred->aup_uid && unix_cred->aup_uid != id) {
         result.status = Q_EPERM;
         return(&result);
      }

      if (type == GRPQUOTA && unix_cred->aup_uid && unix_cred->aup_gid != id &&
          !in_group((gid_t *)unix_cred->aup_gids, unix_cred->aup_len, id)) {
         result.status = Q_EPERM;
         return(&result);
      }
   } else {
      arguments.args = (getquota_args *)argp;
      id = arguments.args->gqa_uid;
      type = USRQUOTA;
      pathname = arguments.args->gqa_pathp;

      if (unix_cred->aup_uid && unix_cred->aup_uid != id) {
         result.status = Q_EPERM;
         return(&result);
      }
   }

   fp = setmntent(MNTTAB, "r");
   while ((mnt = getmntent(fp)) != (struct mntent *)0) {
      if (stat(mnt->mnt_dir, &stm) == -1)
	  continue;

      if (stat(pathname, &stn) == -1)
	  break;
      else if (stm.st_dev != stn.st_dev)
	  continue;

      if (mnt->mnt_fsname [0] != '/'
	  || strcasecmp (mnt->mnt_type, MNTTYPE_NFS) == 0
	  || strcasecmp (mnt->mnt_type, MNTTYPE_AUTOFS) == 0
	  || strcasecmp (mnt->mnt_type, MNTTYPE_SWAP) == 0
	  || strcasecmp (mnt->mnt_type, MNTTYPE_IGNORE) == 0)
         break;

      /* All blocks reported are in BLOCK_SIZE. */
      result.getquota_rslt_u.gqr_rquota.rq_bsize = BLOCK_SIZE;

      if (hasquota(mnt, type, &qfpathname)) {
	      int fmt;
	      if (quotactl(QCMD(Q_GETFMT, type), mnt->mnt_fsname, 0, (caddr_t)&fmt)==0) {
		      /* new style interface
		       * Don't bother trying to read from the file
		       */
		      err = quotactl(QCMD(Q_GETQUOTA_NEW, type),
				     mnt->mnt_fsname, id, (caddr_t)&dqb);
		      if (err) memset(&dqb, 0, sizeof(dqb));
	      } else {
		      /* old style */
		      struct dqblk dq_dqb;

		      if ((err = quotactl(QCMD(Q_GETQUOTA, type), mnt->mnt_fsname,
					  id, (caddr_t)&dq_dqb)) == -1
			  && !(flags & ACTIVE)) {
			      if ((fd = open(qfpathname, O_RDONLY)) < 0)
			      {
				      free(qfpathname);
				      continue;
			      }
			      free(qfpathname);
			      lseek(fd, (long) dqoff(id), L_SET);
			      switch (read(fd, &dq_dqb, sizeof(struct dqblk))) {
			      case 0:/* EOF */
				      /*
				       * Convert implicit 0 quota (EOF) into an
				       * explicit one (zero'ed dqblk)
				       */
				      memset((caddr_t)&dq_dqb, 0, sizeof(struct dqblk));
				      break;
			      case sizeof(struct dqblk):   /* OK */
				      break;
			      default:   /* ERROR */
				      close(fd);
				      continue;
			      }
			      close(fd);
		      }
		      dqb.dqb_bhardlimit = dq_dqb.dqb_bhardlimit;
		      dqb.dqb_bsoftlimit = dq_dqb.dqb_bsoftlimit;
		      dqb.dqb_curspace = dq_dqb.dqb_curblocks * 1024;
		      dqb.dqb_ihardlimit = dq_dqb.dqb_ihardlimit;
		      dqb.dqb_isoftlimit = dq_dqb.dqb_isoftlimit;
		      dqb.dqb_curinodes = dq_dqb.dqb_curinodes;
		      dqb.dqb_btime = dq_dqb.dqb_btime;
		      dqb.dqb_itime = dq_dqb.dqb_itime;
	      }
         endmntent(fp);

         if (err && (flags & ACTIVE)) {
            result.status = Q_NOQUOTA;   
            return(&result);
         }

         result.status = Q_OK;   
         result.getquota_rslt_u.gqr_rquota.rq_active = (err == 0) ? TRUE : FALSE;
         /*
          * Make a copy of the info into the last part of the remote quota
          * struct might not be exactly the same on all architectures...
          */

         rquota = &result.getquota_rslt_u.gqr_rquota;
         rquota->rq_bhardlimit = dqb.dqb_bhardlimit;
         rquota->rq_bsoftlimit = dqb.dqb_bsoftlimit;;
         rquota->rq_curblocks = dqb.dqb_curspace/1024;
         rquota->rq_fhardlimit = dqb.dqb_ihardlimit;
         rquota->rq_fsoftlimit = dqb.dqb_isoftlimit;
         rquota->rq_curfiles = dqb.dqb_curinodes;
         rquota->rq_btimeleft = dqb.dqb_btime;
         rquota->rq_ftimeleft = dqb.dqb_itime;

         return(&result);
      }
   }
   endmntent(fp);

   result.status = Q_NOQUOTA;   
   return(&result);
}

getquota_rslt *rquotaproc_getquota_1(getquota_args *argp, struct svc_req *rqstp)
{
   return(getquotainfo(0, (caddr_t *)argp, rqstp));
}

getquota_rslt *rquotaproc_getactivequota_1(getquota_args *argp, struct svc_req *rqstp)
{
   return(getquotainfo(ACTIVE, (caddr_t *)argp, rqstp));
}

getquota_rslt *rquotaproc_getquota_2(ext_getquota_args *argp, struct svc_req *rqstp)
{
   return(getquotainfo(TYPE_EXTENDED, (caddr_t *)argp, rqstp));
}

getquota_rslt *rquotaproc_getactivequota_2(ext_getquota_args *argp, struct svc_req *rqstp)
{
   return(getquotainfo(TYPE_EXTENDED | ACTIVE, (caddr_t *)argp, rqstp));
}
