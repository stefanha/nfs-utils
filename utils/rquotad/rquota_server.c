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
#define _LINUX_QUOTA_VERSION 1

#include <rpc/rpc.h>
#include "rquota.h"
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/quota.h>
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
   struct dqblk dq_dqb;
   struct mntent *mnt;
   char *pathname, *qfpathname;
   int fd, err, id, type;
   struct stat stm, stn;
   struct rquota *rquota;

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
         rquota->rq_bhardlimit = dq_dqb.dqb_bhardlimit;
         rquota->rq_bsoftlimit = dq_dqb.dqb_bsoftlimit;;
         rquota->rq_curblocks = dq_dqb.dqb_curblocks;
         rquota->rq_fhardlimit = dq_dqb.dqb_ihardlimit;
         rquota->rq_fsoftlimit = dq_dqb.dqb_isoftlimit;
         rquota->rq_curfiles = dq_dqb.dqb_curinodes;
         rquota->rq_btimeleft = dq_dqb.dqb_btime;
         rquota->rq_ftimeleft = dq_dqb.dqb_itime;

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
