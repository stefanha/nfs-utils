/*
 * Copyright (C) 1995, 1997-1999 Jeffrey A. Uphoff
 *
 * NSM for Linux.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "statd.h"
#include "notlist.h"

extern void my_svc_exit (void);


/*
 * Services SM_SIMU_CRASH requests.
 */
void *
sm_simu_crash_1_svc (void *argp, struct svc_req *rqstp)
{
  static char *result = NULL;

  note (N_WARNING, "*** SIMULATING CRASH! ***");
  my_svc_exit ();

  if (rtnl)
    nlist_kill (&rtnl);

  return ((void *)&result);
}
