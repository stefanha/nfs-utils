/*
 * Copyright (C) 1995, 1997, 1999 Jeffrey A. Uphoff
 * Modified by Olaf Kirch, 1996.
 *
 * NSM for Linux.
 */

#include "config.h"
#include <netdb.h>
#include "statd.h"

/* 
 * Services SM_STAT requests.
 *
 * According the the X/Open spec's on this procedure: "Implementations
 * should not rely on this procedure being operative.  In many current
 * implementations of the NSM it will always return a 'STAT_FAIL'
 * status."  My implementation is operative; it returns 'STAT_SUCC'
 * whenever it can resolve the hostname that it's being asked to
 * monitor, and returns 'STAT_FAIL' otherwise.
 */
struct sm_stat_res * 
sm_stat_1_svc (struct sm_name *argp, struct svc_req *rqstp)
{
  static sm_stat_res result;

  if (gethostbyname (argp->mon_name) == NULL) {
    log (L_WARNING, "gethostbyname error for %s", argp->mon_name);
    result.res_stat = STAT_FAIL;
    dprintf (L_DEBUG, "STAT_FAIL for %s", argp->mon_name);
  } else {
    result.res_stat = STAT_SUCC;
    dprintf (L_DEBUG, "STAT_SUCC for %s", argp->mon_name);
  }
  result.state = MY_STATE;
  return(&result);
}
