/*
 * Copyright (C) 1995-1997, 1999 Jeffrey A. Uphoff
 * Modified by Olaf Kirch, 1996.
 * Modified by H.J. Lu, 1998.
 *
 * NSM for Linux.
 */

#include "config.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include "statd.h"


/* 
 * Most NSM's keep the status number in an ASCII file.  I'm keeping it
 * as an int (4-byte binary) for now...
 */
void
change_state (void)
{
  int fd, size;
  extern short int restart;
  
  if ((fd = open (SM_STAT_PATH, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR)) == -1)
    die ("open (%s): %s", SM_STAT_PATH, strerror (errno));

  if ((size = read (fd, &MY_STATE, sizeof MY_STATE)) == -1)
    die ("read (%s): %s", SM_STAT_PATH, strerror (errno));

  if (size != 0 && size != sizeof MY_STATE) {
    note (N_ERROR, "Error in status file format...correcting.");

    if (close (fd) == -1)
      die ("close (%s): %s", SM_STAT_PATH, strerror (errno));

    if ((fd = creat (SM_STAT_PATH, S_IRUSR | S_IWUSR)) == -1)
      die ("creat (%s): %s", SM_STAT_PATH, strerror (errno));
  }
  note (N_DEBUG, "New state: %u", (++MY_STATE % 2) ? MY_STATE : ++MY_STATE);

  if (lseek (fd, 0, SEEK_SET) == -1)
    die ("lseek (%s): %s", SM_STAT_PATH, strerror (errno));

  if (write (fd, &MY_STATE, sizeof MY_STATE) != sizeof MY_STATE)
    die ("write (%s): %s", SM_STAT_PATH, strerror (errno));

  if (fsync (fd) == -1)
    note (N_ERROR, "fsync (%s): %s", SM_STAT_PATH, strerror (errno));

  if (close (fd) == -1)
    note (N_ERROR, "close (%s): %s", SM_STAT_PATH, strerror (errno));

  if (MY_NAME == NULL) {
    char fullhost[SM_MAXSTRLEN + 1];
    struct hostent *hostinfo;

    if (gethostname (fullhost, SM_MAXSTRLEN) == -1)
      die ("gethostname: %s", strerror (errno));

    if ((hostinfo = gethostbyname (fullhost)) == NULL)
      note (N_ERROR, "gethostbyname error for %s", fullhost);
    else {
      strncpy (fullhost, hostinfo->h_name, sizeof (fullhost) - 1);
      fullhost[sizeof (fullhost) - 1] = '\0';
    }

    MY_NAME = xstrdup (fullhost);
  }
}


/* 
 * Fairly traditional use of two directories for this.
 */
void 
shuffle_dirs (void)
{
  DIR *nld;
  struct dirent *de;
  struct stat st;
  char *src, *dst;
  int len1, len2, len;
  
  if (stat (SM_DIR, &st) == -1 && errno != ENOENT)
    die ("stat (%s): %s", SM_DIR, strerror (errno));

  if (!S_ISDIR (st.st_mode))
    if (mkdir (SM_DIR, S_IRWXU) == -1)
      die ("mkdir (%s): %s", SM_DIR, strerror (errno));

  memset (&st, 0, sizeof st);

  if (stat (SM_BAK_DIR, &st) == -1 && errno != ENOENT)
    die ("stat (%s): %s", SM_BAK_DIR, strerror (errno));

  if (!S_ISDIR (st.st_mode))
    if (mkdir (SM_BAK_DIR, S_IRWXU) == -1)
      die ("mkdir (%s): %s", SM_BAK_DIR, strerror (errno));

  if (!(nld = opendir (SM_DIR)))
    die ("opendir (%s): %s", SM_DIR, strerror (errno));

  len1=strlen(SM_DIR);
  len2=strlen(SM_BAK_DIR);
  while ((de = readdir (nld))) {
    if (de->d_name[0] == '.')
      continue;
    len=strlen(de->d_name);
    src=xmalloc(len1+len+2);
    dst=xmalloc(len2+len+2);
    sprintf (src, "%s/%s", SM_DIR, de->d_name);
    sprintf (dst, "%s/%s", SM_BAK_DIR, de->d_name);
    if (rename (src, dst) == -1)
      die ("rename (%s to %s): %s", SM_DIR, SM_BAK_DIR, strerror (errno));
    free(src);
    free(dst);
  }
  if (closedir (nld) == -1)
    note (N_ERROR, "closedir (%s): %s", SM_DIR, strerror (errno));
}
