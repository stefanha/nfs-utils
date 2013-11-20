/*
  mydaemon.c

  Copyright (c) 2000 The Regents of the University of Michigan.
  All rights reserved.

  Copyright (c) 2000 Dug Song <dugsong@UMICH.EDU>.
  Copyright (c) 2002 Andy Adamson <andros@UMICH.EDU>.
  Copyright (c) 2002 Marius Aamodt Eriksen <marius@UMICH.EDU>.
  Copyright (c) 2002 J. Bruce Fields <bfields@UMICH.EDU>.
  Copyright (c) 2013 Jeff Layton <jlayton@redhat.com>

  All rights reserved, all wrongs reversed.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:

  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in the
     documentation and/or other materials provided with the distribution.
  3. Neither the name of the University nor the names of its
     contributors may be used to endorse or promote products derived
     from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xlog.h>

/**
 * mydaemon - daemonize, but have parent wait to exit
 * @nochdir:	skip chdir()'ing the child to / after forking if true
 * @noclose:	skip closing stdin/stdout/stderr if true
 * @pipefds:	pointer to 2 element array of pipefds
 *
 * This function is like daemon(), but with our own special sauce to delay
 * the exit of the parent until the child is set up properly. A pipe is created
 * between parent and child. The parent process will wait to exit until the
 * child dies or writes a '1' on the pipe signaling that it started
 * successfully.
 */
void
mydaemon(int nochdir, int noclose, int *pipefds)
{
	int pid, status, tempfd;

	if (pipe(pipefds) < 0) {
		xlog_err("mydaemon: pipe() failed: errno %d (%s)\n",
			 errno, strerror(errno));
		exit(1);
	}
	if ((pid = fork ()) < 0) {
		xlog_err("mydaemon: fork() failed: errno %d (%s)\n",
			 errno, strerror(errno));
		exit(1);
	}

	if (pid != 0) {
		/*
		 * Parent. Wait for status from child.
		 */
		close(pipefds[1]);
		if (read(pipefds[0], &status, 1) != 1)
			exit(1);
		exit (0);
	}
	/* Child.	*/
	close(pipefds[0]);
	setsid ();
	if (nochdir == 0) {
		if (chdir ("/") == -1) {
			xlog_err("mydaemon: chdir() failed: errno %d (%s)\n",
				 errno, strerror(errno));
			exit(1);
		}
	}

	while (pipefds[1] <= 2) {
		pipefds[1] = dup(pipefds[1]);
		if (pipefds[1] < 0) {
			xlog_err("mydaemon: dup() failed: errno %d (%s)\n",
				 errno, strerror(errno));
			exit(1);
		}
	}

	if (noclose == 0) {
		tempfd = open("/dev/null", O_RDWR);
		if (tempfd >= 0) {
			dup2(tempfd, 0);
			dup2(tempfd, 1);
			dup2(tempfd, 2);
			close(tempfd);
		} else {
			xlog_err("mydaemon: can't open /dev/null: errno %d "
				 "(%s)\n", errno, strerror(errno));
			exit(1);
		}
	}

	return;
}

/**
 * release_parent - tell the parent that it can exit now
 * @pipefds:	pipefd array that was previously passed to mydaemon()
 *
 * This function tells the parent process of mydaemon() that it's now clear
 * to exit(0).
 */
void
release_parent(int *pipefds)
{
	int status;

	if (pipefds[1] > 0) {
		if (write(pipefds[1], &status, 1) != 1) {
			xlog_err("WARN: writing to parent pipe failed: errno "
				 "%d (%s)\n", errno, strerror(errno));
		}
		close(pipefds[1]);
		pipefds[1] = -1;
	}
}

