/*
  Copyright (c) 2004 The Regents of the University of Michigan.
  All rights reserved.

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

#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <string.h>
#include "err_util.h"

static int verbosity = 0;
static int fg = 0;

static char message_buf[500];
static char tmp_buf[500];

void initerr(char *progname, int set_verbosity, int set_fg)
{
	verbosity = set_verbosity;
	fg = set_fg;
	if (!fg)
		openlog(progname, LOG_PID, LOG_DAEMON);
}

void printerr(int priority, char *format, ...)
{
	va_list args;
	int ret;

	/* aggregate lines: only print buffer when we get to the end of a
	 * line or run out of space: */
	va_start(args, format);
	ret = vsnprintf(tmp_buf, sizeof(tmp_buf), format, args);
	va_end(args);
	if ((ret < 0) || (ret >= sizeof(tmp_buf)))
		goto output;
	if (strlen(tmp_buf) + strlen(message_buf) + 1 > sizeof(message_buf))
			goto output;
	strcat(message_buf, tmp_buf);
	if (tmp_buf[strlen(tmp_buf) - 1] == '\n')
		goto output;
	return;
output:
	priority -= verbosity;
	if (priority < 0)
		priority = 0;
	if (fg) {
		if (priority == 0)
			fprintf(stderr, "%s", message_buf);
	} else {
		int sys_pri;
		switch (priority) {
			case 0:
				sys_pri = LOG_ERR;
				break;
			case 1:
				sys_pri = LOG_DEBUG;
				break;
			default:
				goto out;
		}
		syslog(sys_pri, "%s", message_buf);
	}
out:
	memset(message_buf, 0, sizeof(message_buf));
}
