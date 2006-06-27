#if 0
static char sccsid[] = "@(#)nhfsstone.c 1.22 90/05/08 Copyright (c) 1990, Legato Systems Inc";
#endif

/*
 * Copyright (c) 1990 Legato Systems Inc.
 *
 * See DISCLAIMER file for restrictions
 *
 * Ported to Linux by Olaf Kirch <okir@monad.swb.de>
 */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/vfs.h>
#include <sys/stat.h>
#include <sys/wait.h>
#ifdef BSD
#include <sys/dir.h>
#define	dirent	direct
#else
#include <dirent.h>
#endif
#include <signal.h>

#ifndef NULL
#define NULL	0
#endif

/*
 * Usage: nhfsstone [-v] [[-t secs] | [-c calls]] [-l load] [-p nprocs]
 *						[-m mixfile] [dir]...
 *
 * Generates an artifical NFS client load based on a given mix of
 * operations.
 *
 * Strategy: loop for some number of NFS calls doing a random sleep
 * followed by a call to one of the op generator routines. The routines
 * are called based on a weighting factor determined by the difference
 * between the current ops percentages (derived from kernel NFS stats)
 * and a set of default percentages or a mix supplied by the caller.
 *
 * The generator routines try very hard to guess how many NFS operations
 * they are generating so that the calling routine can keep a running
 * estimate of the number of calls and the mix to avoid having to get
 * the NFS statistics from the kernel too often.
 *
 * The operations are done in a directory that has a set of file names
 * that are long enough that they won't be cached by the name cache
 * in the kernel. The "lookup" operation steps through the names and
 * creates a file if that name does not exist, or closes and reopens it
 * if it does. This generates a table of open file descriptors. Most of the
 * other operations are done on random descriptors in the table. The "getattr"
 * operation tries to avoid the kernel attribute cache by doing "fstat"
 * system calls on random descriptors in the table. There must be enough
 * files in the directory so that, on average, the getattr operation hits
 * any file less often than once each 6 seconds (the default timeout for
 * the attributes cache).
 *
 * The parent process starts children to do the real work of generating load.
 * The parent coordinates them so that they all start at the same time, and
 * collects statistics from them when they are done. To coordinate the
 * start up, the parent waits for each child to write one byte into
 * a common log file (opened in append mode to avoid overwriting).
 * After they write a byte the children pause, and the parent send SIGUSR1
 * when it has heard from all of the kids. The children write their statistics
 * into the same common log file and the parent reads and accumulates the
 * statics and prints them out.
 *
 * This code will only compile and run on 4.X BSD based systems.
 */

#define	DEFAULT_LOAD	30		/* default calls per sec */
#define	DEFAULT_CALLS	5000		/* default number of calls */
#define	NFILES		40		/* number of test files/dir */
#define	BUFSIZE		8192		/* block size for read and write */
#define	MAXFILESIZE	32		/* size, in blocks, of large file */
#define	SAMPLETIME	5		/* secs between samples of NFS stats */
#define	NPROCS		7		/* number of children to run */


/*
 * The names of NFS operations
 */
char *Opnames[] = {
	"null", "getattr", "setattr", "root", "lookup", "readlink", "read",
	"wrcache", "write", "create", "remove", "rename", "link", "symlink",
	"mkdir", "rmdir", "readdir", "fsstat",
};

/*
 * NFS operation numbers
 *
 * Used to index the Opnames, Mix and statistics arrays.
 */
#define	NOPS		18		/* number of NFS ops */
#define	NULLCALL	0
#define	GETATTR		1
#define	SETATTR		2
#define	ROOT		3
#define	LOOKUP		4
#define	READLINK	5
#define	READ		6
#define	WRCACHE		7
#define	WRITE		8
#define	CREATE		9
#define	REMOVE		10
#define	RENAME		11
#define	LINK		12
#define	SYMLINK		13
#define	MKDIR		14
#define	RMDIR		15
#define	READDIR		16
#define	FSSTAT		17

/*
 * Operations counts
 */
struct count {
	int		total;
	int		calls[NOPS];
};

/*
 * Software development mix for server with about 50/50 mix of
 * diskless and diskful clients running SunOS 4.0.
 */
int	Mix[NOPS] = {
	0,		/* null */
	13,		/* getattr */
	1,		/* setattr */
	0,		/* root */
	34,		/* lookup */
	8,		/* readlink */
	22,		/* read */
	0,		/* wrcache */
	15,		/* write */
	2,		/* create */
	1,		/* remove */
	0,		/* rename */
	0,		/* link */
	0,		/* symlink */
	0,		/* mkdir */
	0,		/* rmdir */
	3,		/* readdir */
	1,		/* fsstat */
};

/* Prototype decls */
int	setmix(FILE *fp);
void	usage(void);
void	init_logfile(void);
void	init_counters(void);
void	get_delta(struct count *start, struct count *cur);
void	init_testdir(int dirnum, char *parentdir);
void	do_op(int rpct);
void	op(int opnum);
void	nextfile(void);
int	createfile(void);
int	openfile(void);
int	writefile(void);
void	collect_counters(void);
int	check_counters(void);
void	print(void);
void	msec_sleep(int msecs);
void	get_opct(struct count *count);
int	substr(char *sp, char *subsp);
int	check_access(struct stat statb);
void	error(char *str);

/*
 * NFS operations generator routines
 */
int	op_null();
int	op_getattr();
int	op_setattr();
int	op_root();
int	op_lookup();
int	op_readlink();
int	op_read();
int	op_wrcache();
int	op_write();
int	op_create();
int	op_remove();
int	op_rename();
int	op_link();
int	op_symlink();
int	op_mkdir();
int	op_rmdir();
int	op_readdir();
int	op_fsstat();

/*
 * Operations generator vector
 */
struct op_vect {
	int	(*funct)();	/* op */
} Op_vect[NOPS] = {
	{ op_null },
	{ op_getattr },
	{ op_setattr },
	{ op_root },
	{ op_lookup },
	{ op_readlink },
	{ op_read },
	{ op_wrcache },
	{ op_write },
	{ op_create },
	{ op_remove },
	{ op_rename },
	{ op_link },
	{ op_symlink },
	{ op_mkdir },
	{ op_rmdir },
	{ op_readdir },
	{ op_fsstat },
};

/*
 * Name sub-strings
 */
#define	DIRSTR	"dir"			/* directory */
#define	SYMSTR	"sym"			/* symbolic link */
#define	LINSTR	"lin"			/* hard link */

struct timeval	Optime[NOPS+1];		/* cumulative running time for ops */
struct count Curct;			/* total number ops called */
int	Openfd[NFILES];			/* open file descriptors */
int	Curnum;				/* current file number */
int	Symnum;				/* current symlink file number */
int	Linknum;			/* current link file number */
int	Dirnum;				/* current directory number */
DIR	*Testdir;			/* my test directory */
char	Testdirname[MAXNAMLEN*2];	/* my test directory name */
char	Curname[MAXNAMLEN];		/* current file name */
char	Dirname[MAXNAMLEN];		/* current directory name */
char	Symname[MAXNAMLEN];		/* symlink file name */
char	Linkname[MAXNAMLEN];		/* link file name */
char	*Otherspec = "%s/%03d";		/* sprintf spec for other names */
char	*Rename1 = "rename1";		/* first name of rename pair */
char	*Rename2 = "rename2";		/* second name of rename pair */
char	*Symlinkpath = "./symlinknamelongstuff";
					/* symlink file data */
char	*Myname;			/* name program invoked under */
char	Namebuf[MAXNAMLEN];		/* unique name for this program */
int	Log;				/* synchronization log */
char	Logname[MAXNAMLEN];		/* synchronization log name */
int	Kmem;				/* /dev/kmem file descriptor */
off_t	Statoffset;			/* offset to op count in NFS stats */
int	Nprocs;				/* sub-processes started */
int	Verbose;			/* print more info */
int	Testop = -1;			/* operation to test */
int	Saveerrno;			/* place to save errno */

#define	subtime(t1, t2)	{if ((t1.tv_usec -= t2.tv_usec) >= 1000000) {\
				t1.tv_sec += (t1.tv_usec / 1000000); \
				t1.tv_usec %= 1000000; \
			 } else if (t1.tv_usec < 0) { \
				t1.tv_usec += 1000000; \
				t1.tv_sec--; \
			 } \
			 t1.tv_sec -= t2.tv_sec; \
			}

#define	addtime(t1, t2)	{if ((t1.tv_usec += t2.tv_usec) >= 1000000) {\
				t1.tv_sec += (t1.tv_usec / 1000000); \
				t1.tv_usec %= 1000000; \
			 } else if (t1.tv_usec < 0) { \
				t1.tv_usec += 1000000; \
				t1.tv_sec--; \
			 } \
			 t1.tv_sec += t2.tv_sec; \
			}

/*
 * Used to catch the parent's "start" signal
 */
void
startup()
{

	return;
}

/*
 * Clean up and exit
 */
void
cleanup()
{

	(void) unlink(Logname);
	exit(1);
}

int
main(int argc, char **argv)
{
	int runtime;		/* length of run, in seconds */
	int load;		/* load factor, in client loads */
	int ncalls;		/* total number of calls to make */
	int avgmspc;		/* average millisec per call */
	int mspc;		/* millisec per call */
	int wantcalls;		/* ncalls that should have happend by now */
	int pid;		/* process id */
	int delay;		/* msecs since last checked current time */
	int randnum;		/* a random number */
#if HAVE_SIGPROCMASK
	sigset_t oldmask;	/* saved signal mask */
#else
	int oldmask;		/* saved signal mask */
#endif
	int sampletime;		/* secs between reading kernel stats */
	char *opts;		/* option parsing */
	int pct;
	int procnum;
	FILE *fp;
	struct timeval curtime;
	struct timeval starttime;
	struct count startct;
	struct stat statb;
	char workdir[MAXPATHLEN];
	char *getwd();

	Myname = argv[0];

	argc--;
	argv++;

	load = DEFAULT_LOAD;
	ncalls = 0;
	runtime = 0;
	Nprocs = NPROCS;
	pid = 0;

	(void) umask(0);

	/*
	 * Parse options
	 */
	while (argc && **argv == '-') {
		opts = &argv[0][1];
		while (*opts) {
			switch (*opts) {

			case 'c':
				/*
				 * Set number of calls
				 */
				if (!isdigit(argv[1][0])) {
					(void) fprintf(stderr,
					    "%s: illegal calls value %s\n",
					    Myname, argv[1]);
					exit(1);
				}
				ncalls = atoi(argv[1]);
				argv++;
				argc--;
				break;

			case 'l':
				/*
				 * Set load
				 */
				if (!isdigit(argv[1][0])) {
					(void) fprintf(stderr,
					    "%s: illegal load value %s\n",
					    Myname, argv[1]);
					exit(1);
				}
				load = atoi(argv[1]);
				argv++;
				argc--;
				break;

			case 'm':
				/*
				 * Set mix from a file
				 */
				if ((fp = fopen(argv[1], "r")) == NULL) {
					Saveerrno = errno;
					(void) fprintf(stderr,
					    "%s: bad mix file", Myname);
					errno = Saveerrno;
					perror("");
					exit(1);
				}
				if (setmix(fp) < 0) {
					exit(1);
				}
				(void) fclose(fp);
				argv++;
				argc--;
				break;

			case 'p':
				/*
				 * Set number of child processes
				 */
				if (!isdigit(argv[1][0])) {
					(void) fprintf(stderr,
					    "%s: illegal procs value %s\n",
					    Myname, argv[1]);
					exit(1);
				}
				Nprocs = atoi(argv[1]);
				argv++;
				argc--;
				break;

			case 'T':
				/*
				 * Set test mode, number following is opnum
				 */
				if (!isdigit(argv[1][0])) {
					(void) fprintf(stderr,
					    "%s: illegal test value %s\n",
					    Myname, argv[1]);
					exit(1);
				}
				Testop = atoi(argv[1]);
				if (Testop >= NOPS) {
					(void) fprintf(stderr,
					    "%s: illegal test value %d\n",
					    Myname, Testop);
					exit(1);
				}
				argv++;
				argc--;
				break;

			case 't':
				/*
				 * Set running time
				 */
				if (!isdigit(argv[1][0])) {
					(void) fprintf(stderr,
					    "%s: illegal time value %s\n",
					    Myname, argv[1]);
					exit(1);
				}
				runtime = atoi(argv[1]);
				argv++;
				argc--;
				break;

			case 'v':
				/*
				 * Set verbose mode
				 */
				Verbose++;
				break;

			default:
				usage();
				exit(1);

			}
			opts++;
		}
		argv++;
		argc--;
	}

	init_logfile();		/* Set up synchronizatin log file */

	if (getcwd(workdir, sizeof(workdir)) == (char *) 0) {
		Saveerrno = errno;
		(void) fprintf(stderr,
		    "%s: can't find current directory ", Myname);
		errno = Saveerrno;
		perror("");
		exit(1);
	}

	(void) signal(SIGINT, cleanup);
	(void) signal(SIGUSR1, startup);
#if HAVE_SIGPROCMASK
	{
		sigset_t mask;
		sigemptyset(&mask);
		sigaddset(&mask, SIGUSR1);
		sigprocmask(SIG_BLOCK, &mask, &oldmask);
	}
#else
	/*
	 * sigblock() is marked deprecated in modern
	 * glibc and hence generates a warning.
	 */
	oldmask = sigblock(sigmask(SIGUSR1));
#endif

	if (ncalls == 0) {
		if (runtime == 0) {
			ncalls = DEFAULT_CALLS;
		} else {
			ncalls = runtime * load;
		}
	}
	avgmspc = Nprocs * 1000 / load;

	/*
	 * Fork kids
	 */
	for (procnum = 0; procnum < Nprocs; procnum++) {
		if ((pid = fork()) == -1) {
			Saveerrno = errno;
			(void) fprintf(stderr, "%s: can't fork ", Myname);
			errno = Saveerrno;
			perror("");
			(void) kill(0, SIGINT);
			exit(1);
		}
		/*
		 * Kids go initialize
		 */
		if (pid == 0) {
			break;
		}
	}

	/*
	 * Parent: wait for kids to get ready, start them, wait for them to
	 * finish, read and accumulate results.
	 */
	if (pid != 0) {
		/*
		 * wait for kids to initialize
		 */
		do {
			sleep(1);
			if (fstat(Log, &statb) == -1) {
				(void) fprintf(stderr, "%s: can't stat log %s",
				    Myname, Logname);
				(void) kill(0, SIGINT);
				exit(1);
			}
		} while (statb.st_size != Nprocs);

		if (ftruncate(Log, 0L) == -1) {
			(void) fprintf(stderr, "%s: can't truncate log %s",
			    Myname, Logname);
			(void) kill(0, SIGINT);
			exit(1);
		}

		sync();
		sleep(3);

		/*
		 * Be sure there isn't something else going on
		 */
		get_opct(&startct);
		msec_sleep(2000);
		get_delta(&startct, &Curct);
		if (Curct.total > 20) {
			(void) fprintf(stderr,
			    "%s: too much background activity (%d calls/sec)\n",
			    Myname, Curct.total);
			(void) kill(0, SIGINT);
			exit(1);
		}

		/*
		 * get starting stats
		 */
		get_opct(&startct);

		/*
		 * Start kids
		 */
		(void) kill(0, SIGUSR1);

		/*
		 * Kids started, wait for first one to finish, signal the
		 * rest and wait for them to finish.
		 */
		if (wait((union wait *) 0) != -1) {
			(void) kill(0, SIGUSR1);
			while (wait((union wait *) 0) != -1)
				/* nothing */;
		}

		/*
		 * Initialize and sum up counters
		 */
		init_counters();
		get_delta(&startct, &Curct);
		collect_counters();
		if (check_counters() == -1) {
			Verbose = 1;
		}
		print();

		(void) close(Log);
		(void) unlink(Logname);

		exit(0);
	}

	/*
	 * Children: initialize, then notify parent through log file,
	 * wait to get signal, beat the snot out of the server, write
	 * stats to the log file, and exit.
	 */

	/*
	 * Change my name for error logging
	 */
	(void) sprintf(Namebuf, "%s%d", Myname, procnum);
	Myname = Namebuf;

	/*
	 * Initialize and cd to test directory
	 */
	if (argc != 0) {
		init_testdir(procnum, argv[procnum % argc]);
	} else {
		init_testdir(procnum, ".");
	}
	if ((Testdir = opendir(".")) == NULL) {
		Saveerrno = errno;
		(void) fprintf(stderr,
		    "%s: can't open test directory ", Myname);
		errno = Saveerrno;
		perror(Testdirname);
		exit(1);
	}

	init_counters();
	srandom(procnum+1);

	/*
	 * Tell parent I'm ready then wait for go ahead
	 */
	if (write(Log, " ", 1) != 1) {
		(void) fprintf(stderr, "%s: can't write sync file %s",
		    Myname, Logname);
		(void) kill(0, SIGINT);
		exit(1);
	}

#if HAVE_SIGPROCMASK
	sigsuspend(&oldmask);
#else
	sigpause(oldmask);
#endif

	/*
	 * Initialize counters
	 */
	get_opct(&startct);
	(void) gettimeofday(&starttime, (struct timezone *)NULL);
	sampletime = starttime.tv_sec + ((int) random()) % (2 * SAMPLETIME);
	curtime = starttime;

	/*
	 * Do pseudo NFS operations and adapt to dynamic changes in load
	 * by adjusting the sleep time between operations based on the
	 * number of calls that should have occured since starttime and
	 * the number that have actually occured.  A delay is used to avoid
	 * doing gettimeofday calls too often, and a sampletime is
	 * used to avoid reading kernel NFS stats too often.
	 * If parent interrupts, get out and clean up.
	 */
	delay = 0;
	mspc = avgmspc;
	for (;;) {
		randnum = (int) random();
		if (mspc > 0) {
			msec_sleep(randnum % (mspc << 1));
		}

		/*
		 * Do the NFS operation
		 * We use a random number from 0-199 to avoid starvation
		 * of the operations at the end of the mix.
		 */
		do_op(randnum % 200);

		/*
		 * Do a gettimeofday call only once per second
		 */
		delay += mspc;
		if (delay > 1000 || Curct.total >= ncalls) {
			delay = 0;
			(void) gettimeofday(&curtime, (struct timezone *)NULL);

			/*
			 * If sample time is up, check the kernel stats
			 * and adjust our parameters to either catch up or
			 * slow down.
			 */
			if (curtime.tv_sec > sampletime ||
			    Curct.total >= ncalls) {
				sampletime = curtime.tv_sec + SAMPLETIME;
				get_delta(&startct, &Curct);
				if (Curct.total >= ncalls) {
					break;
				}
				wantcalls =
				    ((curtime.tv_sec - starttime.tv_sec) * 1000
				    +(curtime.tv_usec-starttime.tv_usec) / 1000)
				    * Nprocs / avgmspc;
				pct = 1000 * (Curct.total - wantcalls) / ncalls;
				mspc = avgmspc + avgmspc * pct / 20;
				if (mspc <= 0) {
					/*
					 * mspc must be positive or we will
					 * never advance time.
					 */
					mspc = 10;
				}
			}
		}
	}

	/*
	 * Store total time in last slot of counts array
	 */
	Optime[NOPS].tv_sec = curtime.tv_sec - starttime.tv_sec;
	Optime[NOPS].tv_usec = curtime.tv_usec - starttime.tv_usec;

	/*
	 * write stats to log file (append mode)
	 */
	if (write(Log, (char *)Optime, sizeof (Optime)) == -1) {
		Saveerrno = errno;
		(void) fprintf(stderr, "%s: can't write log ", Myname);
		errno = Saveerrno;
		perror("");
		(void) kill(0, SIGINT);
		exit(1);
	}
	(void) close(Log);

	exit(0);
}

/*
 * Initialize test directory
 *
 * If the directory already exists, check to see that all of the
 * files exist and we can write them.  If directory doesn't exist
 * create it and fill it using the LOOKUP and WRITE ops.
 * Chdir to the directory.
 */
void
init_testdir(int dirnum, char *parentdir)
{
	int i;
	int fd;
	char cmd[256];
	struct stat statb;

	(void) sprintf(Testdirname, "%s/testdir%d", parentdir, dirnum);
	if (stat(Testdirname, &statb) == -1) {
		if (mkdir(Testdirname, 0777) == -1) {
			Saveerrno = errno;
			(void) fprintf(stderr,
			    "%s: can't create test directory ", Myname);
			errno = Saveerrno;
			perror(Testdirname);
			(void) kill(0, SIGINT);
			exit(1);
		}
		if (chdir(Testdirname) == -1) {
			Saveerrno = errno;
			(void) fprintf(stderr,
			    "%s: can't cd to test directory ", Myname);
			errno = Saveerrno;
			perror(Testdirname);
			(void) kill(0, SIGINT);
			exit(1);
		}

		/*
		 * create some files with long names and average size
		 */
		for (i = 0; i < NFILES; i++) {
			nextfile();
			(void) createfile();
			if (Openfd[Curnum] == 0 || writefile() == 0) {
				Saveerrno = errno;
				(void) fprintf(stderr,
				    "%s: can't create test file '%s'\n",
				    Myname, Curname);
				errno = Saveerrno;
				perror(Testdirname);
				(void) kill(0, SIGINT);
				exit(1);
			}
		}
	} else {
		if (chdir(Testdirname) == -1) {
			Saveerrno = errno;
			(void) fprintf(stderr,
			    "%s: can't cd to test directory ", Myname);
			errno = Saveerrno;
			perror(Testdirname);
			(void) kill(0, SIGINT);
			exit(1);
		}

		/*
		 * Verify that we can read and write the test dir
		 */
		if (check_access(statb) == -1) {
			(void) fprintf(stderr,
			    "%s: wrong permissions on test dir %s\n",
			    Myname, Testdirname);
			(void) kill(0, SIGINT);
			exit(1);
		}

		/*
		 * Verify that we can read and write all the files
		 */
		for (i = 0; i < NFILES; i++) {
			nextfile();
			if (stat(Curname, &statb) == -1 || statb.st_size == 0) {
				/*
				 * File doesn't exist or is 0 size
				 */
				(void) createfile();
				if (Openfd[Curnum] == 0 || writefile() == 0) {
					(void) kill(0, SIGINT);
					exit(1);
				}
			} else if (check_access(statb) == -1) {
				/*
				 * should try to remove and recreate it
				 */
				(void) fprintf(stderr,
				    "%s: wrong permissions on testfile %s\n",
				    Myname, Curname);
				(void) kill(0, SIGINT);
				exit(1);
			} else if (Openfd[Curnum] == 0) {
				(void) openfile();
				if (Openfd[Curnum] == 0) {
					(void) kill(0, SIGINT);
					exit(1);
				}
			}
		}
	}

	/*
	 * Start with Rename1 and no Rename2 so the
	 * rename op can ping pong back and forth.
	 */
	(void) unlink(Rename2);
	if ((fd = open(Rename1, O_CREAT|O_TRUNC|O_RDWR, 0666)) == -1) {
		Saveerrno = errno;
		(void) fprintf(stderr, "%s: can't create rename file ", Myname);
		errno = Saveerrno;
		perror(Rename1);
		(void) kill(0, SIGINT);
		exit(1);
	}

	/*
	 * Remove and recreate the test sub-directories
	 * for mkdir symlink and hard link.
	 */
	(void) sprintf(cmd, "rm -rf %s %s %s", DIRSTR, SYMSTR, LINSTR);
	if (system(cmd) != 0) {
		(void) fprintf(stderr, "%s: can't %s\n", Myname, cmd);
		(void) kill(0, SIGINT);
		exit(1);
	}

	if (mkdir(DIRSTR, 0777) == -1) {
		(void) fprintf(stderr,
		    "%s: can't create subdir %s\n", Myname, DIRSTR);
		(void) kill(0, SIGINT);
		exit(1);
	}

	if (mkdir(SYMSTR, 0777) == -1) {
		(void) fprintf(stderr,
		    "%s: can't create subdir %s\n", Myname, SYMSTR);
		(void) kill(0, SIGINT);
		exit(1);
	}
	op(SYMLINK);

	if (mkdir(LINSTR, 0777) == -1) {
		(void) fprintf(stderr, "%s: can't create subdir %s\n", Myname,
		    LINSTR);
		(void) kill(0, SIGINT);
		exit(1);
	}

	(void) close(fd);
}

/*
 * The routines below attempt to do over-the-wire operations.
 * Each op tries to cause one or more of a particular
 * NFS operation to go over the wire.  OPs return the number
 * of OTW calls they think they have generated.
 *
 * An array of open file descriptors is kept for the files in each
 * test directory. The open fd's are used to get access to the files
 * without generating lookups. An fd value of 0 mean the corresponding
 * file name is closed.  Ops that need a name use Curname.
 */

/*
 * Call an op based on a random number and the current
 * op calling weights. Op weights are derived from the
 * mix percentage and the current NFS stats mix percentage.
 */
void
do_op(int rpct)
{
	int opnum;
	int weight;
	int oppct;

	if (Testop != -1) {
		nextfile();
		op(Testop);
		return;
	}
	for (opnum = rpct % NOPS; rpct >= 0; opnum = (opnum + 1) % NOPS) {
		if (Curct.total) {
			oppct = (Curct.calls[opnum] * 100) / Curct.total;
		} else {
			oppct = 0;
		}
		/*
		 * Weight is mix percent - (how far off we are * fudge)
		 * fudge factor is required because some ops (read, write)
		 * generate many NFS calls for a single op call
		 */
		weight = Mix[opnum] - ((oppct - Mix[opnum]) << 4);
		if (weight <= 0) {
			continue;
		}
		rpct -= weight;
		if (rpct < 0) {
			if (opnum == RMDIR && Dirnum == 0) {
				op(MKDIR);
			} else if (opnum != CREATE && opnum != LOOKUP &&
			    opnum != REMOVE) {
				nextfile();
			}
			op(opnum);
			if (Openfd[Curnum] == 0) {
				op(CREATE);
#ifdef XXX
				op(WRITE);
#endif /* XXX */
			}
			return;
		}
	}
}

/*
 * Call an op generator and keep track of its running time
 */
void
op(int opnum)
{
	struct timeval start;
	struct timeval stop;
	int nops;

	(void) gettimeofday(&start, (struct timezone *)NULL);
	nops = (*Op_vect[opnum].funct)();
	(void) gettimeofday(&stop, (struct timezone *)NULL);
	stop.tv_sec -= start.tv_sec;
	stop.tv_usec -= start.tv_usec;

#ifdef SUNOS4
	/*
	 * SunOS 4.0 does a lookup and a getattr on each open
	 * so we have to account for that in the getattr op
	 */
	if (opnum == GETATTR && nops == 2) {
		nops = 1;
		stop.tv_sec /= 2;
		stop.tv_usec /= 2;
		Curct.total += Nprocs;
		Curct.calls[LOOKUP] += Nprocs;
		addtime(Optime[LOOKUP], stop);
	}
#endif

	nops *= Nprocs;
	Curct.total += nops;
	Curct.calls[opnum] += nops;
	addtime(Optime[opnum], stop);
}

/*
 * Advance file number (Curnum) and name (Curname)
 */
void
nextfile(void)
{
	static char *numpart = NULL;
	int num;

	Curnum = (Curnum + 1) % NFILES;
	if (numpart == NULL) {
		(void) sprintf(Curname, "%03dabcdefghijklmn", Curnum);
		numpart = Curname;
	} else {
		num = Curnum;
		numpart[0] = '0' + num / 100;
		num %= 100;
		numpart[1] = '0' + num / 10;
		num %= 10;
		numpart[2] = '0' + num;
	}
}

int
createfile(void)
{
	int ret;
	int fd;

	ret = 0;
	fd = Openfd[Curnum];

	if ((fd && close(fd) == -1) ||
	    (fd = open(Curname, O_CREAT|O_RDWR|O_TRUNC, 0666)) == -1) {
		fd = 0;
		ret = -1;
		error("create");
	}
	Openfd[Curnum] = fd;
	return (ret);
}

int
openfile(void)
{
	int ret;
	int fd;

	ret = 0;
	fd = Openfd[Curnum];
	if (fd == 0 && (fd = open(Curname, O_RDWR, 0666)) == -1) {
		fd = 0;
		ret = -1;
		error("open");
	}
	Openfd[Curnum] = fd;
	return (ret);
}

int
writefile(void)
{
	int fd;
	int wrote;
	int bufs;
	int size;
	int randnum;
	char buf[BUFSIZE];

	fd = Openfd[Curnum];

	if (lseek(fd, 0L, 0) == (off_t) -1) {
		error("write: lseek");
		return (-1);
	}

	randnum = (int) random();
	bufs = randnum % 100;	/* using this for distribution desired */
	/*
	 * Attempt to create a distribution of file sizes
	 * to reflect reality.  Most files are small,
	 * but there are a few files that are very large.
	 *
	 * The sprite paper (USENIX 198?) claims :
	 *	50% of all files are < 2.5K
	 *	80% of all file accesses are to files < 10K
	 *	40% of all file I/O is to files > 25K
	 *
	 * static examination of the files in our file system
	 * seems to support the claim that 50% of all files are
	 * smaller than 2.5K
	 */
	if (bufs < 50)  {
		bufs = (randnum % 3) + 1;
		size = 1024;
	} else if (bufs < 97) {
		bufs = (randnum % 6) + 1;
		size = BUFSIZE;
	} else {
		bufs = MAXFILESIZE;
		size = BUFSIZE;
	}

	for (wrote = 0; wrote < bufs; wrote++) {
		if (write(fd, buf, size) == -1) {
			error("write");
			break;
		}
	}

	return (wrote);
}

int
op_null(void)
{

	return (1);
}


/*
 * Generate a getattr call by fstat'ing the current file
 * or by closing and re-opening it. This helps to keep the
 * attribute cache cold.
 */
int
op_getattr(void)
{
	struct stat statb;

	if ((random() % 2) == 0) {
		(void) close(Openfd[Curnum]);
		Openfd[Curnum] = 0;
		if (openfile() == -1) {
			return (0);
		}
		return (2);
	}
	if (fstat(Openfd[Curnum], &statb) == -1) {
		error("getattr");
	}
	return (1);
}


int op_setattr(void)
{

	if (fchmod(Openfd[Curnum], 0666) == -1) {
		error("setattr");
	}
	return (1);
}


int op_root(void)
{

	error("root");
	return (0);
}


/*
 * Generate a lookup by stat'ing the current name.
 */
int op_lookup(void)
{
	struct stat statb;

	if (stat(Curname, &statb) == -1) {
		error("lookup");
	}
	return (1);
}


int op_read(void)
{
	int got;
	int bufs;
	int fd;
	char buf[BUFSIZE];

	bufs = 0;
	fd = Openfd[Curnum];

	if (lseek(fd, 0L, 0) == (off_t) -1) {
		error("read: lseek");
		return (0);
	}

	while ((got = read(fd, buf, sizeof (buf))) > 0) {
		bufs++;
	}

	if (got == -1) {
		error("read");
	} else {
		bufs++;		/* did one extra read to find EOF */
	}
	return (bufs);
}


int op_wrcache(void)
{
	error("wrcache");
	return 0;
}


int op_write(void)
{
	int bufs;

	bufs = writefile();
	if (bufs == 0) {
		return (0);
	}
	(void) fsync(Openfd[Curnum]);

	return (bufs + 2);
}


int op_create(void)
{

	if (createfile() == -1) {
		return (0);
	}
	return (1);
}


int op_remove(void)
{
	int fd;
	int got;

	if (Linknum > 0) {
		got = unlink(Linkname);
		Linknum--;
		(void) sprintf(Linkname, Otherspec, LINSTR, Linknum);
	} else if (Symnum > 1) {
		got = unlink(Symname);
		Symnum--;
		(void) sprintf(Symname, Otherspec, SYMSTR, Symnum);
	} else {
		fd = Openfd[Curnum];

		if (fd && (close(fd) == -1)) {
			error("remove: close");
		}
		Openfd[Curnum] = 0;
		got = unlink(Curname);
	}
	if (got == -1) {
		error("remove");
	}
	return (1);
}


int toggle = 0;

int op_rename(void)
{
	int got;

	if (toggle++ & 01) {
		got = rename(Rename2, Rename1);
	} else {
		got = rename(Rename1, Rename2);
	}
	if (got == -1) {
		error("rename");
	}
	return (1);
}


int op_link(void)
{

	Linknum++;
	(void) sprintf(Linkname, Otherspec, LINSTR, Linknum);
	if (link(Curname, Linkname) == -1) {
		error("link");
	}
	return (1);
}


int op_readlink(void)
{
	char	buf[MAXPATHLEN];

	if (Symnum == 0) {
		error("readlink");
		return (0);
	}
	if (readlink(Symname, buf, sizeof (buf)) == -1) {
		error("readlink");
	}
	return (1);
}


int op_symlink(void)
{

	Symnum++;
	(void) sprintf(Symname, Otherspec, SYMSTR, Symnum);
	if (symlink(Symlinkpath, Symname) == -1) {
		error("symlink");
	}
	return (1);
}


int op_mkdir(void)
{

	Dirnum++;
	(void) sprintf(Dirname, Otherspec, DIRSTR, Dirnum);
	if (mkdir(Dirname, 0777) == -1) {
		error("mkdir");
	}
	return (1);
}


int op_rmdir(void)
{

	if (Dirnum == 0) {
		error("rmdir");
		return (0);
	}
	if (rmdir(Dirname) == -1) {
		error("rmdir");
	}
	Dirnum--;
	(void) sprintf(Dirname, Otherspec, DIRSTR, Dirnum);
	return (1);
}


int op_readdir(void)
{

	rewinddir(Testdir);
	while (readdir(Testdir) != (struct dirent *)NULL)
		/* nothing */;
	return (1);
}


int op_fsstat(void)
{
	struct statfs statfsb;

	if (statfs(".", &statfsb) == -1) {
		error("statfs");
	}
	return (1);
}


/*
 * Utility routines
 */

/*
 * Read counter arrays out of log file and accumulate them in "Optime"
 */
void
collect_counters(void)
{
	int i;
	int j;

	(void) lseek(Log, 0L, 0);

	for (i = 0; i < Nprocs; i++) {
		struct timeval buf[NOPS+1];

		if (read(Log, (char *)buf, sizeof (buf)) == -1) {
			Saveerrno = errno;
			(void) fprintf(stderr, "%s: can't read log ", Myname);
			errno = Saveerrno;
			perror("");
			(void) kill(0, SIGINT);
			exit(1);
		}

		for (j = 0; j < NOPS+1; j++) {
			addtime(Optime[j], buf[j]);
		}
	}
}

/*
 * Check consistance of results
 */
int
check_counters(void)
{
	int i;
	int mixdiff;
	int got;
	int want;

	mixdiff = 0;
	for (i = 0; i < NOPS; i++) {
		got = Curct.calls[i] * 10000 / Curct.total;
		want = Mix[i] * 100;
		if (got > want) {
			mixdiff += got - want;
		} else {
			mixdiff += want - got;
		}
	}
	if (mixdiff > 1000) {
		(void) fprintf(stdout,
		    "%s: INVALID RUN, mix generated is off by %d.%02d%%\n",
		    Myname, mixdiff / 100, mixdiff % 100);
		return (-1);
	}
	return (0);
}

/*
 * Print results
 */
void
print(void)
{
	int totalmsec;
	int runtime;
	int msec;
	int i;

	totalmsec = 0;
	for (i = 0; i < NOPS; i++) {
		totalmsec += Optime[i].tv_sec * 1000;
		totalmsec += Optime[i].tv_usec / 1000;
	}

	if (Verbose) {
	   const char *format = sizeof (Optime[0].tv_sec) == sizeof (long)
	     ? "%-10s%3d%%    %2d.%02d%%   %6d   %4ld.%02ld    %4d.%02d    %2d.%02d%%\n"
	     : "%-10s%3d%%    %2d.%02d%%   %6d   %4d.%02d    %4d.%02d    %2d.%02d%%\n";
		(void) fprintf(stdout,
"op        want       got    calls      secs  msec/call    time %%\n");
		for (i = 0; i < NOPS; i++) {
			msec = Optime[i].tv_sec * 1000
			    + Optime[i].tv_usec / 1000;
			(void) fprintf(stdout, format,
			    Opnames[i], Mix[i],
			    Curct.calls[i] * 100 / Curct.total,
			    (Curct.calls[i] * 100 % Curct.total)
				* 100 / Curct.total,
			    Curct.calls[i],
			    Optime[i].tv_sec, Optime[i].tv_usec / 10000,
			    Curct.calls[i]
				? msec / Curct.calls[i]
				: 0,
			    Curct.calls[i]
				? (msec % Curct.calls[i]) * 100 / Curct.calls[i]
				: 0,
			    msec * 100 / totalmsec,
			    (msec * 100 % totalmsec) * 100 / totalmsec);
		}
	}

	runtime = Optime[NOPS].tv_sec / Nprocs;
	(void) fprintf(stdout,
	    "%d sec %d calls %d.%02d calls/sec %d.%02d msec/call\n",
	    runtime, Curct.total,
	    Curct.total / runtime,
	    ((Curct.total % runtime) * 100) / runtime,
	    totalmsec / Curct.total,
	    ((totalmsec % Curct.total) * 100) / Curct.total);
}

/*
 * Use select to sleep for some number of milliseconds
 * granularity is 20 msec
 */
void
msec_sleep(int msecs)
{
	struct timeval sleeptime;

	if (msecs < 20) {
		return;
	}
	sleeptime.tv_sec = msecs / 1000;
	sleeptime.tv_usec = (msecs % 1000) * 1000;

	if (select(0, (fd_set *)0, (fd_set *)0, (fd_set *)0, &sleeptime) == -1){
		Saveerrno = errno;
		(void) fprintf(stderr, "%s: select failed ", Myname);
		errno = Saveerrno;
		perror("");
		(void) kill(0, SIGINT);
		exit(1);
	}
}

/*
 * Open the synchronization file with append mode
 */
void
init_logfile(void)
{

	(void) sprintf(Logname, "/tmp/nhfsstone%d", getpid());
	if ((Log = open(Logname, O_RDWR|O_CREAT|O_TRUNC|O_APPEND, 0666)) == -1){
		Saveerrno = errno;
		(void) fprintf(stderr,
		    "%s: can't open log file %s ", Myname, Logname);
		errno = Saveerrno;
		perror("");
		exit(1);
	}
}

/*
 * Zero counters
 */
void
init_counters(void)
{
	int i;

	Curct.total = 0;
	for (i = 0; i < NOPS; i++) {
		Curct.calls[i] = 0;
		Optime[i].tv_sec = 0;
		Optime[i].tv_usec = 0;
	}
	Optime[NOPS].tv_sec = 0;
	Optime[NOPS].tv_usec = 0;
}

/*
 * Set cur = cur - start
 */
void
get_delta(struct count *start, struct count *cur)
{
	int i;

	get_opct(cur);
	cur->total -= start->total;
	for (i = 0; i < NOPS; i++) {
		cur->calls[i] -= start->calls[i];
	}
}

/*
 * Read kernel stats
 */
void
get_opct(struct count *count)
{
	static FILE	*fp = NULL;
	char		buffer[256];
	int i;

	if (fp == NULL && !(fp = fopen("/proc/net/rpc/nfs", "r"))) {
		perror("/proc/net/rpc/nfs");
		(void) kill(0, SIGINT);
		exit(1);
	} else {
		fflush(fp);
		rewind(fp);
	}

	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		char	*sp, *line = buffer;

		if ((sp = strchr(line, '\n')) != NULL)
			*sp = '\0';
		if (!(sp = strtok(line, " \t")) || strcmp(line, "proc2"))
			continue;
		if (!(sp = strtok(NULL, " \t")))
			goto bummer;
		count->total = 0;
		for (i = 0; i < 18; i++) {
			if (!(sp = strtok(NULL, " \t")))
				goto bummer;
			/* printf("call %d -> %s\n", i, sp); */
			count->calls[i] = atoi(sp);
			count->total += count->calls[i];
		}
		/* printf("total calls %d\n", count->total); */
		break;
	}

	return;

bummer:
	fprintf(stderr, "parse error in /proc/net/rpc/nfs!\n");
	kill(0, SIGINT);
	exit(1);
}

#define	LINELEN		128		/* max bytes/line in mix file */
#define	MIX_START	0
#define	MIX_DATALINE	1
#define	MIX_DONE	2
#define	MIX_FIRSTLINE	3

/*
 * Mix file parser.
 * Assumes that the input file is in the same format as
 * the output of the nfsstat(8) command.
 *
 * Uses a simple state transition to keep track of what to expect.
 * Parsing is done a line at a time.
 *
 * State	   Input		action		New state
 * MIX_START	   ".*nfs:.*"		skip one line	MIX_FIRSTLINE
 * MIX_FIRSTLINE   ".*[0-9]*.*"		get ncalls	MIX_DATALINE
 * MIX_DATALINE    "[0-9]* [0-9]*%"X6	get op counts	MIX_DATALINE
 * MIX_DATALINE    "[0-9]* [0-9]*%"X4	get op counts	MIX_DONE
 * MIX_DONE	   EOF			return
 */
int
setmix(FILE *fp)
{
	int state;
	int got;
	int opnum;
	int calls;
	int len;
	char line[LINELEN];

	state = MIX_START;
	opnum = 0;

	while (state != MIX_DONE && fgets(line, LINELEN, fp)) {

		switch (state) {

		case MIX_START:
			len = strlen(line);
			if (len >= 4 && substr(line, "nfs:")) {
				if (fgets(line, LINELEN, fp) == NULL) {
					(void) fprintf(stderr,
"%s: bad mix format: unexpected EOF after 'nfs:'\n", Myname);
					return (-1);
				}
				state = MIX_FIRSTLINE;
			}
			break;

		case MIX_FIRSTLINE:
			got = sscanf(line, "%d", &calls);
			if (got != 1) {
				(void) fprintf(stderr,
"%s: bad mix format: can't find 'calls' value %d\n", Myname, got);
				return (-1);
			}
			if (fgets(line, LINELEN, fp) == NULL) {
				(void) fprintf(stderr,
"%s: bad mix format: unexpected EOF after 'calls'\n", Myname);
				return (-1);
			}
			state = MIX_DATALINE;
			break;

		case MIX_DATALINE:
			got = sscanf(line,
	"%d %*d%% %d %*d%% %d %*d%% %d %*d%% %d %*d%% %d %*d%% %d %*d%%",
	&Mix[opnum], &Mix[opnum+1], &Mix[opnum+2], &Mix[opnum+3],
	&Mix[opnum+4], &Mix[opnum+5], &Mix[opnum+6]);
			if (got == 4 && opnum == 14) {
				/*
				 * looks like the last line
				 */
				state = MIX_DONE;
			} else if (got == 7) {
				opnum += 7;
				if (fgets(line, LINELEN, fp) == NULL) {
					(void) fprintf(stderr,
"%s: bad mix format: unexpected EOF after 'calls'\n", Myname);
					return (-1);
				}
			} else {
				(void) fprintf(stderr,
"%s: bad mix format: can't find %d op values\n", Myname, got);
				return (-1);
			}
			break;
		default:
			(void) fprintf(stderr,
			    "%s: unknown state %d\n", Myname, state);
			return (-1);
		}
	}
	if (state != MIX_DONE) {
		(void) fprintf(stderr,
		    "%s: bad mix format: unexpected EOF\n", Myname);
		return (-1);
	}
	for (opnum = 0; opnum < NOPS; opnum++) {
		Mix[opnum] = Mix[opnum] * 100 / calls
		    + ((Mix[opnum] * 1000 / calls % 10) >= 5);
	}
	return (0);
}

/*
 * return true if sp contains the substring subsp, false otherwise
 */
int
substr(char *sp, char *subsp)
{
	int found;
	int want;
	char *s2;

	if (sp == NULL || subsp == NULL) {
		return (0);
	}

	want = strlen(subsp);

	while (*sp != '\0') {
		while (*sp != *subsp && *sp != '\0') {
			sp++;
		}
		found = 0;
		s2 = subsp;
		while (*sp == *s2) {
			sp++;
			s2++;
			found++;
		}
		if (found == want) {
			return (1);
		}
	}
	return (0);
}

/*
 * check to make sure that we have
 * both read and write permissions
 * for this file or directory.
 */
int
check_access(struct stat statb)
{
	int gidsetlen;
	gid_t gidset[NGROUPS];
	int i;

	if (statb.st_uid == getuid()) {
		if ((statb.st_mode & 0200) && (statb.st_mode & 0400)) {
			return 1;
		} else {
			return -1;
		}
	}

	gidsetlen = NGROUPS;

	if (getgroups(gidsetlen, gidset) == -1) {
		perror("getgroups");
		return -1;
	}

	for (i = 0; i < NGROUPS; i++) {
		if (statb.st_gid == gidset[i]) {
			if ((statb.st_mode & 020) && (statb.st_mode & 040)) {
				return 1;
			} else {
				return -1;
			}
		}
	}

	if ((statb.st_mode & 02) && (statb.st_mode & 04)) {
		return 1;
	} else {
		return -1;
	}
}

void
usage(void)
{

	(void) fprintf(stderr, "usage: %s [-v] [[-t secs] | [-c calls]] [-l load] [-p nprocs] [-m mixfile] [dir]...\n", Myname);
}

void
error(char *str)
{

	Saveerrno = errno;
	(void) fprintf(stderr, "%s: op failed: %s ", Myname, str);
	errno = Saveerrno;
	perror("");
}
