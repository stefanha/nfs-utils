/*
 * getiversion
 *
 * Get version number for an inode on an ext2 file system.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <stdio.h>
#include <sys/fs/ext2fs.h>

int
main(int argc, char **argv)
{
	int	i, fd;
	u_int32_t	vers;

	if (argc <= 1) {
		fprintf(stderr, "usage: getiversion file ...\n");
		return 1;
	}

	for (i = 1; i < argc; i++) {
		if ((fd = open(argv[i], O_RDONLY)) < 0
		 || ioctl(fd, EXT2_IOC_GETVERSION, &vers) < 0) {
			perror(argv[i]);
			continue;
		} else {
			printf("%-20s %d\n", argv[i], vers);
		}
		close(fd);
	}
	return 0;
}
