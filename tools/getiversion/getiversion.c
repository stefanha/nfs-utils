/*
 * getiversion
 *
 * Get version number for an inode on an ext2 file system.
 */

#include "config.h"

#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
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
