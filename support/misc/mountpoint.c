
/*
 * check if a given path is a mountpoint 
 */

#include <string.h>
#include <malloc.h>
#include <sys/stat.h>

int
is_mountpoint(char *path)
{
	/* Check if 'path' is a current mountpoint.
	 * Possibly we should also check it is the mountpoint of the 
	 * filesystem holding the target directory, but there doesn't
	 * seem a lot of point.
	 *
	 * We deem it to be a mountpoint if appending a ".." gives a different
	 * device or the same inode number.
	 */
	char *dotdot;
	struct stat stb, pstb;

	dotdot = malloc(strlen(path)+4);
	strcat(strcpy(dotdot, path), "/..");
	if (lstat(path, &stb) != 0 ||
	    lstat(dotdot, &pstb) != 0)
		return 0;

	if (stb.st_dev != pstb.st_dev
	    || stb.st_ino == pstb.st_ino)
		return 1;
	return 0;
}
