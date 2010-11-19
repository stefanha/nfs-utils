
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pwd.h>
#include <grp.h>
#include <keyutils.h>
#include <nfsidmap.h>

#include <syslog.h>

/* gcc nfsidmap.c -o nfsidmap -l nfsidmap -l keyutils */

#define MAX_ID_LEN   11
#define IDMAP_NAMESZ 128
#define USER  1
#define GROUP 0


/*
 * Find either a user or group id based on the name@domain string
 */
int id_lookup(char *name_at_domain, key_serial_t key, int type)
{
	char id[MAX_ID_LEN];
	uid_t uid = 0;
	gid_t gid = 0;
	int rc;

	if (type == USER) {
		rc = nfs4_owner_to_uid(name_at_domain, &uid);
		sprintf(id, "%u", uid);
	} else {
		rc = nfs4_group_owner_to_gid(name_at_domain, &gid);
		sprintf(id, "%u", gid);
	}

	if (rc == 0)
		rc = keyctl_instantiate(key, id, strlen(id) + 1, 0);

	return rc;
}

/*
 * Find the name@domain string from either a user or group id
 */
int name_lookup(char *id, key_serial_t key, int type)
{
	char name[IDMAP_NAMESZ];
	char domain[NFS4_MAX_DOMAIN_LEN];
	uid_t uid;
	gid_t gid;
	int rc;

	rc = nfs4_get_default_domain(NULL, domain, NFS4_MAX_DOMAIN_LEN);
	if (rc != 0) {
		rc = -1;
		goto out;
	}

	if (type == USER) {
		uid = atoi(id);
		rc = nfs4_uid_to_name(uid, domain, name, IDMAP_NAMESZ);
	} else {
		gid = atoi(id);
		rc = nfs4_gid_to_name(gid, domain, name, IDMAP_NAMESZ);
	}

	if (rc == 0)
		rc = keyctl_instantiate(key, &name, strlen(name), 0);

out:
	return rc;
}

int main(int argc, char **argv)
{
	char *arg;
	char *value;
	char *type;
	int rc = 1;
	int timeout = 600;
	key_serial_t key;

	if (argc < 3)
		return 1;

	arg = malloc(sizeof(char) * strlen(argv[2]) + 1);
	strcpy(arg, argv[2]);
	type = strtok(arg, ":");
	value = strtok(NULL, ":");

	if (argc == 4) {
		timeout = atoi(argv[3]);
		if (timeout < 0)
			timeout = 0;
	}

	key = strtol(argv[1], NULL, 10);

	if (strcmp(type, "uid") == 0)
		rc = id_lookup(value, key, USER);
	else if (strcmp(type, "gid") == 0)
		rc = id_lookup(value, key, GROUP);
	else if (strcmp(type, "user") == 0)
		rc = name_lookup(value, key, USER);
	else if (strcmp(type, "group") == 0)
		rc = name_lookup(value, key, GROUP);

	/* Set timeout to 5 (600 seconds) minutes */
	if (rc == 0)
		keyctl_set_timeout(key, timeout);

	free(arg);
	return rc;
}
