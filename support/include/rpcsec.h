/*
 *  Declarations needed for the authdes library. Some of the functions
 *  mentioned herein have been omitted from the Linux libc header files
 */

#ifndef RPCSEC_H
#define RPCSEC_H

int	netname2user(char *netname, int *uidp, int *gidp,
					int *gidlenp, int *gidlist);
int	netname2host(char *netname, char *hostname, int hostlen);
int	getnetname(char *name);
int	user2netname(char *netname, int uid, char *domain);
int	host2netname(char *netname, char *hostname, char *domain);
void	passwd2des(char *pw, char *key);
int	getsecretkey(char *netname, char *secretkey, char *passwd);
int	getpublickey(char *hostname, char *publickey);
int	yp_update(char *domain, char *map, unsigned int ypop,
			char *key, int keylen, char *data, int datalen);
int	key_setsecret(char *secret);
int	xencrypt(char *secret, char *passwd);
int	xdecrypt(char *secret, char *passwd);


#define PUBLICKEY_MAP	"publickey.byname"
#define NETID_MAP	"netid.byname"

#ifndef DEBUG
#define RPCSEC_BASE	"/etc/"
#else
#define RPCSEC_BASE	"/tmp/"
#endif

#define PUBLICKEY_FILE	RPCSEC_BASE "publickey"
#define PUBLICKEY_LOCK	RPCSEC_BASE "publickey.lock"
#define ROOTKEY_FILE	RPCSEC_BASE ".rootkey"
#define KEYSTORE_FILE	RPCSEC_BASE "keystore"

#endif /* RPCSEC_H */
