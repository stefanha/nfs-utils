
/*
 * Handle communication with knfsd internal cache
 *
 * We open /proc/net/rpc/{auth.unix.ip,nfsd.export,nfsd.fh}/channel
 * and listen for requests (using my_svc_run)
 * 
 */
#include "config.h"

#include <sys/types.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include "misc.h"
#include "nfslib.h"
#include "exportfs.h"
#include "mountd.h"
#include "xmalloc.h"

/*
 * Support routines for text-based upcalls.
 * Fields are separated by spaces.
 * Fields are either mangled to quote space tab newline slosh with slosh
 * or a hexified with a leading \x
 * Record is terminated with newline.
 *
 */
void cache_export_ent(char *domain, struct exportent *exp);


char *lbuf  = NULL;
int lbuflen = 0;

void auth_unix_ip(FILE *f)
{
	/* requests are
	 *  class IP-ADDR
	 * Ignore if class != "nfsd"
	 * Otherwise find domainname and write back:
	 *
	 *  "nfsd" IP-ADDR expiry domainname
	 */
	char *cp;
	char class[20];
	char ipaddr[20];
	char *client;
	struct in_addr addr;
	if (readline(fileno(f), &lbuf, &lbuflen) != 1)
		return;

	cp = lbuf;

	if (qword_get(&cp, class, 20) <= 0 ||
	    strcmp(class, "nfsd") != 0)
		return;

	if (qword_get(&cp, ipaddr, 20) <= 0)
		return;

	if (inet_aton(ipaddr, &addr)==0)
		return;

	/* addr is a valid, interesting address, find the domain name... */
	client = client_compose(addr);

	
	qword_print(f, "nfsd");
	qword_print(f, ipaddr);
	qword_printint(f, time(0)+30*60);
	if (client)
		qword_print(f, *client?client:"DEFAULT");
	qword_eol(f);

	if (client) free(client);
	
}

void nfsd_fh(FILE *f)
{
	/* request are:
	 *  domain fsidtype fsid
	 * interpret fsid, find export point and options, and write:
	 *  domain fsidtype fsid expiry path
	 */
	char *cp;
	char *dom;
	int fsidtype;
	int fsidlen;
	unsigned int dev, major=0, minor=0;
	unsigned int inode=0;
	unsigned int fsidnum=0;
	char fsid[32];
	struct exportent *found = NULL;
	nfs_export *exp;
	int i;

	if (readline(fileno(f), &lbuf, &lbuflen) != 1)
		return;

	cp = lbuf;

	dom = malloc(strlen(cp));
	if (dom == NULL)
		return;
	if (qword_get(&cp, dom, strlen(cp)) <= 0)
		goto out;
	if (qword_get_int(&cp, &fsidtype) != 0)
		goto out;
	if (fsidtype < 0 || fsidtype > 1)
		goto out; /* unknown type */
	if ((fsidlen = qword_get(&cp, fsid, 32)) <= 0)
		goto out;
	switch(fsidtype) {
	case 0: /* 4 bytes: 2 major, 2 minor, 4 inode */
		if (fsidlen != 8)
			goto out;
		memcpy(&dev, fsid, 4);
		memcpy(&inode, fsid+4, 4);
		major = ntohl(dev)>>16;
		minor = ntohl(dev) & 0xFFFF;
		break;

	case 1: /* 4 bytes - fsid */
		if (fsidlen != 4)
			goto out;
		memcpy(&fsidnum, fsid, 4);
		break;
	}

	/* Now determine export point for this fsid/domain */
	for (i=0 ; i < MCL_MAXTYPES; i++) {
		for (exp = exportlist[i]; exp; exp = exp->m_next) {
			if (!client_member(dom, exp->m_client->m_hostname))
				continue;
			if (fsidtype == 1 &&
			    ((exp->m_export.e_flags & NFSEXP_FSID) == 0 ||
			     exp->m_export.e_fsid != fsidnum))
				continue;
			if (fsidtype == 0) {
				struct stat stb;
				if (stat(exp->m_export.e_path, &stb) != 0)
					continue;
				if (stb.st_ino != inode)
					continue;
				if (major != major(stb.st_dev) ||
				    minor != minor(stb.st_dev))
					continue;
			}
			/* It's a match !! */
			if (!found)
				found = &exp->m_export;
			else if (strcmp(found->e_path, exp->m_export.e_path)!= 0)
			{
				xlog(L_WARNING, "%s and %s have name filehandle for %s, using first",
				     found->e_path, exp->m_export.e_path, dom);
			}
		}
	}
	cache_export_ent(dom, found);

	qword_print(f, dom);
	qword_printint(f, fsidtype);
	qword_printhex(f, fsid, fsidlen);
	qword_printint(f, time(0)+30*60);
	if (found)
		qword_print(f, found->e_path);
	qword_eol(f);
 out:
	free(dom);
	return;		
}

void nfsd_export(FILE *f)
{
	/* requests are:
	 *  domain path
	 * determine export options and return:
	 *  domain path expiry flags anonuid anongid fsid
	 */

	char *cp;
	int i;
	char *dom, *path;
	nfs_export *exp, *found = NULL;


	if (readline(fileno(f), &lbuf, &lbuflen) != 1)
		return;

	cp = lbuf;
	dom = malloc(strlen(cp));
	path = malloc(strlen(cp));

	if (!dom || !path)
		goto out;

	if (qword_get(&cp, dom, strlen(lbuf)) <= 0)
		goto out;
	if (qword_get(&cp, path, strlen(lbuf)) <= 0)
		goto out;

	/* now find flags for this export point in this domain */
	for (i=0 ; i < MCL_MAXTYPES; i++) {
		for (exp = exportlist[i]; exp; exp = exp->m_next) {
			if (!client_member(dom, exp->m_client->m_hostname))
				continue;
			if (strcmp(path, exp->m_export.e_path))
				continue;
			if (!found)
				found = exp;
			else {
				xlog(L_WARNING, "%s exported to both %s and %s in %s",
				     path, exp->m_client->m_hostname, found->m_client->m_hostname,
				     dom);
			}
		}
	}

	qword_print(f, dom);
	qword_print(f, path);
	qword_printint(f, time(0)+30*60);
	if (found) {
		qword_printint(f, found->m_export.e_flags);
		qword_printint(f, found->m_export.e_anonuid);
		qword_printint(f, found->m_export.e_anongid);
		qword_printint(f, found->m_export.e_fsid);
	}
	qword_eol(f);
 out:
	if (dom) free(dom);
	if (path) free(path);
}


struct {
	char *cache_name;
	void (*cache_handle)(FILE *f);
	FILE *f;
} cachelist[] = {
	{ "auth.unix.ip", auth_unix_ip},
	{ "nfsd.export", nfsd_export},
	{ "nfsd.fh", nfsd_fh},
	{ NULL, NULL }
};

void cache_open(void) 
{
	int i;
	for (i=0; cachelist[i].cache_name; i++ ){
		char path[100];
		sprintf(path, "/proc/net/rpc/%s/channel", cachelist[i].cache_name);
		cachelist[i].f = fopen(path, "r+");
	}
}

void cache_set_fds(fd_set *fdset)
{
	int i;
	for (i=0; cachelist[i].cache_name; i++) {
		if (cachelist[i].f)
			FD_SET(fileno(cachelist[i].f), fdset);
	}
}

int cache_process_req(fd_set *readfds) 
{
	int i;
	int cnt = 0;
	for (i=0; cachelist[i].cache_name; i++) {
		if (cachelist[i].f != NULL &&
		    FD_ISSET(fileno(cachelist[i].f), readfds)) {
			cnt++;
			cachelist[i].cache_handle(cachelist[i].f);
		}
	}
	return cnt;
}


/*
 * Give IP->domain and domain+path->options to kernel
 * % echo nfsd $IP  $[now+30*60] $domain > /proc/net/rpc/auth.unix.ip/channel
 * % echo $domain $path $[now+30*60] $options $anonuid $anongid $fsid > /proc/net/rpc/nfsd.export/channel
 */

void cache_export_ent(char *domain, struct exportent *exp)
{

	FILE *f = fopen("/proc/net/rpc/nfsd.export/channel", "r+");
	if (!f)
		return;

	qword_print(f, domain);
	qword_print(f, exp->e_path);
	qword_printint(f, time(0)+30*60);
	qword_printint(f, exp->e_flags);
	qword_printint(f, exp->e_anonuid);
	qword_printint(f, exp->e_anongid);
	qword_printint(f, exp->e_fsid);
	qword_eol(f);

	fclose(f);
}

void cache_export(nfs_export *exp)
{
	FILE *f;

	f = fopen("/proc/net/rpc/auth.unix.ip/channel", "r+");
	if (!f)
		return;

	qword_print(f, "nfsd");
	qword_print(f, inet_ntoa(exp->m_client->m_addrlist[0]));
	qword_printint(f, time(0)+30*60);
	qword_print(f, exp->m_client->m_hostname);
	qword_eol(f);
	
	fclose(f);

	cache_export_ent(exp->m_client->m_hostname, &exp->m_export);
}

/* Get a filehandle.
 * { 
 *   echo $domain $path $length 
 *   read filehandle <&0
 * } <> /proc/fs/nfs/filehandle
 */
struct nfs_fh_len *
cache_get_filehandle(nfs_export *exp, int len)
{
	FILE *f = fopen("/proc/fs/nfs/filehandle", "r+");
	char buf[200];
	char *bp = buf;
	static struct nfs_fh_len fh;
	if (!f)
		return NULL;

	qword_print(f, exp->m_client->m_hostname);
	qword_print(f, exp->m_export.e_path);
	qword_printint(f, len);	
	qword_eol(f);
	
	if (fgets(buf, sizeof(buf), f) == NULL)
		return NULL;
	memset(fh.fh_handle, 0, sizeof(fh.fh_handle));
	fh.fh_size = qword_get(&bp, fh.fh_handle, NFS3_FHSIZE);
	return &fh;
}

