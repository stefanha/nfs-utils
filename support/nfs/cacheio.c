/*
 * support/nfs/cacheio.c
 * support IO on the cache channel files in 2.5 and beyond.
 * These use 'qwords' which are like words, but with a little quoting.
 *
 */


/*
 * Support routines for text-based upcalls.
 * Fields are separated by spaces.
 * Fields are either mangled to quote space tab newline slosh with slosh
 * or a hexified with a leading \x
 * Record is terminated with newline.
 *
 */

#include <nfslib.h>
#include <stdio.h>
#include <ctype.h>
#include <unistd.h>

void qword_add(char **bpp, int *lp, char *str)
{
	char *bp = *bpp;
	int len = *lp;
	char c;

	if (len < 0) return;

	while ((c=*str++) && len)
		switch(c) {
		case ' ':
		case '\t':
		case '\n':
		case '\\':
			if (len >= 4) {
				*bp++ = '\\';
				*bp++ = '0' + ((c & 0300)>>6);
				*bp++ = '0' + ((c & 0070)>>3);
				*bp++ = '0' + ((c & 0007)>>0);
			}
			len -= 4;
			break;
		default:
			*bp++ = c;
			len--;
		}
	if (c || len <1) len = -1;
	else {
		*bp++ = ' ';
		len--;
	}
	*bpp = bp;
	*lp = len;
}

void qword_addhex(char **bpp, int *lp, char *buf, int blen)
{
	char *bp = *bpp;
	int len = *lp;

	if (len < 0) return;

	if (len > 2) {
		*bp++ = '\\';
		*bp++ = 'x';
		len -= 2;
		while (blen && len >= 2) {
			unsigned char c = *buf++;
			*bp++ = '0' + ((c&0xf0)>>4) + (c>=0xa0)*('a'-'9'-1);
			*bp++ = '0' + (c&0x0f) + ((c&0x0f)>=0x0a)*('a'-'9'-1);
			len -= 2;
			blen--;
		}
	}
	if (blen || len<1) len = -1;
	else {
		*bp++ = ' ';
		len--;
	}
	*bpp = bp;
	*lp = len;
}

static char qword_buf[8192];
void qword_print(FILE *f, char *str)
{
	char *bp = qword_buf;
	int len = sizeof(qword_buf);
	qword_add(&bp, &len, str);
	fwrite(qword_buf, bp-qword_buf, 1, f);
}

void qword_printhex(FILE *f, char *str, int slen)
{
	char *bp = qword_buf;
	int len = sizeof(qword_buf);
	qword_addhex(&bp, &len, str, slen);
	fwrite(qword_buf, bp-qword_buf, 1, f);
}

void qword_printint(FILE *f, int num)
{
	fprintf(f, "%d ", num);
}

void qword_eol(FILE *f)
{
	fprintf(f,"\n");
	fflush(f);
}



#define isodigit(c) (isdigit(c) && c <= '7')
int qword_get(char **bpp, char *dest, int bufsize)
{
	/* return bytes copied, or -1 on error */
	char *bp = *bpp;
	int len = 0;

	while (*bp == ' ') bp++;

	if (bp[0] == '\\' && bp[1] == 'x') {
		/* HEX STRING */
		bp += 2;
		while (isxdigit(bp[0]) && isxdigit(bp[1]) && len < bufsize) {
			int byte = isdigit(*bp) ? *bp-'0' : toupper(*bp)-'A'+10;
			bp++;
			byte <<= 4;
			byte |= isdigit(*bp) ? *bp-'0' : toupper(*bp)-'A'+10;
			*dest++ = byte;
			bp++;
			len++;
		}
	} else {
		/* text with \nnn octal quoting */
		while (*bp != ' ' && *bp != '\n' && *bp && len < bufsize-1) {
			if (*bp == '\\' &&
			    isodigit(bp[1]) && (bp[1] <= '3') &&
			    isodigit(bp[2]) &&
			    isodigit(bp[3])) {
				int byte = (*++bp -'0');
				bp++;
				byte = (byte << 3) | (*bp++ - '0');
				byte = (byte << 3) | (*bp++ - '0');
				*dest++ = byte;
				len++;
			} else {
				*dest++ = *bp++;
				len++;
			}
		}
	}

	if (*bp != ' ' && *bp != '\n' && *bp != '\0')
		return -1;
	while (*bp == ' ') bp++;
	*bpp = bp;
	*dest = '\0';
	return len;
}

int qword_get_int(char **bpp, int *anint)
{
	char buf[50];
	char *ep;
	int rv;
	int len = qword_get(bpp, buf, 50);
	if (len < 0) return -1;
	if (len ==0) return -1;
	rv = strtol(buf, &ep, 0);
	if (*ep) return -1;
	*anint = rv;
	return 0;
}

int readline(int fd, char **buf, int *lenp)
{
	/* read a line into *buf, which is malloced *len long
	 * realloc if needed until we find a \n
	 * nul out the \n and return
	 * 0 of eof, 1 of success 
	 */
	int len = *lenp;

	if (len == 0) {
		char *b = malloc(128);
		if (b == NULL)
			return 0;
		*buf = b;
		*lenp = 128;
	}
	len = read(fd, *buf, len);
	if (len <= 0)
		return 0;
	while ((*buf)[len-1] != '\n') {
	/* now the less common case.  There was no newline,
	 * so we have to keep reading after re-alloc
	 */
		char *new;
		int nl;
		*lenp += 128;
		new = realloc(*buf, *lenp);
		if (new == NULL)
			return 0;
		nl = read(fd, *buf +len, *lenp - len);
		if (nl <= 0 )
			return 0;
		new += nl;
	}
	(*buf)[len-1] = 0;
	return 1;
}

