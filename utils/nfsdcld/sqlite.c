/*
 * Copyright (C) 2011  Red Hat, Jeff Layton <jlayton@redhat.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

/*
 * Explanation:
 *
 * This file contains the code to manage the sqlite backend database for the
 * clstated upcall daemon.
 *
 * The main database is called main.sqlite and contains the following tables:
 *
 * parameters: simple key/value pairs for storing database info
 *
 * clients: one column containing a BLOB with the as sent by the client
 * 	    and a timestamp (in epoch seconds) of when the record was
 * 	    established
 *
 * FIXME: should we also record the fsid being accessed?
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <errno.h>
#include <event.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <sqlite3.h>
#include <linux/limits.h>

#include "xlog.h"

#define CLD_SQLITE_SCHEMA_VERSION 1

#ifndef CLD_SQLITE_TOPDIR
#define CLD_SQLITE_TOPDIR NFS_STATEDIR "/nfsdcld"
#endif

/* in milliseconds */
#define CLD_SQLITE_BUSY_TIMEOUT 10000

/* private data structures */

/* global variables */

/* top level DB directory */
static char *sqlite_topdir;

/* reusable pathname and sql command buffer */
static char buf[PATH_MAX];

/* global database handle */
static sqlite3 *dbh;

/* forward declarations */

/* make a directory, ignoring EEXIST errors unless it's not a directory */
static int
mkdir_if_not_exist(char *dirname)
{
	int ret;
	struct stat statbuf;

	ret = mkdir(dirname, S_IRWXU);
	if (ret && errno != EEXIST)
		return -errno;

	ret = stat(dirname, &statbuf);
	if (ret)
		return -errno;

	if (!S_ISDIR(statbuf.st_mode))
		ret = -ENOTDIR;

	return ret;
}

/*
 * Open the "main" database, and attempt to initialize it by creating the
 * parameters table and inserting the schema version into it. Ignore any errors
 * from that, and then attempt to select the version out of it again. If the
 * version appears wrong, then assume that the DB is corrupt or has been
 * upgraded, and return an error. If all of that works, then attempt to create
 * the "clients" table.
 */
int
sqlite_maindb_init(char *topdir)
{
	int ret;
	char *err = NULL;
	sqlite3_stmt *stmt = NULL;

	sqlite_topdir = topdir ? topdir : CLD_SQLITE_TOPDIR;

	ret = mkdir_if_not_exist(sqlite_topdir);
	if (ret)
		return ret;

	ret = snprintf(buf, PATH_MAX - 1, "%s/main.sqlite", sqlite_topdir);
	if (ret < 0)
		return ret;

	buf[PATH_MAX - 1] = '\0';

	ret = sqlite3_open(buf, &dbh);
	if (ret != SQLITE_OK) {
		xlog(L_ERROR, "Unable to open main database: %d", ret);
		return ret;
	}

	ret = sqlite3_busy_timeout(dbh, CLD_SQLITE_BUSY_TIMEOUT);
	if (ret != SQLITE_OK) {
		xlog(L_ERROR, "Unable to set sqlite busy timeout: %d", ret);
		goto out_err;
	}

	/* Try to create table */
	ret = sqlite3_exec(dbh, "CREATE TABLE IF NOT EXISTS parameters "
				"(key TEXT PRIMARY KEY, value TEXT);",
				NULL, NULL, &err);
	if (ret != SQLITE_OK) {
		xlog(L_ERROR, "Unable to create parameter table: %d", ret);
		goto out_err;
	}

	/* insert version into table -- ignore error if it fails */
	ret = snprintf(buf, sizeof(buf),
		       "INSERT OR IGNORE INTO parameters values (\"version\", "
		       "\"%d\");", CLD_SQLITE_SCHEMA_VERSION);
	if (ret < 0) {
		goto out_err;
	} else if ((size_t)ret >= sizeof(buf)) {
		ret = -EINVAL;
		goto out_err;
	}

	ret = sqlite3_exec(dbh, (const char *)buf, NULL, NULL, &err);
	if (ret != SQLITE_OK) {
		xlog(L_ERROR, "Unable to insert into parameter table: %d",
				ret);
		goto out_err;
	}

	ret = sqlite3_prepare_v2(dbh,
		"SELECT value FROM parameters WHERE key == \"version\";",
		 -1, &stmt, NULL);
	if (ret != SQLITE_OK) {
		xlog(L_ERROR, "Unable to prepare select statement: %d", ret);
		goto out_err;
	}

	/* check schema version */
	ret = sqlite3_step(stmt);
	if (ret != SQLITE_ROW) {
		xlog(L_ERROR, "Select statement execution failed: %s",
				sqlite3_errmsg(dbh));
		goto out_err;
	}

	/* process SELECT result */
	ret = sqlite3_column_int(stmt, 0);
	if (ret != CLD_SQLITE_SCHEMA_VERSION) {
		xlog(L_ERROR, "Unsupported database schema version! "
			"Expected %d, got %d.",
			CLD_SQLITE_SCHEMA_VERSION, ret);
		ret = -EINVAL;
		goto out_err;
	}

	/* now create the "clients" table */
	ret = sqlite3_exec(dbh, "CREATE TABLE IF NOT EXISTS clients "
				"(id BLOB PRIMARY KEY, time INTEGER);",
				NULL, NULL, &err);
	if (ret != SQLITE_OK) {
		xlog(L_ERROR, "Unable to create clients table: %s", err);
		goto out_err;
	}

	sqlite3_free(err);
	sqlite3_finalize(stmt);
	return 0;

out_err:
	if (err) {
		xlog(L_ERROR, "sqlite error: %s", err);
		sqlite3_free(err);
	}
	sqlite3_finalize(stmt);
	sqlite3_close(dbh);
	return ret;
}

/*
 * Create a client record
 *
 * Returns a non-zero sqlite error code, or SQLITE_OK (aka 0)
 */
int
sqlite_insert_client(const unsigned char *clname, const size_t namelen)
{
	int ret;
	sqlite3_stmt *stmt = NULL;

	ret = sqlite3_prepare_v2(dbh, "INSERT OR REPLACE INTO clients VALUES "
				      "(?, strftime('%s', 'now'));", -1,
					&stmt, NULL);
	if (ret != SQLITE_OK) {
		xlog(L_ERROR, "%s: insert statement prepare failed: %s",
			__func__, sqlite3_errmsg(dbh));
		return ret;
	}

	ret = sqlite3_bind_blob(stmt, 1, (const void *)clname, namelen,
				SQLITE_STATIC);
	if (ret != SQLITE_OK) {
		xlog(L_ERROR, "%s: bind blob failed: %s", __func__,
				sqlite3_errmsg(dbh));
		goto out_err;
	}

	ret = sqlite3_step(stmt);
	if (ret == SQLITE_DONE)
		ret = SQLITE_OK;
	else
		xlog(L_ERROR, "%s: unexpected return code from insert: %s",
				__func__, sqlite3_errmsg(dbh));

out_err:
	xlog(D_GENERAL, "%s: returning %d", __func__, ret);
	sqlite3_finalize(stmt);
	return ret;
}
