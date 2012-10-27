/*
 * Copyright (c) 1999 - 2003 Kungliga Tekniska H�gskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "fsrv_locl.h"

#include "pts.cs.h"

#include "arlalib.h"

RCSID("$Id: connsec.c,v 1.19 2003/11/14 10:17:56 tol Exp $");

int
fs_connsec_nametoid(namelist *nlist, idlist *ilist)
{
    int error = ARLA_CALL_DEAD;
    int first = 0;
    struct db_server_context conn_context;
    struct rx_connection *conn;

retry:

    for (conn = arlalib_first_db(&conn_context,
				 NULL, NULL, afsprport, PR_SERVICE_ID, 
				 arlalib_getauthflag (0, 1, 0, 0));
	 conn != NULL && arlalib_try_next_db(error);
	 conn = arlalib_next_db(&conn_context)) {
	error = PR_NameToID(conn, nlist, ilist);
    }

    free_db_server_context(&conn_context);

    if (error == RXKADEXPIRED && first == 0) {
	++first;
	goto retry;
    }
    
    if (error) {
	fprintf(stderr, "PR_NameToID error: %s(%d)\n",
		koerr_gettext(error), error);
	return error;
    }

    return 0;
}

int
fs_connsec_idtoname(idlist *ilist, namelist *nlist)
{
    int error = ARLA_CALL_DEAD;
    int first = 0;
    struct db_server_context conn_context;
    struct rx_connection *conn;

retry:

    for (conn = arlalib_first_db(&conn_context,
				 NULL, NULL, afsprport, PR_SERVICE_ID, 
				 arlalib_getauthflag (0, 1, 0, 0));
	 conn != NULL && arlalib_try_next_db(error);
	 conn = arlalib_next_db(&conn_context)) {
	error = PR_IDToName(conn, ilist, nlist);
    }

    free_db_server_context(&conn_context);

    if (error == RXKADEXPIRED && first == 0) {
	++first;
	goto retry;
    }

    if (error) {
	if (koerr_gettext(error))
	    fprintf(stderr, "PR_IDToName error: %s(%d)\n",
		    koerr_gettext(error), error);
	else
	    fprintf(stderr, "PR_IDToName error: %d\n", error);
	return error;
    }

    return 0;
}

static void
fs_connsec_anonymous(struct fs_security_context *sec)
{
    sec->uid = PR_ANONYMOUSID;
    sec->cps->len = 2;
    sec->cps->val = malloc(2*sizeof(uint32_t));
    if (sec->cps->val == NULL) {
	sec->cps->len = 0;
	return; /* XXX */
    }
    sec->cps->val[0] = PR_ANYUSERID;
    sec->cps->val[1] = PR_ANONYMOUSID;
}

/*
 * split principal_string into user (etc) and realm
 * on success, return 0.
 * user needs to be free()d.
 */

int
fs_connsec_split_principal(char *principal_string, char **user, char **realm)
{
    *user = strdup(principal_string);
    if (*user == NULL)
	return -1;
    *realm = strrchr(*user, '@');
    if (*realm == NULL) {
	free(*user);
	return -1;
    }
    **realm = '\0';
    *realm++;

    return 0;
}

/*
 * get user name for conn, in a PR suitable format
 */

int
fs_connsec_get_user(struct rx_connection *conn, char *rname, int size)
{
    char *fullname;
    char *user;
    char *realm;
    int error;

    error = sec_getname(conn, &fullname);
    if (error == 0)
	error = fs_connsec_split_principal(fullname, &user, &realm);

    if (error == 0) {	
	if (!strcasecmp(realm, netinit_getrealm())) {
	    if (strlcpy(rname, user, size) >= size)
		error = -1;
	} else {
	    if (snprintf(rname, size, "%s@%s", user, strlwr(realm)) >= size)
		error = -1;
	}
	free(user);
    }

    return error;
}

static void
fs_connsec_createconn(struct rx_connection *conn)
{
    struct fs_security_context *sec;
    namelist nlist;
    idlist ilist;
    char rname[PR_MAXNAMELEN];
    int error;
    int32_t over;
    struct db_server_context conn_context;
    struct rx_connection *out_conn;
    int i;

    if (conn->rock)
	return;

    sec = malloc(sizeof(struct fs_security_context));
    if (sec == NULL) 
	return; /* XXX */

    sec->superuser = 0;
    sec->ref = 1;
    sec->cps = malloc(sizeof(prlist));
    if (sec->cps == NULL)
	return; /* XXX */

    conn->rock = sec;

    error = fs_connsec_get_user(conn, rname, sizeof(rname));
    if (error) {
	fs_connsec_anonymous(sec);
	return;
    }

    nlist.len = 1;
    nlist.val = &rname;
    ilist.val = NULL;

    error = ARLA_CALL_DEAD;
    for (out_conn = arlalib_first_db(&conn_context,
				 NULL, NULL, afsprport, PR_SERVICE_ID, 
				 arlalib_getauthflag (0, 1, 0, 0));
	 out_conn != NULL && arlalib_try_next_db(error);
	 out_conn = arlalib_next_db(&conn_context)) {
	error = PR_NameToID(out_conn, &nlist, &ilist);
	if (error == 0)
	    break;
    }

    if (error) {
	fprintf(stderr, "PR_NameToID error: %s(%d)\n",
		koerr_gettext(error), error);
	free(ilist.val);

	fs_connsec_anonymous(sec);
	free_db_server_context(&conn_context);
	return;
    }

    fprintf(stderr, "ID is %d\n", ilist.val[0]);
    sec->uid = ilist.val[0];
    free(ilist.val);

    error = PR_GetCPS(out_conn, sec->uid, sec->cps, &over);

    free_db_server_context(&conn_context);

    if (error) {
	fprintf(stderr, "PR_GetCPS error: %s(%d)\n",
		koerr_gettext(error), error);
	fs_connsec_anonymous(sec);
	return;
    }

    for (i = 0; i < sec->cps->len; i++) {
	if (sec->cps->val[i] == PR_SYSADMINID) {
	    sec->superuser = 1;
	    break;
	}
    }
}

void
fs_connsec_destroyconn(struct rx_connection *conn)
{
    if (conn->rock == NULL)
	return;
    
    fs_connsec_context_put(conn->rock);
    conn->rock = NULL;
}

struct fs_security_context *
fs_connsec_context_get(struct rx_connection *conn)
{
    struct fs_security_context *sec;

    fs_connsec_createconn(conn);

    sec = conn->rock;

    assert(sec);

    sec->ref++;
    return sec;
}

void
fs_connsec_context_put(struct fs_security_context *sec)
{
    assert(sec->ref > 0);

    sec->ref--;

    if (sec->ref == 0) {
	free(sec->cps->val);
	free(sec->cps);
	free(sec);
    }
}
