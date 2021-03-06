/*
 * Copyright (c) 1998 - 2001, 2005 Kungliga Tekniska H�gskolan
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

#include "appl_locl.h"
#include <arla-pioctl.h>
#ifdef KERBEROS
#include <kafs.h>
#endif

RCSID("$Id: fs_lib.c,v 1.46 2005/11/17 09:52:03 tol Exp $");

enum { PIOCTL_MAXSIZE = 2000 };

/*
 *
 */

static int
arla_k_pioctl(char *a_path,
	      int o_opcode,
	      struct arlaViceIoctl *a_paramsP,
	      int a_followSymlinks)
{
    return k_pioctl(a_path, o_opcode, (void *)a_paramsP, a_followSymlinks);
}

/*
 * fserr, try to implement a generic function for fs error messages
 */

void
fserr(const char *progname, int error, const char *realpath)
{
    const char *path = realpath ? realpath : "[unknown path]";

    switch(error) {
    case EACCES: 
	fprintf(stderr, "%s: You don't have the required access rights on"
		" '%s'\n", progname, path);
	break;
    case EINVAL: 
	fprintf(stderr, "%s: Invalid argument; it is possible that %s is"
		" not in AFS.\n", progname, path);
	break;
    case ENOENT: 
	fprintf(stderr, "%s: '%s' doesn't exist\n", progname, path);
	break;
    case EPERM: 
	fprintf(stderr, "%s: You do not have the required rights to do"
		" this operation\n", progname); 
	break;
    case ESRCH: 
	fprintf (stderr, "%s: Home cell information not available\n",
		 progname); 
	break;
    case EDOM: 
    default: 
	fprintf(stderr, "%s: error %s (%d) return from pioctl\n",
		progname, koerr_gettext(error), error);
	break;
    }
}

/*
 * fs_getfid, the the `fid' that `path' points on. 
 */

int
fs_getfid(char *path, VenusFid *fid)
{
    struct arlaViceIoctl a_params;

    if (path == NULL || fid == NULL)
	return EINVAL;

    a_params.in_size=0;
    a_params.out_size=sizeof(*fid);
    a_params.in=NULL;
    a_params.out=(void*) fid;
    
    if(arla_k_pioctl(path,ARLA_VIOCGETFID,&a_params,1) == -1)
	return errno;

    return 0;
}

/*
 * Do nothing
 */

int
fs_nop(void)
{
    struct arlaViceIoctl a_params;

    a_params.in_size=0;
    a_params.out_size=0;
    a_params.in=NULL;
    a_params.out=NULL;
    
    if (arla_k_pioctl(NULL,ARLA_VIOCNOP,&a_params,1) == -1) 
	return errno;

    return 0;
}

/*
 * Get the `cell' that the `path' ends up in
 */

int
fs_getfilecellname(char *path, char *cell, size_t len)
{
    struct arlaViceIoctl a_params;

    a_params.in_size=0;
    a_params.out_size=len;
    a_params.in=NULL;
    a_params.out=cell;
    
    if (arla_k_pioctl(path,ARLA_VIOC_FILE_CELL_NAME,&a_params,1) == -1) 
	return errno;

    return 0;
}

/*
 * set the level of crypt
 */

int
fs_setcrypt (uint32_t n)
{
    struct arlaViceIoctl	a_params;

    a_params.in_size  = sizeof(n);
    a_params.out_size = 0;
    a_params.in	      = (char *)&n;
    a_params.out      = NULL;

    if (arla_k_pioctl (NULL, ARLA_VIOC_SETRXKCRYPT, &a_params, 0) == -1)
	return errno;

    return 0;
}

/*
 * get currernt level of crypt
 */

int
fs_getcrypt (uint32_t *level)
{
    struct arlaViceIoctl	a_params;

    a_params.in_size  = 0;
    a_params.out_size = sizeof(*level);
    a_params.in	      = NULL;
    a_params.out      = (char *) level;

    if (arla_k_pioctl (NULL, ARLA_VIOC_GETRXKCRYPT, &a_params, 0) == -1) 
	return errno;
    
    return 0;
}

/*
 * get and set the connect-mode
 */

int
fs_connect(int32_t type, int32_t *flags)
{
    struct arlaViceIoctl   a_params;

    a_params.in_size = sizeof(type);
    a_params.out_size = sizeof (int32_t);
    a_params.in = (char *) &type;
    a_params.out = (char *) flags;

    if (arla_k_pioctl (NULL, ARLA_AIOC_CONNECTMODE, &a_params, 0) == -1)
	return errno;

    return 0;
}

/*
 *
 */

int
fs_setfprio(VenusFid fid, int16_t prio)
{
    struct arlaViceIoctl   a_params;
    struct arla_vioc_fprio  fprio;

    fprio.cmd = arla_FPRIO_SET;
    fprio.Cell = fid.Cell;
    fprio.Volume = fid.fid.Volume;
    fprio.Vnode = fid.fid.Vnode;
    fprio.Unique = fid.fid.Unique;
    fprio.prio = prio;

    a_params.in_size = sizeof(fprio);
    a_params.out_size = 0;
    a_params.in = (char *) &fprio;
    a_params.out = NULL;

    if (arla_k_pioctl (NULL, ARLA_VIOC_FPRIOSTATUS , &a_params, 0) == -1)
	return errno;

    return 0;
}

int
fs_getfprio(VenusFid fid, int16_t *prio)
{
    struct arlaViceIoctl   a_params;
    struct arla_vioc_fprio  fprio;

    fprio.cmd = arla_FPRIO_GET;
    fprio.Cell = fid.Cell;
    fprio.Volume = fid.fid.Volume;
    fprio.Vnode = fid.fid.Vnode;
    fprio.Unique = fid.fid.Unique;

    a_params.in_size = sizeof(fprio);
    a_params.out_size = sizeof(*prio);
    a_params.in = (char *) &fprio;
    a_params.out = (char *) prio;

    if (arla_k_pioctl (NULL, ARLA_VIOC_FPRIOSTATUS , &a_params, 0) == -1)
	return errno;

    return 0;
}

int
fs_setmaxfprio(int16_t maxprio)
{
    struct arlaViceIoctl   a_params;
    struct arla_vioc_fprio  fprio;

    fprio.cmd = arla_FPRIO_SETMAX;
    fprio.prio = maxprio;

    a_params.in_size = sizeof(fprio);
    a_params.out_size = 0;
    a_params.in = (char *) &fprio;
    a_params.out = NULL;

    if (arla_k_pioctl (NULL, ARLA_VIOC_FPRIOSTATUS , &a_params, 0) == -1)
	return errno;

    return 0;
}

int
fs_getmaxfprio(int16_t *maxprio)
{
    struct arlaViceIoctl   a_params;
    struct arla_vioc_fprio  fprio;

    fprio.cmd = arla_FPRIO_GETMAX;

    a_params.in_size = sizeof(fprio);
    a_params.out_size = sizeof(*maxprio);
    a_params.in = (char *) &fprio;
    a_params.out = (char *) maxprio;

    if (arla_k_pioctl (NULL, ARLA_VIOC_FPRIOSTATUS , &a_params, 0) == -1)
	return errno;

    return 0;
}

/*
 *
 */

static int
getcacheparam(int32_t opcode, int64_t *val)
{
    struct arlaViceIoctl a_params;

    a_params.in_size  = sizeof(opcode);
    a_params.out_size = sizeof(*val);
    a_params.in       = (char *)&opcode;
    a_params.out      = (char *)val;

    if (arla_k_pioctl (NULL, ARLA_AIOC_GETCACHEPARAMS , &a_params, 0) == -1)
	return errno;
    return 0;
}

int
fs_getfilecachestats(int64_t *max_bytes,
		     int64_t *used_bytes,
		     int64_t *low_bytes,
		     int64_t *max_vnodes,
		     int64_t *used_vnodes,
		     int64_t *low_vnodes)
{
    uint32_t oldparms[16];
    struct arlaViceIoctl a_params;

#define query(o,v) \
	if (v && getcacheparam(arla_GETCACHEPARAMS_OPCODE_##o,v)) goto old

    query(HIGHBYTES, max_bytes);
    query(USEDBYTES, used_bytes);
    query(LOWBYTES, low_bytes);
    query(HIGHVNODES, max_vnodes);
    query(USEDVNODES, used_vnodes);
    query(LOWVNODES, low_vnodes);
    
#undef query

    return 0;

 old:
    /* old interface */

    a_params.in_size  = 0;
    a_params.out_size = sizeof(oldparms);
    a_params.in       = NULL;
    a_params.out      = (char *) oldparms;

    memset (oldparms, 0, sizeof(oldparms));

    if (arla_k_pioctl (NULL, ARLA_VIOCGETCACHEPARAMS , &a_params, 0) == -1)
	return errno;

    /* param[0] and param[1] send maxbytes and usedbytes in kbytes */

    if (max_vnodes)
	*max_vnodes = oldparms[2];
    if (used_vnodes)
	*used_vnodes = oldparms[3];
    if (max_bytes)
	*max_bytes = oldparms[4];
    if (used_bytes)
	*used_bytes = oldparms[5];
    if (low_bytes)
	*low_bytes = 0;
    if (low_vnodes)
	*low_vnodes = 0;

    return 0;
}


/*
 *
 */

int
fs_getaviatorstats(uint32_t *max_workers,
		   uint32_t *used_workers)
{
    uint32_t parms[16];
    struct arlaViceIoctl a_params;

    a_params.in_size = 0;
    a_params.out_size = sizeof(parms);
    a_params.in = NULL;
    a_params.out = (char *) parms;

    if (arla_k_pioctl (NULL, ARLA_VIOC_AVIATOR , &a_params, 0) == -1)
	return errno;

    if (max_workers)
	*max_workers = parms[0];
    if (used_workers)
	*used_workers = parms[1];

    return 0;
}

/*
 *
 */

int
fs_gcpags(void)
{
    struct arlaViceIoctl a_params;

    a_params.in_size  = 0;
    a_params.out_size = 0;
    a_params.in       = NULL;
    a_params.out      = NULL;


    if (arla_k_pioctl(NULL, ARLA_VIOC_GCPAGS, &a_params, 0) != 0)
	return errno;
    
    return 0;
}

/*
 *
 */

int
fs_calculate_cache(uint32_t *calculated,
		   uint32_t *usedbytes)
{
    uint32_t parms[16];
    struct arlaViceIoctl a_params;

    a_params.in_size = 0;
    a_params.out_size = sizeof(parms);
    a_params.in = NULL;
    a_params.out = (char *) parms;

    if (arla_k_pioctl (NULL, ARLA_VIOC_CALCULATE_CACHE , &a_params, 0) == -1)
	return errno;

    if (calculated)
	*calculated = parms[0];
    if (usedbytes)
	*usedbytes = parms[1];

    return 0;
}

/*
 *
 */

int
fs_invalidate (const char *path)
{
    struct arlaViceIoctl   a_params;

    a_params.in_size  = 0;
    a_params.out_size = 0;
    a_params.in       = NULL;
    a_params.out      = NULL;
    
    if (arla_k_pioctl ((char *)path, ARLA_VIOC_BREAKCALLBACK, &a_params, 0) < 0)
	return errno;
    else
	return 0;
}

/*
 * Get/set debug levels with pioctl_cmd.
 *
 * inflags == -1 -> don't change
 * outflags == NULL -> don't return
 */

static int
debug (int pioctl_cmd, int inflags, int *outflags, char *pathname)
{
    struct arlaViceIoctl   a_params;

    int32_t rinflags = inflags;
    int32_t routflags;

    if (inflags != -1) {
	a_params.in_size = sizeof(rinflags);
	a_params.in = (char *) &rinflags;
    } else {
	a_params.in_size = 0;
	a_params.in = NULL;
    }
	
    if (outflags) {
	a_params.out_size = sizeof(routflags);
	a_params.out = (char *)  &routflags;
    } else {
	a_params.out_size = 0;
	a_params.out = NULL;
    }

    if (arla_k_pioctl (pathname, pioctl_cmd, &a_params, 0) == -1)
	return errno;
    
    if (outflags)
	*outflags = routflags;

    return 0;
}

/*
 * nnpfs_debug
 */

int
nnpfs_debug(int inflags, int *outflags)
{
    return debug (ARLA_VIOC_NNPFSDEBUG, inflags, outflags, NULL);
}

/*
 * nnpfs_debug_print
 */

int
nnpfs_debug_print(int inflags, char *pathname)
{
    return debug (ARLA_VIOC_NNPFSDEBUG_PRINT, inflags, NULL, pathname);
}

/*
 * arla_debug
 */

int
arla_debug (int inflags, int *outflags)
{
    return debug (ARLA_VIOC_ARLADEBUG, inflags, outflags, NULL);
}

/*
 * checkservers
 *
 *   flags is the same flags as in CKSERV flags
 *
 */

int
fs_checkservers(char *cell, int32_t flags, uint32_t *hosts, int numhosts)
{
    struct arlaViceIoctl a_params;
    char *in = NULL;
    int ret;
    size_t insize;

    if (cell != NULL) {
	insize = strlen(cell) + sizeof(int32_t) + 1;
	in = malloc (insize);
	if (in == NULL)
	    errx (1, "malloc");

	memcpy (in, &flags, sizeof(flags));

	memcpy (in + sizeof(int32_t), cell, strlen(cell));
	in[sizeof(int32_t) + strlen(cell)] = '\0';
	
	a_params.in_size = insize;
	a_params.in = in;
    } else {
	a_params.in_size = sizeof(flags);
	a_params.in = (caddr_t )&flags;
    }

    a_params.out_size = numhosts * sizeof(uint32_t);
    a_params.out = (caddr_t)hosts;

    ret = 0;

    if (arla_k_pioctl (NULL, ARLA_VIOCCKSERV, &a_params, 0) == -1)
	ret = errno;
    
    if (in)
	free(in);

    return ret;
}

/*
 * check validity of cached volume information
 */

int
fs_checkvolumes (void)
{
    struct arlaViceIoctl a_params;

    a_params.in       = NULL;
    a_params.in_size  = 0;
    a_params.out      = NULL;
    a_params.out_size = 0;

    if (arla_k_pioctl (NULL, ARLA_VIOCCKBACK, &a_params, 0) < 0)
	return errno;
    else
	return 0;
}

/*
 * return current sysname in `sys' (of max length `sys_sz')
 */

int
fs_get_sysname (char *sys, size_t sys_sz)
{
    struct arlaViceIoctl a_params;
    int32_t set = 0;
    char *buf;

    buf = malloc (sys_sz + 4);
    if (buf == NULL)
	return ENOMEM;

    a_params.in       = (caddr_t)&set;
    a_params.in_size  = sizeof(set);
    a_params.out      = buf;
    a_params.out_size = sys_sz + 4;

    if(arla_k_pioctl (NULL, ARLA_VIOC_AFS_SYSNAME, &a_params, 1) < 0)
	return errno;
    else {
	strlcpy (sys, buf + 4, sys_sz);
	return 0;
    }
}

/*
 * set current sysname to `sys'
 */

int
fs_set_sysname (const char *sys)
{
    struct arlaViceIoctl a_params;
    int32_t set = 1;

    a_params.in_size  = sizeof(set) + strlen(sys) + 1;
    a_params.in       = malloc(a_params.in_size);
    if (a_params.in == NULL)
	return ENOMEM;
    a_params.out      = NULL;
    a_params.out_size = 0;
    memcpy (a_params.in, &set, sizeof(set));
    strcpy (a_params.in + sizeof(set), sys);

    if(arla_k_pioctl (NULL, ARLA_VIOC_AFS_SYSNAME, &a_params, 1) < 0)
	return errno;
    else
	return 0;
}

/*
 * fs_setcache -- use the old interface, fallback only
 */

static int
fs_setcache(int lv, int hv, int lb, int hb)
{
    struct arlaViceIoctl a_params;
    uint32_t s[4];

    s[0] = lv;
    s[1] = hv;
    s[2] = lb;
    s[3] = hb;

    a_params.in_size  = ((hv == 0) ? 1 : 4) * sizeof(uint32_t);
    a_params.out_size = 0;
    a_params.in       = (void *)s;
    a_params.out      = NULL;

    if (arla_k_pioctl(NULL, ARLA_VIOCSETCACHESIZE, &a_params, 0) < 0)
	return errno;
    else
	return 0;
}

/*
 * setcacheparam -- utility function using the new interface
 */

static int
setcacheparam(int32_t opcode, int64_t *high, int64_t *low)
{
    struct arlaViceIoctl a_params;
    char buf[sizeof(opcode) + sizeof(*high) + sizeof(*low)];
    char *p = buf;

    memcpy(p, &opcode, sizeof(opcode));
    p += sizeof(opcode);

    memcpy(p, high, sizeof(*high));
    p += sizeof(*high);

    memcpy(p, low, sizeof(*low));

    a_params.in_size  = sizeof(opcode) + sizeof(*high) + sizeof(*low);
    a_params.out_size = 0;
    a_params.in       = buf;
    a_params.out      = NULL;

    if (arla_k_pioctl (NULL, ARLA_AIOC_SETCACHEPARAMS , &a_params, 0) == -1)
	return errno;
    return 0;
}

/*
 * fs_setcacheparam -- try new interface first, fall back on old if necessary
 */

int
fs_setcacheparam(int64_t high_bytes,
		 int64_t low_bytes,
		 int64_t high_vnodes,
		 int64_t low_vnodes)
{
    int error = 0;

    if (high_bytes != 0 || low_bytes != 0)
	error = setcacheparam(arla_SETCACHEPARAMS_OPCODE_BYTES,
			      &high_bytes, &low_bytes);
    
    if (error == 0 && (high_vnodes != 0 || low_vnodes != 0))
	error = setcacheparam(arla_SETCACHEPARAMS_OPCODE_VNODES,
			      &high_vnodes, &low_vnodes);
    
    if (error == 0)
	return error;
    
    /* fall back on old style, int32 */
    if (high_bytes > INT_MAX || low_bytes > INT_MAX
	|| high_vnodes > INT_MAX || low_vnodes > INT_MAX)
	return EINVAL;

    return fs_setcache(low_vnodes, high_vnodes, low_bytes, high_bytes);
}

/*
 * return the local cell in `cell' (of size `cell_sz').
 */

int
fs_wscell (char *cell, size_t cell_sz)
{
    struct arlaViceIoctl a_params;

    a_params.in_size  = 0;
    a_params.in       = NULL;
    a_params.out_size = cell_sz;
    a_params.out      = cell;

    if (arla_k_pioctl (NULL, ARLA_VIOC_GET_WS_CELL, &a_params, 0) < 0)
	return errno;
    return 0;
}

/*
 * Flush the contents of the volume pointed to by `path'.
 */

int
fs_flushvolume (const char *path)
{
    struct arlaViceIoctl a_params;

    a_params.in_size  = 0;
    a_params.out_size = 0;
    a_params.in       = NULL;
    a_params.out      = NULL;

    if (arla_k_pioctl ((char *)path, ARLA_VIOC_FLUSHVOLUME, &a_params, 0) < 0)
	return errno;
    else
	return 0;
}

/*
 * Flush the file `path' from the cache.
 */

int
fs_flush (const char *path)
{
    struct arlaViceIoctl a_params;

    a_params.in_size  = 0;
    a_params.out_size = 0;
    a_params.in       = NULL;
    a_params.out      = NULL;

    if (arla_k_pioctl ((char *)path, ARLA_VIOCFLUSH, &a_params, 0) < 0)
	return errno;
    else
	return 0;
}

/*
 *
 */

int
fs_venuslog (void)
{
    struct arlaViceIoctl a_params;
    int32_t status = 0;   /* XXX not really right, but anyway */

    a_params.in_size  = sizeof(int32_t);
    a_params.out_size = 0;
    a_params.in       = (caddr_t) &status;
    a_params.out      = NULL;

    if (arla_k_pioctl (NULL, ARLA_VIOC_VENUSLOG, &a_params, 0) < 0)
	return errno;
    else
	return 0;
}

/*
 * Create a new cell (or change servers for an existing one), with
 * name `cell' and `nservers' servers in `servers'.
 */

int
fs_newcell (const char *cell, int nservers, char **servers)
{
    struct arlaViceIoctl a_params;
    int len;
    char *buf;
    int i, ret;
    uint32_t *hp;

    nservers = min (nservers, 8);

    len = 8 * sizeof(uint32_t) + strlen(cell) + 1;
    buf = malloc (len);
    if (buf == NULL)
	return errno;

    memset (buf, 0, len);
    strcpy (buf + 8 * sizeof(uint32_t), cell);
    hp = (uint32_t *)buf;
    for (i = 0; i < nservers; ++i) {
	struct addrinfo hints, *res;
	
	memset (&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	
	ret = getaddrinfo(servers[i], NULL, &hints, &res);
	if (ret) {
	    free (buf);
	    return EINVAL;
	}
	assert (res->ai_family == PF_INET);
	hp[i] = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;
	freeaddrinfo(res);
    }

    a_params.in_size  = len;
    a_params.out_size = 0;
    a_params.in       = (caddr_t)buf;
    a_params.out      = NULL;

    ret = arla_k_pioctl (NULL, ARLA_VIOCNEWCELL, &a_params, 0);
    free (buf);
    if (ret < 0)
	return errno;
    return 0;
}

/*
 * Fetch cell status for cell `num', and put the ip-numbers to the servers
 * in the array `server' of length `numservers'. `Cell' is the name
 * of the cell and has length `sell_sz'.
 */

int
fs_getcells (int32_t num, uint32_t *server, int numservers,
	     char *cell, size_t cell_sz)
{
    struct arlaViceIoctl   a_params;
    int32_t *server_list;
    int i;
    
    if (server == NULL && numservers != 0)
	return EINVAL;

    memset(server, 0, numservers * sizeof(*server));

#define GETCELL_MAXSERVER 8
    a_params.in_size = sizeof (num);
    a_params.out_size = sizeof (uint32_t) * GETCELL_MAXSERVER + cell_sz + 1;
    a_params.in = (char *) &num;
    a_params.out = malloc (a_params.out_size);
    
    if (a_params.out == NULL)
	return ENOMEM;

    server_list = (int32_t *) a_params.out;

    if (arla_k_pioctl (NULL, ARLA_VIOCGETCELL, &a_params, 0) != 0)
	return errno;
    
    if (numservers > GETCELL_MAXSERVER)
	numservers = GETCELL_MAXSERVER;
    for (i = 0 ; i < numservers; i++)
	server[i] = server_list[i];

    strlcpy (cell, 
	     (char *) a_params.out +  GETCELL_MAXSERVER * sizeof(uint32_t),
	     cell_sz);
    
    return 0;
}

/*
 * Get status for `cell' and put the flags in `flags'.
 */

int
fs_getcellstatus (char *cellname, uint32_t *flags)
{
    struct arlaViceIoctl a_params;

    a_params.in_size  = strlen (cellname) + 1;
    a_params.out_size = sizeof (uint32_t);
    a_params.in       = cellname;
    a_params.out      = (caddr_t) flags;

    if (arla_k_pioctl (NULL, ARLA_VIOC_GETCELLSTATUS, &a_params, 0) < 0)
	return errno;
    else
	return 0;
}

/*
 * Separate `path' into directory and last component and call
 * pioctl with `pioctl_cmd'.
 */

static int
internal_mp (const char *path, int pioctl_cmd, char **res)
{
    struct arlaViceIoctl    a_params;
    char               *last;
    char               *path_bkp;
    int			error;

    path_bkp = strdup (path);
    if (path_bkp == NULL) {
	printf ("fs: Out of memory\n");
	return ENOMEM;
    }

    a_params.out = malloc (PIOCTL_MAXSIZE);
    if (a_params.out == NULL) {
	printf ("fs: Out of memory\n");
	free (path_bkp);
	return ENOMEM;
    }

    /* If path contains more than the filename alone - split it */

    last = strrchr (path_bkp, '/');
    if (last != NULL) {
	*last = '\0';
	a_params.in = last + 1;
    } else 
	a_params.in = (char *)path;

    if (strcmp((char *)a_params.in, ".") == 0
	|| strcmp((char *)a_params.in, "..") == 0) {
	printf("fs: don't use '%s' as the last component in lsmount\n",
	       (char *)a_params.in);
	free (path_bkp);
	return ENOMEM;
    }
    
    a_params.in_size = strlen (a_params.in) + 1;
    a_params.out_size = PIOCTL_MAXSIZE;

    error = arla_k_pioctl (last ? path_bkp : "." ,
		      pioctl_cmd, &a_params, 1);
    if (error < 0) {
	error = errno;
	free (path_bkp);
	free (a_params.out);
	return error;
    }

    if (res != NULL)
	*res = a_params.out;
    else
	free (a_params.out);
    free (path_bkp);
    return 0;
}

int
fs_lsmount (const char *path)
{
    char *res;
    int error = internal_mp (path, ARLA_VIOC_AFS_STAT_MT_PT, &res);

    if (error == 0) {
	printf ("'%s' is a mount point for volume '%s'\n", path, res);
	free (res);
    }
    return error;
}

int
fs_rmmount (const char *path)
{
    return internal_mp (path, ARLA_VIOC_AFS_DELETE_MT_PT, NULL);
}

int
fs_incompat_renumber (int *ret)
{
    struct arlaViceIoctl a_params;
    unsigned char buf[1024];

    a_params.in_size  = 0;
    a_params.out_size = sizeof(buf);
    a_params.in       = 0;
    a_params.out      = (caddr_t) buf;

    /* getcrypt or getinitparams */
    if (arla_k_pioctl (NULL, _VICEIOCTL(49), &a_params, 0) < 0) {
	if (errno == EINVAL) {

	    /* not openafs or old openafs */

	    a_params.in_size  = 0;
	    a_params.out_size = 4;
	    a_params.in       = 0;
	    a_params.out      = (caddr_t) buf;
	    
	    if (arla_k_pioctl (NULL, _VICEIOCTL(49), &a_params, 0) < 0) {
		if (errno == EINVAL) {
		    
		    a_params.in_size  = 0;
		    a_params.out_size = 4;
		    a_params.in       = 0;
		    a_params.out      = (caddr_t) buf;
		    
		    /* might be new interface */

		    if (arla_k_pioctl (NULL, _VICEIOCTL(55), &a_params, 0) < 0)
			return errno; /* dunno */
		    
		    *ret = 1;
		    return 0;
		} else {
		    return errno;
		}
	    }
	    *ret = 0;
	    return 0;
	} else
	    return errno;
    }
    *ret = 1;
    return 0;
}


/*
 *
 */

int
fs_statistics_list(uint32_t *host, uint32_t *part, int *n)
{
    uint32_t data[512];
    uint32_t indata;
    struct arlaViceIoctl a_params;
    int i;

    indata = arla_STATISTICS_OPCODE_LIST;

    a_params.in_size  = sizeof(indata);
    a_params.out_size = sizeof(data);
    a_params.in       = (char *) &indata;
    a_params.out      = (char *) data;

    memset (data, 0, sizeof(data));

    if (arla_k_pioctl (NULL, ARLA_AIOC_STATISTICS , &a_params, 0) == -1)
	return errno;

    if (data[0] < *n)
	*n = data[0];

    for (i = 0; i < *n; i++) {
	host[i] = data[2 * i + 1];
	part[i] = data[2 * i + 2];
    }

    return 0;
}

int
fs_statistics_entry(uint32_t host, uint32_t part, uint32_t type,
		    uint32_t items_slot, uint32_t *count,
		    int64_t *items_total, int64_t *total_time)
{
    uint32_t data[160];
    uint32_t indata[5];
    struct arlaViceIoctl a_params;
    int i;
    int j;

    indata[0] = arla_STATISTICS_OPCODE_GETENTRY;
    indata[1] = host;
    indata[2] = part;
    indata[3] = type;
    indata[4] = items_slot;

    a_params.in_size  = sizeof(indata);
    a_params.out_size = sizeof(data);
    a_params.in       = (char *) indata;
    a_params.out      = (char *) data;

    memset (data, 0, sizeof(data));

    if (arla_k_pioctl (NULL, ARLA_AIOC_STATISTICS , &a_params, 0) == -1)
	return errno;

    j = 0;
    for (i = 0; i < 32; i++) {
	count[i] = data[j++];
    }
    for (i = 0; i < 32; i++) {
	memcpy(&items_total[i], &data[j], 8);
	j+=2;
    }
    for (i = 0; i < 32; i++) {
	memcpy(&total_time[i], &data[j], 8);
	j+=2;
    }

    return 0;
}
