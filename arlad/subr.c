/*
 * Copyright (c) 1995-2002, 2005-2006 Kungliga Tekniska Högskolan
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

#include "arla_local.h"
RCSID("$Id: subr.c,v 1.15 2006/10/24 16:32:51 tol Exp $");

/*
 * come up with a good inode number for `name', `fid' in `parent'
 */

ino_t
dentry2ino (const char *name, const VenusFid *fid, const FCacheEntry *parent)
{
    if (strcmp (name, ".") == 0
	&& (parent->flags.vol_root
	    || (fid->fid.Vnode == 1 && fid->fid.Unique == 1))
	&& parent->volume != NULL) {

	long voltype = getvoltype(fid->fid.Volume, parent->volume);
	return afsfid2inode (&parent->volume->parent[voltype].mp_fid);

    } else if (strcmp (name, "..") == 0
	       && (parent->flags.vol_root
		   || (parent->fid.fid.Vnode == 1
		       && parent->fid.fid.Unique == 1))
	       && parent->volume != NULL) {

	long voltype = getvoltype(fid->fid.Volume, parent->volume);
	return afsfid2inode (&parent->volume->parent[voltype].fid);

    } else if (strcmp (name, "..") == 0
	       && fid->fid.Vnode == 1 && fid->fid.Unique == 1
	       && parent->volume != NULL) {

	long voltype = getvoltype(fid->fid.Volume, parent->volume);
	return afsfid2inode (&parent->volume->parent[voltype].mp_fid);

    } else {
	return afsfid2inode (fid);
    }
}

/*
 * Assume `e' has valid data.
 */

int
conv_dir_sub(FCacheEntry *e, CredCacheEntry *ce, u_int tokens,
	     fdir_readdir_func func,
	     void (*flush_func)(void *),
	     size_t blocksize)
{
     int flags = O_WRONLY | O_CREAT | O_TRUNC | O_BINARY;
     struct write_dirent_args args;
     int ret;
     fbuf the_fbuf;

     e->flags.extradirp = TRUE;
     args.fd = fcache_open_extra_dir(e, flags, 0666);
     if (args.fd == -1) {
	  ret = errno;
	  arla_warn (ADEBWARN, ret, "open index %u", e->index);
	  return ret;
     }

     /* ret = fcache_fhget (cache_name, cache_handle); */

     args.off  = 0;
     args.buf  = (char *)malloc (blocksize);
     if (args.buf == NULL) {
	 ret = errno;
	 arla_warn (ADEBWARN, ret, "malloc %u", (unsigned)blocksize);
	 close (args.fd);
	 return ret;
     }
     memset(args.buf, 0, blocksize);

     ret = fcache_get_fbuf(e, &the_fbuf, FBUF_READ);
     if (ret) {
	 close (args.fd);
	 free (args.buf);
	 return ret;
     }
     
     args.ptr  = args.buf;
     args.last = NULL;
     args.e    = e;
     args.ce   = ce;
     
     /* translate to local dir format, write in args.fd */
     fdir_readdir (&the_fbuf, func, (void *)&args, e->fid, NULL);

     abuf_end (&the_fbuf);

     if (args.last)
	  (*flush_func) (&args);
     free (args.buf);
     ret = close (args.fd);
     if (ret)
	  ret = errno;
     return ret;
}
