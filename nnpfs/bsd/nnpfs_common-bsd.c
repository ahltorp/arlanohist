/*
 * Copyright (c) 1995 - 2006 Kungliga Tekniska Högskolan
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

#include <nnpfs/nnpfs_locl.h>
#include <nnpfs/nnpfs_common.h>
#include <nnpfs/nnpfs_deb.h>

RCSID("$Id: nnpfs_common-bsd.c,v 1.36 2010/06/16 19:58:51 tol Exp $");

#ifdef MALLOC_DEFINE
MALLOC_DEFINE(M_NNPFS, "nnpfs-misc", "nnpfs misc");
MALLOC_DEFINE(M_NNPFS_NODE, "nnpfs-node", "nnpfs node");
MALLOC_DEFINE(M_NNPFS_LINK, "nnpfs-link", "nnpfs link");
MALLOC_DEFINE(M_NNPFS_MSG, "nnpfs-msg", "nnpfs msg");
MALLOC_DEFINE(M_NNPFS_BLOCKS, "nnpfs-blocks", "nnpfs blocklist");
#endif

#ifdef NNPFS_DEBUG
static u_int nnpfs_allocs;
static u_int nnpfs_frees;

void *
nnpfs_alloc(u_int size, nnpfs_malloc_type type)
{
    void *ret;

    nnpfs_allocs++;
    NNPFSDEB(XDEBMEM, ("nnpfs_alloc: nnpfs_allocs - nnpfs_frees %d\n", 
		     nnpfs_allocs - nnpfs_frees));

#if (defined(__OpenBSD__) && OpenBSD >= 200811)
    ret = malloc(size, type, M_WAITOK);
#else
    MALLOC(ret, void *, size, type, M_WAITOK);
#endif
    return ret;
}

void
nnpfs_free(void *ptr, u_int size, nnpfs_malloc_type type)
{
    nnpfs_frees++;
#if (defined(__OpenBSD__) && OpenBSD >= 200811)
    free(ptr, type);
#else
    FREE(ptr, type);
#endif
}

#endif /* NNPFS_DEBUG */

/*
 * Return zero if privileged enough to set nnpfs debug flags.
 */
int
nnpfs_priv_check_debug(d_thread_t *p)
{
#ifdef HAVE_KERNEL_PRIV_CHECK
#ifdef PRIV_NNPFS_DEBUG
    return priv_check(p, PRIV_NNPFS_DEBUG);
#else
    return priv_check(p, PRIV_ROOT);
#endif
#elif defined(__APPLE__)
    return proc_suser(p);
#elif defined(HAVE_KERNEL_KAUTH_CRED_GETUID)
    uid_t uid = kauth_cred_getuid(p->l_proc->p_cred);
    if (uid == 0)
	return 0;
    return EPERM;
#elif defined(HAVE_KERNEL_SUSER_UCRED)
    return suser_ucred(nnpfs_proc_to_cred(p));
#elif defined(HAVE_TWO_ARGUMENT_SUSER)
    return suser(nnpfs_proc_to_cred(p), NULL);
#else
    return suser(p);
#endif
}

/*
 * Print a `nnpfs_dev_t' in some readable format
 */

#ifdef HAVE_KERNEL_DEVTONAME

const char *
nnpfs_devtoname_r (nnpfs_dev_t dev, char *buf, size_t sz)
{
    return devtoname (dev);
}

#else /* !HAVE_KERNEL_DEVTONAME */

const char *
nnpfs_devtoname_r (nnpfs_dev_t dev, char *buf, size_t sz)
{
#ifdef HAVE_KERNEL_SNPRINTF
    snprintf (buf, sz, "%u/%u", nnpfs_major(dev), nnpfs_minor(dev));
    return buf;
#else
    return "<unknown device>";
#endif
}

#endif /* HAVE_KERNEL_DEVTONAME */
