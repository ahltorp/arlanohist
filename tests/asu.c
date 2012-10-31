/*
 * Copyright (c) 2001 - 2002 Kungliga Tekniska Högskolan
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

#ifdef HAVE_CONFIG_H
#include <config.h>
RCSID("$Id: asu.c,v 1.10 2006/02/07 21:12:09 lha Exp $");
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <pwd.h>
#include <unistd.h>

#include <roken.h>

#include <atypes.h>

#ifdef KERBEROS
#include <kafs.h>
#endif

#include <err.h>

static void
usage(int exit_val)
{
    fprintf(stderr, "%s user program [arguments ...]\n", getprogname());
    exit(exit_val);
}

#define NNPFS_PAG1_LLIM 33536
#define NNPFS_PAG1_ULIM 34560
#define NNPFS_PAG2_LLIM 32512
#define NNPFS_PAG2_ULIM 48896

static int
is_pag(void)
{
#ifdef NGROUPS_MAX
    gid_t groups[NGROUPS_MAX];
    int num;
    int base = 0;
    gid_t egid = getegid();

    num = getgroups(NGROUPS_MAX, groups);
    if (num < 0)
	err(1, "getgroups failed");
    
    if (num >= 1 && groups[0] == egid)
	base = 1;

    if (num >= 2 + base && 
	groups[base] >= NNPFS_PAG1_LLIM &&
	groups[base] <= NNPFS_PAG1_ULIM &&
	groups[base + 1] >= NNPFS_PAG2_LLIM &&
	groups[base + 1] <= NNPFS_PAG2_ULIM)
	return 1;
#endif /* NGROUPS_MAX */

    return 0;
}

int
main(int argc, char **argv)
{
    const char *user, *prog;

    setprogname(argv[0]);

    if (argc < 3)
	usage(1);

    user = argv[1];
    prog = argv[2];

    if (getuid() == 0 && is_pag()) {
	struct passwd *pw;
	gid_t groups[1];
	uid_t uid;
	gid_t gid;

	pw = getpwnam(user);
	if(pw == NULL)
	    errx(1, "no such user %s", user);
	
	uid = pw->pw_uid;
	gid = pw->pw_gid;
	groups[0] = gid;
	
	if (setgroups(1, groups))
	    errx(1, "setgroups failed");

	setgid(gid);
	setuid(uid);
	setegid(gid);
	seteuid(uid);
    }

#if 0
    if (k_hasafs()) {
	int ret = k_setpag();
	if (ret < 0)
	    warn("k_setpag");
    }
#endif

    execvp(prog, &argv[2]);

    err(1, "failed to execute %s", prog);
}
