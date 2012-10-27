/*
 * Copyright (c) 1995 - 2000, 2002, 2005 Kungliga Tekniska Högskolan
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

#include "mount_locl.h"

#ifdef RCSID
RCSID("$Id: mount_nnpfs.c,v 1.22 2008/02/26 21:59:16 tol Exp $");
#endif

static const struct mntopt mopts[] = {
    MOPT_STDOPTS,
#ifdef MNT_NOATIME
    MOPT_NOACCESSTIME,
    MOPT_NOATIME,
#endif
#ifdef MNT_UNION
    MOPT_UNION,
#endif
#ifdef MNT_NODEV
    MOPT_NODEV,
#endif
    MOPT_ASYNC,
    MOPT_SYNC,
    MOPT_UPDATE,
    MOPT_RELOAD,
    {NULL}
};

static void
usage(const char *name)
{
    fprintf(stderr, "Usage: %s [-o options] [-F flags] device path\n", 
	    name);
    exit(1);
}

int
main(int argc, char **argv)
{
    int error;
    int ch, mntflags = 0;
    char *fsname = "nnpfs";
    char *name;
    char *dir;
    void *data;

    name = strrchr(argv[0], '/');
    if (name)
	name++;
    else
	name = argv[0];

    optind = 1;
#ifdef HAVE_OPTRESET
    optreset = 1;
#endif

    while ((ch = getopt(argc, argv, "o:F:")) != -1)
	switch (ch) {
	case 'o':
	    getmntopts(optarg, mopts, &mntflags);
	    break;
	case 'F':
	    mntflags = atoi(optarg);
	    break;
	case '?':
	default:
	    usage(name);
	}

    argc -= optind;
    argv += optind;

    if (argc != 2)
	usage(name);

    dir = argv[1];
    data = argv[0];

    error = mount(fsname, dir, mntflags, data);

    if (error != 0)
	err(1, "mount");

#ifdef __APPLE__
    {
	mach_port_t port;
	
	error = DiskArbStart(&port);
	if (!error) {
	    error = DiskArbDiskAppearedWithMountpointPing_auto(fsname,
							       DiskArbDiskMask,
							       dir);
	}
    }
#endif

    return 0;
}
