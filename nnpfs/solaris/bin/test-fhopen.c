/*
 * Copyright (c) 1998 Kungliga Tekniska Högskolan
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

#include <config.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <err.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <atypes.h>
#include <sys/ioccom.h>
#include <kafs.h>

RCSID("$Id: test-fhopen.c,v 1.2 2000/10/02 23:54:00 lha Exp $");

static int
fhget (char *filename, char buf[76])
{
    struct ViceIoctl vice_ioctl;

    vice_ioctl.out      = (caddr_t)buf;
    vice_ioctl.out_size = 76;

    return k_pioctl (filename, VIOC_FHGET, &vice_ioctl, 0);
}

static int
fhopen (char buf[76], int flags)
{
    struct ViceIoctl vice_ioctl;

    vice_ioctl.in      = buf;
    vice_ioctl.in_size = 76;

    return k_pioctl (NULL, VIOC_FHOPEN, &vice_ioctl, flags);
}

static void
doit (const char *fname)
{
    int ret;
    int fd;
    char buf[1024];
    char fh[76];

    ret = fhget (fname, fh);
    if (ret < 0)
	err (1, "fhget %s", fname);

    fd = fhopen (fh, O_RDONLY);
    if (fd < 0)
	err (1, "fhopen");
    while ((ret = read (fd, buf, sizeof(buf))) > 0) {
	write (STDOUT_FILENO, buf, ret);
    }
    close (fd);
}

int
main(int argc, char **argv)
{
    int i;

    k_hasafs ();

    for (i = 1; i < argc; ++i)
	doit (argv[i]);
    return 0;
}
