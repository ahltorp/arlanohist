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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/vmount.h>

static void
usage(char *progname)
{
    fprintf (stderr, "Usage: %s path\n", progname);
    exit (1);
}

int
main(int argc, char **argv)
{
    char *fs;
    int ret;
    char *buf;
    size_t buf_size;
    struct vmount *vmnt;
    int i;
    int vfs_no = -1;

    if (argc != 2)
	usage (argv[0]);

    fs = argv[1];
    
    buf_size = 1024;
    buf = malloc (buf_size);
    if (buf == NULL) {
	perror ("malloc");
	return 1;
    }
    do {
	ret = mntctl (MCTL_QUERY, buf_size, buf);
	if (ret < 0) {
	    perror ("mntctl");
	    return 1;
	} else if (ret == 0) {
	    buf_size = *((unsigned int *)buf);
	    buf = realloc (buf, buf_size);
	    if (buf == NULL) {
		perror ("realloc");
		return 1;
	    }
	}
    } while(ret <= 0);

    vmnt = (struct vmount *)buf;

    for (i = 0; i < ret; ++i) {
	char *stub = vmt2dataptr(vmnt, VMT_STUB);

	if (strcmp (stub, fs) == 0) {
	    vfs_no = vmnt->vmt_vfsnumber;
	    break;
	}
	vmnt = (struct vmount *)((char *)vmnt + vmnt->vmt_length);
    }

    free (buf);

    if (vfs_no == -1) {
	fprintf (stderr, "%s: %s not mounted\n", argv[0], fs);
	return 1;
    }

    ret = uvmount (vfs_no, /*flag*/ 0);
    if (ret < 0) {
	perror ("uvmount");
	return 1;
    }
    return 0;
}
