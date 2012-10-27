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
    fprintf (stderr, "Usage: %s device path\n", progname);
    exit (1);
}

static int
roundup (int a, int base)
{
    return (a + base - 1) / base * base;
}

int
main(int argc, char **argv)
{
    struct vmount *mnt;
    size_t sz;
    int ret;
    char *object;
    char *stub;
    char *dummy;
    size_t offset;
    size_t object_len, stub_len, dummy_len;

    if (argc != 3)
	usage (argv[0]);
    
    object = argv[1];
    stub   = argv[2];
    dummy  = "";

    object_len = strlen(object) + 1;
    stub_len   = strlen(stub) + 1;
    dummy_len  = strlen(dummy) + 1;

    sz = sizeof(struct vmount) + roundup (object_len, 4)
	+ roundup (stub_len, 4) + roundup (dummy_len, 4);
    mnt = malloc (sz);
    if (mnt == NULL) {
	perror ("malloc");
	return 1;
    }
    memset (mnt, 0, sz);

    mnt->vmt_revision = VMT_REVISION;
    mnt->vmt_length   = sz;
    mnt->vmt_flags    = 0;
    mnt->vmt_gfstype  = MNT_USRVFS;

    offset = sizeof(struct vmount);

    mnt->vmt_data[VMT_OBJECT].vmt_off  = offset;
    mnt->vmt_data[VMT_OBJECT].vmt_size = object_len;
    strcpy ((char *)mnt + offset, object);

    offset += roundup(object_len, 4);

    mnt->vmt_data[VMT_STUB].vmt_off  = offset;
    mnt->vmt_data[VMT_STUB].vmt_size = stub_len;
    strcpy ((char *)mnt + offset, stub);

    offset += roundup(stub_len, 4);

    mnt->vmt_data[VMT_LASTINDEX].vmt_off  = offset;
    mnt->vmt_data[VMT_LASTINDEX].vmt_size = dummy_len;
    strcpy ((char *)mnt + offset, dummy);

    offset += roundup(dummy_len, 4);

    ret = vmount (mnt, sz);
    if (ret) {
	perror("mount");
	return ret;
    }
    return 0;
}
