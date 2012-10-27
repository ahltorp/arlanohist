/*
 * Copyright (c) 2003 Kungliga Tekniska Högskolan
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
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <err.h>
#include <roken.h>

#ifndef MAP_FAILED
#define MAP_FAILED ((void *)-1)
#endif

#ifdef RCSID
RCSID("$Id: mmap-and-fork.c,v 1.7 2003/02/28 17:17:57 lha Exp $");
#endif

static void
doit (const char *filename, int close_before_p, int unmapp)
{
    pid_t pid;
    int fd;
    size_t sz = getpagesize ();
    void *v;

    fd = open (filename, O_RDWR | O_CREAT, 0600);
    if (fd < 0)
	err (1, "open %s", filename);
    if (ftruncate (fd, sz) < 0)
	err (1, "ftruncate %s", filename);
    v = mmap (NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (v == (void *)MAP_FAILED)
	err (1, "mmap %s", filename);

    memset (v, 'z', sz);

    if (close_before_p)
	close(fd);

    pid = fork();
    if (pid < 0)
	errx (1, "fork failed");

    if (pid == 0) {
	memset (v, 'x', sz);
	_exit(0);
    } else {
	int stat;
	if (waitpid (pid, &stat, 0) < 0)
	    errx(1, "waitpid");
    }
    memset (v, 'y', sz);

    if (!close_before_p)
	close(fd);

    if (unmapp)
	munmap(v, sz);

}

int
main (int argc, char **argv)
{
    setprogname(argv[0]);

    doit ("foo1", 0, 0);
    doit ("foo2", 1, 0);
    doit ("foo3", 0, 1);
    doit ("foo4", 1, 1);

    doit ("foo1", 0, 0);
    doit ("foo2", 1, 0);
    doit ("foo3", 0, 1);
    doit ("foo4", 1, 1);

    unlink("foo1");
    unlink("foo2");
    unlink("foo3");
    unlink("foo4");

    return 0;
}
