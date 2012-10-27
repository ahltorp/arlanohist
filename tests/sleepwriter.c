/*
 * Copyright (c) 2001, 2006 Kungliga Tekniska Högskolan
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
#include <fcntl.h>
#include <unistd.h>

#include <roken.h>
#include <err.h>

RCSID("$Id: sleepwriter.c,v 1.1 2007/01/03 13:11:01 tol Exp $");

#define BUF_SIZE	(128*1024)
#define TOTAL_SIZE	(8 * BUF_SIZE)

static void
doit(const char *filename)
{
    size_t sz = BUF_SIZE;
    size_t nbytes = TOTAL_SIZE;
    char *buf = malloc(sz);
    off_t offset = 0;
    int fd, ret;

    if (!buf)
	errx(1, "malloc failed");

    memset(buf, 0, BUF_SIZE);

    fd = open(filename, O_RDWR | O_TRUNC | O_CREAT, 0666);
    if (fd < 0)
	err(1, "open %s", filename);

    while (offset < nbytes) {
	ret = write(fd, buf, sz);
	if (ret != sz)
	    err(1, "write at %llu", (unsigned long long)offset);
	offset += sz;
	(void)sleep(1);
    }
    
    (void)close(fd);

    free(buf);
}

int
main(int argc, char **argv)
{
    setprogname(argv[0]);

    if (argc == 1)
	doit("foo");
    else if (argc == 2)
	doit(argv[1]);
    else
	errx(1, "usage: %s [filename]", argv[0]);
    return 0;
}
