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
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#ifdef KERBEROS
#include <kafs.h>
#endif
#include <fs.h>
#include <arlalib.h>

#include <roken.h>
#include <err.h>

RCSID("$Id: write4.c,v 1.3 2007/02/19 10:45:28 tol Exp $");

#define BLOCK_SIZE	(256*1024)
#define BUF_SIZE	1024

/*
 * write a sparse file, check that we get zeroes in the right places
 * and correct data where we've written.
 */

static void
writeat(int fd, off_t offset, char *buf, size_t sz)
{
    if (lseek(fd, offset, SEEK_SET) != offset)
	err(1, "lseek/w at %llu", (unsigned long long)offset);
    
    if (write(fd, buf, sz) != sz)
	err(1, "write at %llu", (unsigned long long)offset);
}

static void
readat(int fd, off_t offset, char *buf, const char *data, size_t sz)
{
    if (lseek(fd, offset, SEEK_SET) != offset)
	err(1, "lseek/r at %llu", (unsigned long long)offset);
    
    if (read(fd, buf, sz) != sz)
	err(1, "read at %llu", (unsigned long long)offset);

    if (memcmp(buf, data, sz)) {
	fprintf(stderr, "read %x, expected %x\n",
		*(unsigned*)buf, *(unsigned*)data);
	errx(1, "memcmp at %llu", (unsigned long long)offset);
    }
}

static void
do_rw(const char *filename, int flushp)
{
    int fd, ret;

    char *databuf = malloc(BUF_SIZE);
    char *zerobuf = malloc(BUF_SIZE);
    char *scratch = malloc(BUF_SIZE);

    if (!databuf || !zerobuf || !scratch)
	errx(1, "malloc failed");

    memset(databuf, 0xe3, BUF_SIZE);
    memset(zerobuf, 0, BUF_SIZE);

    fd = open(filename, O_RDWR | O_TRUNC | O_CREAT, 0666);
    if (fd < 0)
	err(1, "open %s", filename);

    writeat(fd, 5 * BLOCK_SIZE, databuf, BUF_SIZE);

    if (flushp) {
	if (close(fd) < 0)
	    err(1, "close %s", filename);
	
	ret = fs_flush(filename);
	if (ret)
	    err(1, "flush %s", filename);
	
	fd = open(filename, O_RDWR, 0666);
	if (fd < 0)
	    err(1, "open2 %s", filename);
    }

    writeat(fd, 9 * BLOCK_SIZE, databuf, BUF_SIZE);

    readat(fd, 2 * BLOCK_SIZE, scratch, zerobuf, BUF_SIZE);
    readat(fd, 7 * BLOCK_SIZE, scratch, zerobuf, BUF_SIZE);
    readat(fd, 8 * BLOCK_SIZE, scratch, zerobuf, BUF_SIZE);

    readat(fd, 5 * BLOCK_SIZE, scratch, databuf, BUF_SIZE);
    readat(fd, 9 * BLOCK_SIZE, scratch, databuf, BUF_SIZE);

    if (close(fd) < 0)
	err(1, "close %s", filename);

    if (unlink(filename) < 0)
	err(1, "unlink %s", filename);

    free(databuf);
    free(zerobuf);
    free(scratch);
}

static void
doit(const char *filename)
{
    do_rw(filename, 0);
    do_rw(filename, 1);
}

int
main(int argc, char **argv)
{
    setprogname(argv[0]);

#ifdef KERBEROS
    if (!k_hasafs())
#endif
	exit (1);

    if (argc == 1)
	doit("foo");
    else if (argc == 2)
	doit(argv[1]);
    else
	errx(1, "usage: %s [filename]", argv[0]);
    return 0;
}
