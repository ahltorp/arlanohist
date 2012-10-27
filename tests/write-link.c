/*
 * Copyright (c) 2006-2007 Kungliga Tekniska Högskolan
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

#include <roken.h>
#include <err.h>

RCSID("$Id: write-link.c,v 1.1 2007/01/03 13:07:08 tol Exp $");

#define BUF_SIZE	(64 * 1024)
#define FILE_SIZE       (9 * BUF_SIZE)

/*
 * check that link() doesn't cause statinfo to be corrupted/reverted
 * for dirty file.
 */

static void
doit(const char *filename, const char *linkname)
{
    ssize_t bytes = 0;
    struct stat sb;
    off_t offset;
    int fd, ret;

    char *buf = malloc(BUF_SIZE);
    if (!buf)
	err(1, "malloc failed");

    fd = open(filename, O_WRONLY | O_TRUNC | O_CREAT, 0666);
    if (fd < 0)
	err(1, "open %s", filename);
    
    for (offset = 0; offset < FILE_SIZE; offset += bytes) {
	bytes = write(fd, buf, BUF_SIZE);
	if (bytes != BUF_SIZE)
	    err(1, "write at %llu", (unsigned long long)offset);
    }

    ret = link(filename, linkname);
    if (ret < 0)
	err (1, "link");

    ret = lstat(linkname, &sb);
    if (ret < 0)
	err (1, "stat");

    if (sb.st_nlink != 2)
	errx(1, "nlink not 2 (%d)", sb.st_nlink);

    if (sb.st_size != offset)
	errx(1, "bad size %d", (int)sb.st_size);

    if (close(fd) < 0)
	err(1, "close %s", filename);

    if (unlink(linkname) < 0)
	err(1, "unlink %s", linkname);

    if (unlink(filename) < 0)
	err(1, "unlink %s", filename);

    free(buf);
}

int
main(int argc, char **argv)
{
    setprogname(argv[0]);

    doit("foo", "bar");

    return 0;
}
