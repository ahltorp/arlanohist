/*
 * Copyright (c) 2000, 2006 Kungliga Tekniska Högskolan
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
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <err.h>
#include <roken.h>

RCSID("$Id: truncate-write.c,v 1.2 2006/10/24 16:33:57 tol Exp $");

/*
 * truncate-write:
 *
 * tries to trigger a case where nnpfs believes it has blocks beyond
 * eof on a newly truncated file, which causes arlad to be surprised
 * about the length of the subsequent write.
 *
 * Fixed in nnpfs/bsd/nnpfs_message.c: 1.99.4.16.
 */

static void
create_and_write(char *name, const char *buf, int len)
{
    int fd, ret;
    fd = open(name, O_WRONLY|O_CREAT|O_TRUNC, 0666);
    if (fd < 0)
	err(1, "open");
    ret = write(fd, buf, len);
    if (ret != len)
	err(1, "write");
    ret = close(fd);
    if (ret < 0)
	err(1, "close");
}

static void
write_and_truncate(char *name, const char *buf, int len)
{
    int fd, ret;
    fd = open(name, O_WRONLY);
    if (fd < 0)
	err(1, "open");
    ret = write(fd, buf, len);
    if (ret != len)
	err(1, "write");
    ret = ftruncate(fd, 0);
    if (ret < 0)
	err(1, "ftruncate");
    ret = close(fd);
    if (ret < 0)
	err(1, "close");
}

int
main(int argc, char **argv)
{
    int ret;
    int size = 260*1024; /* keep it larger than block size */
    char *buf = malloc(size);

    setprogname(argv[0]);

    memset(buf, 'c', size);

    create_and_write("foo", buf, size);
    create_and_write("foo", buf, size);

    write_and_truncate("foo", buf, size);
    write_and_truncate("foo", buf, size);

    ret = unlink("foo");
    if (ret < 0)
	err(1, "unlink");

    free(buf);

    return 0;
}
