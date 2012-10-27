/*
 * Copyright (c) 2003, Stockholms Universitet
 * (Stockholm University, Stockholm Sweden)
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
 * 3. Neither the name of the university nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <atypes.h>

#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif

int
main(int argc, char **argv)
{
    off_t large = 2147483647; /* 2G-1; */
    off_t larger = ((uint64_t)1 << 33) + 1; /* 8G+1; */
    char buf[1024 * 8];
    int fd;
    const char *fn = "f-file";
    FILE *verbose_fp;

    verbose_fp = fdopen (4, "w");
    if (verbose_fp == NULL) {
	verbose_fp = fopen ("/dev/null", "w");
	if (verbose_fp == NULL)
	    err (1, "fopen");
    }

    if ((fd = open(fn, O_RDWR|O_CREAT|O_LARGEFILE, 0600)) < 0)
	err(1, "open");

    pread(fd, buf, sizeof(buf), large);

    if (ftruncate(fd, large - sizeof(buf)) < 0) {
#ifdef EDQUOT
	if (errno == EDQUOT)
	    warnx("get yourself more quota for this test, you'll need at least 2G free");
#endif
	err(1, "ftruncate");
    }
    pread(fd, buf, sizeof(buf), large - sizeof(buf));

    /* now try even larger */
    pread(fd, buf, sizeof(buf), larger);

    if (ftruncate(fd, larger + sizeof(buf)) < 0) {
	if (errno != E2BIG && errno != EFBIG)
	    err(1, "ftruncate > 32bit file");
	fprintf(verbose_fp, "ftruncate > 32bit file: %s(%d)\n",
		strerror(errno), errno);
    }
    pread(fd, buf, sizeof(buf), larger);

    if (ftruncate(fd, 0) < 0)
	err(1, "ftruncate");

    close(fd);

    unlink(fn);

    return 0;
}
