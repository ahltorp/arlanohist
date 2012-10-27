/*
 * Copyright (c) 2006, Stockholms Universitet
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

#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <roken.h>
#include <sha.h>

#ifdef RCSID
RCSID("$Id: sha1sum.c,v 1.2 2007/01/12 16:42:30 tol Exp $");
#endif

static int
do_read(int fd, size_t sz)
{
    unsigned char res[SHA_DIGEST_LENGTH];
    SHA_CTX ctx;
    ssize_t ret;
    char *buf;
    int i;

    buf = malloc(sz);
    if (buf == NULL)
	err(1, "malloc %u", (unsigned)sz);

    SHA1_Init(&ctx);

    while ((ret = read(fd, buf, sz)) > 0)
	SHA1_Update(&ctx, buf, ret);

    SHA1_Final(res, &ctx);
    free(buf);

    if (ret < 0)
	err(1, "read");

    for (i = 0; i < SHA_DIGEST_LENGTH; i ++)
	printf("%02x", res[i]);
    printf("\n");
    
    return ret;
}

int
main (int argc, char **argv)
{
    const size_t sz  = 16384;
    int fd = STDIN_FILENO;
    int ret = 0;

    setprogname(argv[0]);

    if (argc > 1) {
	int arg = 1;
	while (--argc) {
	    char *file = argv[arg];
	    if ((fd = open(file, O_RDONLY)) < 0)
		err(1, "open %s", file);
	    
	    printf("%s: \t", file);
	    (void)do_read(fd, sz);
	    ret = close(fd);
	    arg++;
	}
    } else {
	ret = do_read(fd, sz);
    }

    return ret;
}
