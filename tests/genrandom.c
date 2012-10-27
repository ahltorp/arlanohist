/*
 * Copyright (c) 2001, 2006-2007 Kungliga Tekniska Högskolan
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

#include <roken.h>
#include <err.h>

RCSID("$Id: genrandom.c,v 1.1 2007/01/12 17:01:49 tol Exp $");

#define BUF_SIZE	(128*1024)

/*
 * Silly "random" data generator, writes `nbytes' to stdout, from
 * `offset' in our stream.
 */

static void *
fill_buf(unsigned long *buf, unsigned long long base)
{
    unsigned i;

    if (!buf) {
	buf = malloc(BUF_SIZE);
	
	if (!buf)
	    errx(1, "malloc failed");
    }

    srandom(base / BUF_SIZE);
    for (i = 0; i < BUF_SIZE/sizeof(long); i++) {
	unsigned long tmp = random();
	buf[i] = tmp ^ (tmp << 1);
    }
    return buf;
}

static void
doit(long long offset, long long nbytes)
{
    unsigned long long base, off;
    char *buf = NULL;
    size_t sz;
    int ret;
    
    while (nbytes) {
	base = offset & (~(BUF_SIZE - 1));
	off = offset - base;
	if (base == offset || !buf)
	    buf = fill_buf((void *)buf, base);

	sz = BUF_SIZE - off;
	if (sz > nbytes)
	    sz = nbytes;
	ret = write(STDOUT_FILENO, buf + off, sz);
	if (ret != sz)
	    err(1, "write at %llu", (unsigned long long)offset);
	offset += ret;
	nbytes -= ret;
    }
    
    free(buf);
}

int
main(int argc, char **argv)
{
    long long nbytes, offset = 0;

    setprogname(argv[0]);

    if (argc < 2 || argc > 3)
	errx(1, "usage: %s nbytes [offset]", argv[0]);

    nbytes = strtoll(argv[1], NULL, 10); /* XXX errno */

    if (argc == 3)
	offset = strtoll(argv[2], NULL, 10); /* XXX errno */

    doit(offset, nbytes);

    return 0;
}
