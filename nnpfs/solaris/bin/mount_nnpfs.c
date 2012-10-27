/*
 * Copyright (c) 1995 - 2000 Kungliga Tekniska Högskolan
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/mnttab.h>
#include <strings.h>
#include <errno.h>

RCSID("$Id: mount_nnpfs.c,v 1.8 2002/09/07 10:47:50 lha Exp $");

static void
usage(const char *progname)
{
    fprintf (stderr, "Usage: %s device path\n", progname);
    exit (1);
}


#define MNTTAB "/etc/mnttab"
#define MNTTAB_LOCK "/etc/.mnttab.lock"

/*
 * add an mount entry for `dev' on  `mountp' to /etc/mnttab
 */

static int
updatemnttab(char *dev, char *mountp)
{
    int ret;
    int mnttablock;
    FILE *mnttabfd;
    struct mnttab mp;
    struct timeval tp;
    char timebuf[15];
    struct flock flock;

    mnttablock = open(MNTTAB_LOCK, O_WRONLY|O_CREAT, 0);
    if (mnttablock < 0) {
	perror("open " MNTTAB_LOCK);
	exit(1);
    }

    memset(&flock, 0, sizeof(flock));
    flock.l_type = F_WRLCK;
    ret = fcntl (mnttablock, F_SETLKW, &flock);
    if (ret < 0) {
	perror("fcntl " MNTTAB_LOCK);
	exit (1);
    }

    mnttabfd = fopen(MNTTAB, "a");
    if (mnttabfd == NULL) {
	if (errno == ENOSYS) {
	    close (mnttablock);
	    return 0;
	}
	perror("open " MNTTAB);
	exit(1);
    }

    memset(&flock, 0, sizeof(flock));
    flock.l_type = F_WRLCK;
    ret = fcntl (fileno(mnttabfd), F_SETLKW, &flock);
    if (ret < 0) {
	perror("fcntl " MNTTAB);
	exit (1);
    }

    gettimeofday(&tp, NULL);
    snprintf(timebuf, sizeof(timebuf), "%d", tp.tv_sec);

    mp.mnt_special = dev;
    mp.mnt_mountp  = mountp;
    mp.mnt_fstype  = "nnpfs";
    mp.mnt_mntopts = "rw";
    mp.mnt_time    = timebuf;

    ret = putmntent(mnttabfd, &mp);
    if (ret == EOF) {
	printf("putmntent returned %d\n", ret);
	return ret;
    }

    fclose(mnttabfd);
    close(mnttablock);

    return 0;
}

int
main(int argc, char **argv)
{
    int ret;

    if (argc != 3)
	usage (argv[0]);

    ret = mount(argv[1], argv[2], MS_DATA, "nnpfs", NULL, 0);
    if (ret) {
	perror("mount");
	return ret;
    } else
	updatemnttab(argv[1], argv[2]);

    return 0;
}
