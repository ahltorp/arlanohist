/*
 * Copyright (c) 2001, 2003 Kungliga Tekniska Högskolan
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
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <dirent.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>

#include <roken.h>

#include <err.h>

RCSID("$Id: intr-read.c,v 1.9 2003/01/24 18:49:09 tol Exp $");

static int num_children = 50;

static sig_atomic_t set_alarm = 0;
static sig_atomic_t dead_children = 0;
static int do_children = 0;

static RETSIGTYPE
sigalrm(int foo)
{
    signal(SIGALRM, sigalrm);
    set_alarm = 1;
}

static RETSIGTYPE
sigchld(int foo)
{
    int status;

    signal(SIGALRM, sigalrm);
    dead_children--;
    wait3(&status, WNOHANG, NULL);
}



static void
try_read(const char *filename)
{
    int fd;

    fd = open(filename, O_RDONLY);
    if (fd < 0) {
	if (errno == EINTR)
	    err(1, "open %s was interrupted", filename);
    } else {
	close(fd);
    }
}

static void
find(const char *dirname)
{
    DIR *dir;
    struct dirent *dp;

    dir = opendir(dirname);
    if (dir == NULL)
	err (1, "opendir %s", dirname);
    while ((dp = readdir(dir)) != NULL) {
	char fname[MAXPATHLEN];
	struct stat sb;

	if (set_alarm) {
	    alarm(1);
	    set_alarm = 0;
	}
	if (strcmp (dp->d_name, ".") == 0
	    || strcmp (dp->d_name, "..") == 0)
	    continue;
	snprintf(fname, sizeof(fname), "%s/%s", dirname, dp->d_name);
	if (lstat(fname, &sb) < 0)
	    err(1, "stat %s", fname);
	if (S_ISDIR(sb.st_mode))
	  find(fname);
	else
	  try_read(fname);
    }
    closedir(dir);
}

int
main(int argc, char **argv)
{
    struct sigaction sa;
    pid_t *children = NULL;
    int i;

    setprogname (argv[0]);

    if (argc < 2)
	errx(1, "argc < 2");

    sa.sa_handler = sigalrm;
    sigfillset(&sa.sa_mask);
    sa.sa_flags   = 0;
    sigaction(SIGALRM, &sa, NULL);

    sa.sa_handler = sigchld;
    sigfillset(&sa.sa_mask);
    sa.sa_flags   = 0;
    sigaction(SIGCHLD, &sa, NULL);

    while (argc > 1) {
	if (strcmp(argv[1], "--alarm") == 0)
	    set_alarm = 1;
	else if (strcmp(argv[1], "--child") == 0)
	    do_children = 1;
	else
	    break;
	argc--;
	argv++;
    }

    /* 
     * fork child, child figure out how long to sleep (max 13 seconds)
     * every second the child checks if the parent is alive or to make
     * sure it don't stay around too long
     */
       
    if (do_children) {
	pid_t pid, ppid;

	children = emalloc(sizeof(pid_t) * num_children);

	ppid = getpid();

	for (i = 0 ; i < num_children; i++) {
	    pid = fork();
	    switch (pid) {
	    case 0:
		srandom(getpid() * time(NULL));
		i = random() % 10 + 3;
		while(--i) {
		    sleep(1);
		    if (kill(ppid, 0) < 0)
			_exit(1);
		}
		_exit(0);
	    case -1:
		err(1, "fork");
	    default:
		children[i] = pid;
		break;
	    }
	}
    }

    while (--argc)
	find(*++argv);

    /*
     * On Windows, the pwd of the children will be in the test
     * directory and then it can't be removed. Also its seems kind of
     * silly that there are processes changing round just to die a
     * couple of seconds after the test has finished.
     */
    
    if (do_children) {
	sa.sa_handler = SIG_IGN;
	sigfillset(&sa.sa_mask);
	sa.sa_flags   = 0;
	sigaction(SIGCHLD, &sa, NULL);
	
	for (i = 0 ; i < num_children; i++) {
	    if (kill(children[i], SIGTERM) >= 0) {
		int status;
		wait4(children[i], &status, 0, NULL);
	    }
	}
    }

    return 0;
}
