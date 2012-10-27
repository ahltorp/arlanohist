/*
 * Copyright (c) 1995, 1996, 1997 Kungliga Tekniska Högskolan
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

/*
 * NNPFS system calls.
 */
#include <sys/syscall.h>
#include <sys/systm.h>

#include <nnpfs/nnpfs_syscalls.h>

/* int afs_syscall(), afs_xioctl(), afs_xflock(); */

static int (*saved_setgroups)() = 0;

#if defined(__STDC__)
static int nnpfs_setgroups(void)
#else
static int
nnpfs_setgroups()
#endif
{
  uprintf("in afs_xsetgroups\n");
  return (*saved_setgroups)();
}

#if 0
typedef struct FID {
  fsid_t fsid;
  struct fid id;
} FID;

static int getFID(char *path, FID* fidp);
static int FIDopen(FID *fidp, int filemode);
#endif

/*
 * Install and uninstall syscalls.
 */
extern struct sysent sysent[];

#if defined(__STDC__)
int nnpfs_install_syscalls(void)
#else
int
nnpfs_install_syscalls()
#endif
{
  if (sysent[SYS_setgroups].sy_call != 0)
    {
      saved_setgroups = sysent[SYS_setgroups].sy_call;
      sysent[SYS_setgroups].sy_call = nnpfs_setgroups;
    }
  
  return 0;
}

#if defined(__STDC__)
int nnpfs_uninstall_syscalls(void)
#else
int
nnpfs_uninstall_syscalls()
#endif
{
  if (saved_setgroups != 0)
    sysent[SYS_setgroups].sy_call = saved_setgroups;
  saved_setgroups = 0;

  return 0;
}

#if defined(__STDC__)
int nnpfs_vdstat_syscalls(void)
#else
int
nnpfs_vdstat_syscalls()
#endif
{
  return 0;
}
