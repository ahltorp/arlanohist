/*
 * Copyright (c) 2003-2004 Kungliga Tekniska Högskolan
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
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL").
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
 * Orignally written for OpenAFS by Chaskiel Grundman <cg2v@andrew.cmu.edu>,
 * mudged somewhat by Love <lha@it.su.se>.
 */

#define __NO_VERSION__
#include <nnpfs/nnpfs_locl.h>
#include <nnpfs/nnpfs_debug.h>
#include <nnpfs/nnpfs_syscalls.h>
#include <linux/sched.h>
#include <linux/unistd.h>

#ifdef RCSID
RCSID("$Id: nnpfs_syscalls-lossage.c,v 1.19 2010/08/08 20:43:05 tol Exp $");
#endif

#include <linux/kallsyms.h>
static void *lower_bound = &kernel_thread;

void * __attribute__((weak)) sys_call_table(void);
nnpfs_sys_call_function *nnpfs_sys_call_table =
(nnpfs_sys_call_function *)sys_call_table;

const char * __attribute__((weak))
    kallsyms_lookup(unsigned long addr,
		    unsigned long *symbolsize,
		    unsigned long *offset,
		    char **modname, char *namebuf);

#ifdef __x86_64__
extern rwlock_t tasklist_lock __attribute__((weak));
#endif
static void **
get_start_addr(void) {
#ifdef __x86_64__
    return (void **)&tasklist_lock - 0x1000;
#else
    return (void **)&mutex_lock;
#endif
}

static inline int 
kallsym_is_equal(unsigned long addr, const char *name)
{
    char namebuf[128];
    const char *retname;
    unsigned long size, offset;
    char *modname;

    retname = kallsyms_lookup(addr, &size, &offset, &modname, namebuf);
    if (retname != NULL	&& strcmp(name, retname) == 0 && offset == 0)
        return 1;

    return 0;
}

static inline int
verify(void **p) {
    const int zapped_syscalls[] = {
#ifdef __NR_break
	__NR_break,
#endif
#ifdef __NR_stty
	__NR_stty,
#endif
#ifdef __NR_gtty
	__NR_gtty,
#endif
#ifdef __NR_ftime
	__NR_ftime,
#endif
#ifdef __NR_prof
	__NR_prof,
#endif
#ifdef __NR_lock
	__NR_lock,
#endif
#ifdef __NR_mpx
	__NR_mpx,
#endif
	0 };
    const int num_zapped_syscalls =
	(sizeof(zapped_syscalls)/sizeof(zapped_syscalls[0])) - 1;
    const int unique_syscalls[] = {
	__NR_exit, __NR_mount, __NR_read, __NR_write,
	__NR_open, __NR_close, __NR_unlink };
    const int num_unique_syscalls =
	sizeof(unique_syscalls)/sizeof(unique_syscalls[0]);
    int i, s;
    
    for (i = 0; i < num_unique_syscalls; i++)
	for (s = 0; s < 223; s++)
	    if (p[s] == p[unique_syscalls[i]]
		&& s != unique_syscalls[i])
		return 0;
    
    for (i = 1; i < num_zapped_syscalls; i++)
	if (p[zapped_syscalls[i]] != p[zapped_syscalls[0]])
	    return 0;
    
    if (kallsyms_lookup
	&& (!kallsym_is_equal((unsigned long)p[__NR_close], "sys_close")
	    || !kallsym_is_equal((unsigned long)p[__NR_chdir], "sys_chdir")))
	return 0;
    
    return 1;
}

static inline int looks_good(void **p)
{
    if (*p <= (void*)lower_bound || *p >= (void*)p)
	return 0;
    return 1;
}

int
nnpfs_fixup_syscall_lossage(void)
{
    void **ptr = get_start_addr();
    void **limit;

    if (nnpfs_sys_call_table != NULL) {
	printk("nnpfs_sys_call_table: %p\n", nnpfs_sys_call_table);
	return 0;
    }

    lower_bound = (void*)((unsigned long)lower_bound & ~0xfffff);

    for (limit = ptr + 16 * 1024;
	 ptr < limit && nnpfs_sys_call_table == NULL; ptr++)
    {
	int ok = 1;
	int i;

	for (i = 0; i < 222; i++) {
	    if (!looks_good(ptr + i)) {
		ok = 0;
		ptr = ptr + i;
		break;
	    }
	}

	if (ok && verify(ptr)) {
	    nnpfs_sys_call_table = (nnpfs_sys_call_function*)ptr;
	    break;
	}
    }

    if (nnpfs_sys_call_table == NULL) {
	printk("Failed to find address of sys_call_table\n");
 	return -EIO;
    }

    printk("Found sys_call_table at %p\n", nnpfs_sys_call_table);

    return 0;
}
