/*
 * Copyright (c) 2000 Kungliga Tekniska Högskolan
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

#include <windows.h>
#include <nnpfs_ioctl.h>

#define DEBUG 1

/*
 * This is truly revolting
 */

static HANDLE nnpfs_device; 
/*
 *
 */

/*
 *
 */

static void
open_device (char *devname)
{
    DWORD threadid;
    int ret;
    
    ret = DefineDosDevice(DDD_RAW_TARGET_PATH, "nnpfsdev",
			  devname);
    if (!ret) {
	printf ("DefineDosDevice returned %d\n", GetLastError());
	exit (2);
    }
    
    nnpfs_device = CreateFile ("\\\\.\\nnpfsdev", 
			     GENERIC_READ|GENERIC_WRITE,
			     FILE_SHARE_READ|FILE_SHARE_WRITE , NULL,
			     OPEN_EXISTING, 0, NULL);
    
    if (nnpfs_device == INVALID_HANDLE_VALUE) {
	printf ("CreateFile (opening the device) returned %d\n",
		GetLastError());
	exit (2);
    } else {
	printf ("CreateFile (opening the device) returned %d\n",
		GetLastError());
    }
}

/*
 *
 */


static void
send_wakeup(void)
{
    int ret;
    u_long len;
    DWORD ioctl_len;
    char out_len[4];

    ret = DeviceIoControl (nnpfs_device,IOCTL_NNPFS_WAKEMSG,
			   NULL, 0, NULL, 0,
			   &ioctl_len,
			   NULL);
    if (!ret) {
	printf ("DeviceIoControl(WAKEMSG) returned %d\n",
		GetLastError());
	exit(1);
    }
    printf ("DeviceIoControl(WAKEMSG) returned OK\n");
}

/*
 *
 */

int
main (int argc, char **argv)
{
    open_device ("\\Device\\NNPFS");
    send_wakeup();

    CloseHandle (nnpfs_device);
    return 0;
}
