/*
 * Copyright (c) 2000, 2002 Kungliga Tekniska Högskolan
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
#include <stdio.h>

/*
 * This is truly revolting
 */

static SOCKET arla_socket;
static HANDLE nnpfs_device;
static int exit_helper = 0;
static int debug = 0;

/*
 *
 */

static void
start_socket (void)
{
    int ret;
    WORD ver_req;
    WSADATA data;
    struct sockaddr_in addr;
    SOCKET listen_socket;

    ver_req = MAKEWORD( 1, 1 );
    ret = WSAStartup(ver_req, &data);
    if (ret) {
	printf ("WSAStartup returned %d\n", GetLastError());
	exit (1);
    }
    
    listen_socket = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_socket == INVALID_SOCKET) {
	printf ("socket returned %d\n", WSAGetLastError());
	exit (1);
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(0x7f000001); /* 127.0.0.1 */
    addr.sin_port = htons(5000);
    
    ret = bind (listen_socket, (struct sockaddr *) &addr, sizeof(addr));
    if (ret == SOCKET_ERROR) {
	printf ("bind returned %d\n", WSAGetLastError());
	exit(1);
    }

    ret = listen (listen_socket, 1);
    if (ret != 0) {
	printf ("listen returned %d\n", WSAGetLastError());
	exit (1);
    }
    
    ret = sizeof(addr);
    arla_socket = accept (listen_socket, (struct sockaddr *)&addr, &ret);
    if (arla_socket == INVALID_SOCKET) {
	printf ("accept returned %d\n", WSAGetLastError());
	exit (1);
    }

    if (debug)
	printf ("got a connection from: %s\n", inet_ntoa(addr.sin_addr));

    closesocket (listen_socket);
}

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
			     OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    
    if (nnpfs_device == INVALID_HANDLE_VALUE) {
	printf ("CreateFile (opening the device) returned %d\n",
		GetLastError());
	exit (2);
    }
}

void
thread_exit (HANDLE *event)
{
    CloseHandle(*event);
    exit_helper = 1;
    ExitThread(0);
}

/*
 *
 */

static DWORD WINAPI 
device_thread(LPVOID foo)
{
    int ret;
    u_long len;
    DWORD ioctl_len;
    char out_len[4];
    char *msg;
    OVERLAPPED ov={0};

#define NNPFS_MAX_MSG_SIZE (64*1024)

    msg = malloc (NNPFS_MAX_MSG_SIZE);
    if (msg == NULL) {
	printf ("malloc failed with error: %d\n", GetLastError());
	exit (1);
    }

    ov.hEvent = CreateEvent(NULL,  // security
                            FALSE, // reset
                            FALSE, // signaled
                            NULL); // name

    while (!exit_helper) {
	ret = 0;
	/* don't fail on ENOMEM, might be Driver Verifier's fault */
	while (!ret) {
	    ret = DeviceIoControl (nnpfs_device,IOCTL_NNPFS_GETMSG,
				   NULL, 0, msg, NNPFS_MAX_MSG_SIZE-1,
				   NULL, &ov);
	    
	    if (ret || GetLastError() == ERROR_IO_PENDING) 
		ret = GetOverlappedResult(nnpfs_device, &ov, &ioctl_len, TRUE);
	    
	    if (!ret) {
		int error = GetLastError();
		printf ("DeviceIoControl(GETMSG) returned %d\n", error);
		if (error != ERROR_NO_SYSTEM_RESOURCES
		    && error != ERROR_NOT_ENOUGH_MEMORY)
		    thread_exit(&ov.hEvent);
	    }
	}

	if (ioctl_len < 4 || ioctl_len >= NNPFS_MAX_MSG_SIZE) {
	    printf ("got %d bytes from nnpfs!\n", ioctl_len);
	    thread_exit(&ov.hEvent);
	}
	    
	len = htonl (ioctl_len);
	memcpy (out_len, &len, sizeof(out_len));
	ret = send (arla_socket, out_len, sizeof(out_len), 0);
	if (ret != sizeof(out_len)) {
	    printf ("send(out_len) returned %d\n", WSAGetLastError());
	    thread_exit(&ov.hEvent);
	}
	ret = send (arla_socket, msg, ioctl_len, 0);
	if (ret != ioctl_len) {
	    printf ("send(msg) returned %d\n", WSAGetLastError());
	    thread_exit(&ov.hEvent);
	}
	
	if (debug) {
	    unsigned long *p = (unsigned long *)msg;
	    printf ("message to arlad,   size %4x (%8x %8x %8x)\n", 
		    ioctl_len, p[0], p[1], p[2]);
	    fflush(stdout);
	}
    }
    thread_exit(&ov.hEvent);
    return 0;
}

/*
 *
 */

static void
loop (void)
{
    fd_set rfd;
    int ret;
    char *msg;
    OVERLAPPED ov={0};

    msg = malloc (NNPFS_MAX_MSG_SIZE);
    if (msg == NULL) {
	printf ("malloc failed with error: %d\n", GetLastError());
	exit (1);
    }

    ov.hEvent = CreateEvent(NULL,  // security
                            FALSE, // reset
                            FALSE, // signaled
                            NULL); // name

    while (!exit_helper) {
	FD_ZERO (&rfd);
	FD_SET (arla_socket, &rfd);
	
	ret = select (arla_socket + 1, &rfd, NULL, NULL, NULL);
	if (ret == SOCKET_ERROR) {
	    printf ("select returned %d\n", ret);
	    CloseHandle(ov.hEvent);
	    return;
	}

	if (FD_ISSET(arla_socket, &rfd)) {
	    u_long len, left;
	    DWORD ioctl_len;
	    char out_len[4];
	    char *m = msg;
	    unsigned long *p = (unsigned long *)msg;

	    ret = recv (arla_socket, out_len, sizeof(out_len), 0);
	    if (ret == SOCKET_ERROR) {
		printf ("recv (out_len) returned %d\n",
			WSAGetLastError());
		CloseHandle(ov.hEvent);
		return;
	    }

	    memcpy (&len, out_len, sizeof(len));
	    len = ntohl(len);

	    if (len > NNPFS_MAX_MSG_SIZE) {
		printf ("recv a too large message (%d)\n", len);
		CloseHandle(ov.hEvent);
		return;
	    }
	    
	    left = len;
	    while (left > 0) {
		ret = recv (arla_socket, m, left, 0);
		if (ret == left)
		    break;
		if (ret == SOCKET_ERROR) {
		    printf ("recv (msg) returned(SOCKET_ERROR) %d\n",
			    WSAGetLastError());
		    CloseHandle(ov.hEvent);
		    return;
		} 
		m += ret;
		left -= ret;
	    }

	    if (debug) {
		printf ("message from arlad, size %4x (%8x %8x %8x)\n",
			len, p[0], p[1], p[2]);
		fflush(stdout);
	    }
	    
	    ret = 0;
	    /* don't fail on ENOMEM, might be Driver Verifier's fault */
	    while (!ret) {
		ret = DeviceIoControl (nnpfs_device, IOCTL_NNPFS_PUTMSG,
				       msg, len, NULL, 0,
				       &ioctl_len,
				       &ov);
		
		if (ret || GetLastError() == ERROR_IO_PENDING) 
		    ret = GetOverlappedResult(nnpfs_device, &ov,
					      &ioctl_len, TRUE);
		
		if (!ret) {
		    int error = GetLastError();
		    printf ("DeviceIoControl(PUTMSG) returned %d\n", error);
		    if (error != ERROR_NO_SYSTEM_RESOURCES
			&& error != ERROR_NOT_ENOUGH_MEMORY) {
			CloseHandle(ov.hEvent);
			return;
		    }
		}
	    }
	} else {
	    printf ("select behaves strangely\n");
	}
    }
}

/*
 *
 */

int
main (int argc, char **argv)
{
    int ret;
    DWORD nread;
    char *msg;
    DWORD tid;
    HANDLE thread;

    if (argc > 1)
	debug = 1;
    open_device ("\\Device\\NNPFS");
    start_socket ();

    thread = CreateThread (NULL, 0, device_thread, NULL, 0, &tid);
    if (thread == INVALID_HANDLE_VALUE) {
	printf ("CreateThread failed with %d\n", GetLastError());
	return 0;
    } 

    loop();

    exit_helper = 1;

    closesocket (arla_socket);

    return 0;
}
