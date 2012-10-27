/*
 * Copyright (c) 2001, 2002 Kungliga Tekniska Högskolan
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

#include "arlacmm.h"

RCSID("$Id: pioctl.c,v 1.6 2005/11/17 15:44:55 tol Exp $");

int
getfid(UInt8 *path, struct VenusFid *fid)
{
    struct ViceIoctl a_params;

    if (!k_hasafs_recheck())
        return errno;

    if (path == NULL)
        return EINVAL;

    a_params.in_size=0;
    a_params.out_size=sizeof(*fid);
    a_params.in=NULL;
    a_params.out=(void*) fid;
    
    if(k_pioctl(path,ARLA_VIOCGETFID,&a_params,1) == -1)
        return errno;

    return 0;
}

int
isInAFS(UInt8 *path, int *isdir)
{
    struct VenusFid fid;
    int ret;

    ret = getfid(path, &fid);

    if (ret != noErr)
        return 0;

    if (isdir)
	*isdir = fid.fid.Vnode & 1;

    return 1;
}

#define MAXSIZE 2048

CFStringRef
getacl(UInt8 *path)
{
    struct ViceIoctl a_params;
    char *s;
    CFStringRef string;

    if (!k_hasafs_recheck())
        return NULL;

    s = malloc(MAXSIZE);

    a_params.in_size = 0;
    a_params.out_size = MAXSIZE;
    a_params.in = NULL;
    a_params.out = s;
    
    if(k_pioctl(path,ARLA_VIOCGETAL,&a_params,1) == -1)
        return NULL;
        
    s[a_params.out_size] = '\0';
    string = CFStringCreateWithCString(NULL, s, kCFStringEncodingUTF8);
    free(s);
    return string;
}

int
setacl(UInt8 *path, UInt8 *acl)
{
    struct ViceIoctl a_params;

    if (!k_hasafs_recheck())
        return NULL;

    a_params.in_size = strlen(acl);
    a_params.out_size = 0;
    a_params.in = acl;
    a_params.out = NULL;
    
    if(k_pioctl(path,ARLA_VIOCSETAL,&a_params,1) == -1)
        return paramErr;
        
    return 0;
}

struct VolumeStatus {
    int32_t   Vid;
    int32_t   ParentId;
    char      Online;
    char      InService;
    char      Blessed;
    char      NeedsSalvage;
    int32_t   Type;
    int32_t   MinQuota;
    int32_t   MaxQuota;
    int32_t   BlocksInUse;
    int32_t   PartBlocksAvail;
    int32_t   PartMaxBlocks;
};

int
getvolstat(UInt8 *path, CFStringRef *string, int *quota, int *used)
{
    struct ViceIoctl a_params;
    struct VolumeStatus *vs;
    char *name;

    a_params.in_size=0;
    a_params.out_size=MAXSIZE;
    a_params.in=NULL;
    a_params.out=malloc(MAXSIZE);

    if (a_params.out == NULL) {
	return memFullErr;
    }

    if(k_pioctl(path,ARLA_VIOCGETVOLSTAT,&a_params,1)==-1) {
	free(a_params.out);
	return paramErr;
    }

    vs=(struct VolumeStatus *) a_params.out;
    name=a_params.out+sizeof(struct VolumeStatus);

    *string = CFStringCreateWithCString(NULL, name, kCFStringEncodingUTF8);
    *quota = vs->MaxQuota;
    *used = vs->BlocksInUse;
    free(a_params.out);
    return 0;
}

int
getfilecellname(UInt8 *path, CFStringRef *string)
{
    struct ViceIoctl a_params;
    char *name;

    a_params.in_size=0;
    a_params.out_size=MAXSIZE;
    a_params.in=NULL;
    a_params.out=malloc(MAXSIZE);

    if (a_params.out == NULL) {
	return memFullErr;
    }

    if(k_pioctl(path,ARLA_VIOC_FILE_CELL_NAME,&a_params,1)==-1) {
	free(a_params.out);
	return paramErr;
    }

    name = a_params.out;

    *string = CFStringCreateWithCString(NULL, name, kCFStringEncodingUTF8);
    free(a_params.out);
    return 0;
}

int
getfileservers(UInt8 *path, CFStringRef *string)
{
    struct ViceIoctl a_params;
    struct in_addr addr;
    int32_t *curptr;
    char *name;
    int i = 0;

    CFMutableStringRef hosts;
    
    a_params.in_size = 0;
    a_params.out_size = 8 * sizeof(int32_t);
    a_params.in = NULL;
    a_params.out = malloc(8 * sizeof(int32_t));
    
    if (a_params.out == NULL)
	return memFullErr;

    if (k_pioctl(path, VIOCWHEREIS, &a_params, 1) == -1) {
	free(a_params.out);
	return paramErr;
    }
    
    hosts = CFStringCreateMutable(kCFAllocatorDefault, 512);
    curptr=(int32_t *) a_params.out;

    while (curptr[i] && i < 8) {
        struct hostent *h;
	addr.s_addr = curptr[i];
	h = gethostbyaddr((const char *) &addr, sizeof(addr), AF_INET);
	if (h == NULL)
	    name = inet_ntoa(addr);
	else
	    name = h->h_name;

	CFStringAppendCString(hosts, name, kCFStringEncodingUTF8);
	i++;
    }
    
    *string = hosts;
    free(a_params.out);

    return 0;
}
