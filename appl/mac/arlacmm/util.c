/*
 * Copyright (c) 2001 Kungliga Tekniska H�gskolan
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

RCSID("$Id: util.c,v 1.2 2002/04/23 14:38:21 ahltorp Exp $");

OSStatus
context_to_path(const AEDesc *inContext, UInt8 *path, UInt32 maxsize)
{
    FSSpec target;
    FSRef ref;
    Boolean wasChanged;
    AEDesc theDesc;
    Handle handle;
    Size size;
    SInt32 theCount;
    AEKeyword theAEKeyword;
    OSStatus ret;

    if (inContext->descriptorType == typeAlias) {
        theDesc = *inContext;
    } else if (inContext->descriptorType == typeAEList) {
        ret = AECountItems(inContext, &theCount);
        if (ret != noErr)
            return ret;
        if (theCount != 1)
            return paramErr;
        ret = AEGetNthDesc(inContext, 1, typeAlias, &theAEKeyword, &theDesc);
        if (ret != noErr)
            return ret;
    } else {
        return paramErr;
    }

    size = AEGetDescDataSize(&theDesc);
    handle = NewHandle(size);
    if (handle == NULL)
        return memFullErr;
    HLock(handle);
    ret = AEGetDescData(&theDesc, *handle, size);
    if (ret != noErr) {
        DisposeHandle(handle);
        return ret;
    }

    ret = ResolveAlias(NULL, (AliasHandle) handle, &target, &wasChanged);
    if (ret != noErr)
        return ret;
    ret = FSpMakeFSRef(&target, &ref);
    if (ret != noErr)
        return ret;
    ret = FSRefMakePath(&ref, path, maxsize);
    if (ret != noErr)
        return ret;

    DisposeHandle(handle);
    return noErr;
}

OSStatus
cfstring_to_utf8(CFStringRef s, UInt8 **buffer)
{
    CFIndex length;
    OSStatus ret;

    length = CFStringGetMaximumSizeForEncoding(CFStringGetLength(s),
					       kCFStringEncodingUTF8);

    *buffer = malloc(length);
    if (*buffer == NULL) {
	return memFullErr;
    }

    ret = CFStringGetCString(s, *buffer, length, kCFStringEncodingUTF8);

    if (!ret) {
	free(*buffer);
	return paramErr;	
    }

    return 0;
}
