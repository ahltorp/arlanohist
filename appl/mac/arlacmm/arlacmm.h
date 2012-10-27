/*
 * Copyright (c) 2001 Kungliga Tekniska Högskolan
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

/* $Id: arlacmm.h,v 1.9 2005/10/28 14:33:35 tol Exp $ */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <CoreFoundation/CoreFoundation.h>
#include <CoreFoundation/CFPlugInCOM.h>
#include <Carbon/Carbon.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <kafs.h>
#include <pts.h>
#include <fs.h>

#include <atypes.h>
#include <roken.h>
#include <arla-pioctl.h>

typedef struct ArlaCMMType {
    ContextualMenuInterfaceStruct *_contextualMenuInterface;
    CFUUIDRef _factoryID;
    UInt32 _refCount;
    int isactive;
    int modified;
    WindowRef permwindow;
    WindowRef adduserwindow;
    WindowRef infowindow;
    CFStringRef path;
    CFMutableArrayRef acl;
    CFMutableArrayRef groups;
    CFStringRef aclcopy;
} ArlaCMMType;

#define kContextualMenuPermissions 1
#define kContextualMenuStatus 2

#define kControlID 'arla'
#define kAddUserWindowID 'addu'

#define kContextualMenuSignature 'cmcd'

#define kCloseButtonCmd 'clos'
#define kApplyButtonCmd 'aply'
#define kDeleteButtonCmd 'dele'
#define kPopUpMenuCmd 'pupm'
#define kChangeCheckCmd 'chgn'
#define kAddButtonCmd 'add '

#define kFileNameControl 100
#define kPopUpMenuControl 101
#define kDeleteButtonControl 102
#define kApplyButtonControl 103
#define kCloseButtonControl 104
#define kAddButtonControl 105

#define kPermissionLookupControl 110
#define kPermissionInsertControl 111
#define kPermissionDeleteControl 112
#define kPermissionAdministerControl 113
#define kPermissionReadControl 114
#define kPermissionWriteControl 115
#define kPermissionLockControl 116

#define kMenuStart 201

#define kAddUserTextField 101
#define kAddUserPopUpMenu 102

#define kAddUserPopUpMenuCommand 'list'

#define kInfoFileNameControl 100
#define kInfoVolumeName 101
#define kInfoCellName 104
#define kInfoFileServers 105
#define kInfoQuotaUsable 102
#define kInfoQuotaUsed 103

#define kArlaCMMFactoryID (CFUUIDGetConstantUUIDWithBytes(NULL, \
    0xB0, 0x3A, 0xD4, 0x2D, 0xB0, 0xD7, 0x11, 0xD5, 0xA6, 0x61, 0x00, 0x05, 0x02, 0x09, 0xFD, 0xA8))

CFStringRef
getacl(UInt8 *path);

int
setacl(UInt8 *path, UInt8 *acl);

int
getvolstat(UInt8 *path, CFStringRef *string, int *quota, int *used);

int
getfid(UInt8 *path, struct VenusFid *fid);

int
isInAFS(UInt8 *path, int *isdir);

int
getfilecellname(UInt8 *path, CFStringRef *string);

int
getfileservers(UInt8 *path, CFStringRef *string);

int
verifyname(CFStringRef path, CFStringRef name);

OSStatus
context_to_path(const AEDesc *inContext, UInt8 *path, UInt32 maxsize);

OSStatus
cfstring_to_utf8(CFStringRef s, UInt8 **buffer);

OSStatus
permissionWindow (ArlaCMMType *this, UInt8 *path);

OSStatus
addAclItem(ArlaCMMType *this, CFStringRef username);

OSStatus
addUserWindow (ArlaCMMType *this);

OSStatus
infoWindow (ArlaCMMType *this, UInt8 *path);

void *
ArlaCMMFactoryFunction(CFAllocatorRef allocator, CFUUIDRef typeID);
