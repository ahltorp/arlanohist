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

#include "arlacmm.h"

RCSID("$Id: main.c,v 1.3 2002/04/23 10:10:23 ahltorp Exp $");

static OSStatus 
ArlaCMMExamineContext(void *thisInstance,
		      const AEDesc *inContext,
		      AEDescList *outCommandPairs)
{
    AERecord permRecord;
    AERecord statRecord;
    SInt32 permID = kContextualMenuPermissions;
    SInt32 statID = kContextualMenuStatus;
    char *permtext;
    char *stattext;
    OSStatus ret;
    UInt8 path[1024];
    int isdir;

    permtext = "AFS Permissions...";
    stattext = "AFS Info...";
    
    ret = context_to_path(inContext, path, sizeof(path));
    if (ret != noErr)
        return ret;
    
    if (!isInAFS(path, &isdir))
	return noErr;

    if (isdir) {
        ret = AECreateList(NULL, 0, TRUE, &permRecord);
        if (ret != noErr)
            return ret;
        ret = AEPutKeyPtr(&permRecord, keyAEName, typeChar,
			  permtext, strlen(permtext));
        if (ret != noErr)
            return ret;
        ret = AEPutKeyPtr(&permRecord, kContextualMenuSignature,
			  typeLongInteger, &permID, sizeof(permID));
        if (ret != noErr)
            return ret;
        ret = AEPutDesc(outCommandPairs, 0, &permRecord);
        if (ret != noErr)
            return ret;
	
        ret = AEDisposeDesc(&permRecord);
        if (ret != noErr)
            return ret;
    }
	
    ret = AECreateList(NULL, 0, TRUE, &statRecord);
    if (ret != noErr)
	return ret;
    ret = AEPutKeyPtr(&statRecord, keyAEName, typeChar,
		      stattext, strlen(stattext));
    if (ret != noErr)
	return ret;
    ret = AEPutKeyPtr(&statRecord, kContextualMenuSignature,
		      typeLongInteger, &statID, sizeof(statID));
    if (ret != noErr)
	return ret;
    ret = AEPutDesc(outCommandPairs, 0, &statRecord);
    if (ret != noErr)
	return ret;
    
    ret = AEDisposeDesc(&statRecord);
    if (ret != noErr)
	return ret;
    
    return noErr;
}

static OSStatus 
ArlaCMMHandleSelection(void *thisInstance,
		       AEDesc *inContext,
		       SInt32 inCommandID)
{
    OSStatus ret;
    ArlaCMMType *this = (ArlaCMMType *)thisInstance;
    UInt8 path[1024];
    
    ret = context_to_path(inContext, path, sizeof(path));
    if (ret != noErr)
        return ret;
    
    if (!isInAFS(path, NULL))
        return paramErr;
    
    switch(inCommandID) {
    case kContextualMenuPermissions:
        ret = permissionWindow(this, path);
        if (ret != noErr)
            return ret;
        break;
    case kContextualMenuStatus:
        ret = infoWindow(this, path);
        if (ret != noErr)
            return ret;
        break;
    default:
        return paramErr;
    }
    
    return 0;
}

static void 
ArlaCMMPostMenuCleanup(void *thisInstance)
{
    return;
}

static void deallocArlaCMMType(ArlaCMMType *this);

static HRESULT
ArlaCMMQueryInterface(void *thisInstance, REFIID iid, LPVOID *ppv)
{
    CFUUIDRef interfaceID = CFUUIDCreateFromUUIDBytes(NULL, iid);
    ArlaCMMType *this = (ArlaCMMType *) thisInstance;
    
    if (CFEqual(interfaceID, kContextualMenuInterfaceID)) {
        this->_contextualMenuInterface->AddRef(this);
        *ppv = this;
        CFRelease(interfaceID);
        return S_OK;
    } else if (CFEqual(interfaceID, IUnknownUUID)) {
        this->_contextualMenuInterface->AddRef(this);
        *ppv = this;
        CFRelease(interfaceID);
        return S_OK;
    } else {
        *ppv = NULL;
        CFRelease(interfaceID);
        return E_NOINTERFACE;
    }
}

static ULONG
ArlaCMMAddRef(void *thisInstance)
{
    ArlaCMMType *this = (ArlaCMMType *) thisInstance;    

    this->_refCount += 1;
    return this->_refCount;
}

static ULONG
ArlaCMMRelease(void *thisInstance)
{
    ArlaCMMType *this = (ArlaCMMType *) thisInstance;

    this->_refCount -= 1;
    if (this->_refCount == 0) {
        deallocArlaCMMType(this);
        return 0;
    } else
        return this->_refCount;
}

static ContextualMenuInterfaceStruct contextualMenuInterfaceFtbl = {
    NULL,
    ArlaCMMQueryInterface,
    ArlaCMMAddRef,
    ArlaCMMRelease,
    ArlaCMMExamineContext,
    ArlaCMMHandleSelection,
    ArlaCMMPostMenuCleanup
};

static ArlaCMMType *
allocArlaCMMType(CFUUIDRef factoryID)
{
    ArlaCMMType *newOne = (ArlaCMMType *)malloc(sizeof(ArlaCMMType));
    
    newOne->_contextualMenuInterface = &contextualMenuInterfaceFtbl;
    newOne->_factoryID = CFRetain(factoryID);
    CFPlugInAddInstanceForFactory(factoryID);
    newOne->_refCount = 1;
    newOne->isactive = 0;
    newOne->modified = 0;
    newOne->permwindow = NULL;
    newOne->adduserwindow = NULL;
    newOne->infowindow = NULL;
    newOne->acl = NULL;
    newOne->groups = NULL;
    
    return newOne;
}

static void
deallocArlaCMMType(ArlaCMMType *this)
{
    CFUUIDRef factoryID = this->_factoryID;
    free(this);
    if (factoryID) {
        CFPlugInRemoveInstanceForFactory(factoryID);
        CFRelease(factoryID);
	if (this->acl)
	    CFRelease(this->acl);
	if (this->groups)
	    CFRelease(this->groups);
    }
}

void *
ArlaCMMFactoryFunction(CFAllocatorRef allocator, CFUUIDRef typeID)
{
    if (CFEqual(typeID, kContextualMenuTypeID)) {
        ArlaCMMType *result = allocArlaCMMType(kArlaCMMFactoryID);
        return result;
    } else {
        return NULL;
    }
    
    return 0;
}

