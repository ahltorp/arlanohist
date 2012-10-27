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

RCSID("$Id: infowin.c,v 1.2 2005/10/28 14:33:35 tol Exp $");

static ControlID textcontrolid = {kControlID, kInfoFileNameControl};
static ControlID volumenameid = {kControlID, kInfoVolumeName};
static ControlID quotausableid = {kControlID, kInfoQuotaUsable};
static ControlID quotausedid = {kControlID, kInfoQuotaUsed};
static ControlID cellnameid = {kControlID, kInfoCellName};
static ControlID fileserversid = {kControlID, kInfoFileServers};

static pascal OSStatus
CloseWindowEventHandler(EventHandlerCallRef handlerRef,
		       EventRef event, void *userData)
{
    ArlaCMMType *this = (ArlaCMMType *)userData;

    HideWindow(this->infowindow);

    return noErr;
}

static OSStatus
createWindow(ArlaCMMType *this)
{
    IBNibRef 		nibRef;
    CFBundleRef bundle;
    OSStatus ret;
    WindowRef window;
    EventTypeSpec closespec = {kEventClassWindow, kEventWindowClose };

    if (this->infowindow)
        return 0;
        
    bundle = CFBundleGetBundleWithIdentifier(
	CFSTR("se.kth.stacken.arla.macosx.cmm"));
    ret = CreateNibReferenceWithCFBundle(bundle, CFSTR("dialog"), &nibRef);
    if (ret != noErr)
        return ret;
    ret = CreateWindowFromNib(nibRef, CFSTR("Info"), &window);
    if (ret != noErr)
        return ret;
    DisposeNibReference(nibRef);
    this->infowindow = window;
    InstallWindowEventHandler(this->infowindow,
			      NewEventHandlerUPP(CloseWindowEventHandler),
			      1, &closespec,
                              this, NULL);
    return 0;
}

OSStatus
infoWindow (ArlaCMMType *this, UInt8 *path)
{
    OSStatus ret;
    ControlHandle textcontrol;
    ControlHandle volumenamecontrol;
    ControlHandle quotausablecontrol;
    ControlHandle quotausedcontrol;
    ControlHandle cellnamecontrol;
    ControlHandle fileserverscontrol;
    CFStringRef volname;
    int quota;
    int used;
    CFStringRef quotastring;
    CFStringRef usedstring;
    CFStringRef cellname;
    CFStringRef fileservers;

    ret = createWindow(this);
    if (ret != noErr)
        return ret;

    ret = getvolstat(path, &volname, &quota, &used);
    if (ret)
	return ret;

    ret = getfilecellname(path, &cellname);
    if (ret) {
        CFRelease(volname);
	return ret;
    }

    ret = getfileservers(path, &fileservers);
    if (ret) {
        CFRelease(volname);
	CFRelease(cellname);
	return ret;
    }

    GetControlByID(this->infowindow, &textcontrolid, &textcontrol);
    this->path = CFStringCreateWithCString(NULL, path, kCFStringEncodingUTF8);
    ret = SetControlData(textcontrol, 0, kControlEditTextCFStringTag,
			 sizeof(CFStringRef), &this->path);

    GetControlByID(this->infowindow, &volumenameid, &volumenamecontrol);
    ret = SetControlData(volumenamecontrol, 0, kControlEditTextCFStringTag,
			 sizeof(CFStringRef), &volname);

    quotastring = CFStringCreateWithFormat(NULL, NULL, CFSTR("%d KB"),
					   quota);

    usedstring = CFStringCreateWithFormat(NULL, NULL, CFSTR("%d KB"),
					  used);

    GetControlByID(this->infowindow, &quotausableid, &quotausablecontrol);
    ret = SetControlData(quotausablecontrol, 0, kControlEditTextCFStringTag,
			 sizeof(CFStringRef), &quotastring);

    GetControlByID(this->infowindow, &quotausedid, &quotausedcontrol);
    ret = SetControlData(quotausedcontrol, 0, kControlEditTextCFStringTag,
			 sizeof(CFStringRef), &usedstring);

    GetControlByID(this->infowindow, &cellnameid, &cellnamecontrol);
    ret = SetControlData(cellnamecontrol, 0, kControlEditTextCFStringTag,
			 sizeof(CFStringRef), &cellname);

    GetControlByID(this->infowindow, &fileserversid, &fileserverscontrol);
    ret = SetControlData(fileserverscontrol, 0, kControlEditTextCFStringTag,
			 sizeof(CFStringRef), &fileservers);

    CFRelease(volname);
    CFRelease(quotastring);
    CFRelease(usedstring);
    CFRelease(cellname);
    CFRelease(fileservers);

    ShowWindow(this->infowindow);
    return 0;
}
