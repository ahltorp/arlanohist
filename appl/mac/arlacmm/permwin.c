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

RCSID("$Id: permwin.c,v 1.9 2002/04/23 16:26:44 ahltorp Exp $");

static ControlID lookupcontrolid = {kControlID, kPermissionLookupControl};
static ControlID insertcontrolid = {kControlID, kPermissionInsertControl};
static ControlID deletecontrolid = {kControlID, kPermissionDeleteControl};
static ControlID admincontrolid = {kControlID, kPermissionAdministerControl};
static ControlID readcontrolid = {kControlID, kPermissionReadControl};
static ControlID writecontrolid = {kControlID, kPermissionWriteControl};
static ControlID lockcontrolid = {kControlID, kPermissionLockControl};

static OSStatus
showAclItem(ArlaCMMType *this)
{
    ControlHandle popupcontrol;
    ControlID popupcontrolid = {kControlID, kPopUpMenuControl};
    ControlHandle lookupcontrol;
    ControlHandle insertcontrol;
    ControlHandle deletecontrol;
    ControlHandle admincontrol;
    ControlHandle readcontrol;
    ControlHandle writecontrol;
    ControlHandle lockcontrol;
    SInt32 entrynum;
    CFStringRef text;
    CFArrayRef array;
    int perm;

    if (this->acl == NULL)
        return paramErr;
        
    GetControlByID(this->permwindow, &popupcontrolid, &popupcontrol);

    GetControlByID(this->permwindow, &lookupcontrolid, &lookupcontrol);
    GetControlByID(this->permwindow, &insertcontrolid, &insertcontrol);
    GetControlByID(this->permwindow, &deletecontrolid, &deletecontrol);
    GetControlByID(this->permwindow, &admincontrolid, &admincontrol);
    GetControlByID(this->permwindow, &readcontrolid, &readcontrol);
    GetControlByID(this->permwindow, &writecontrolid, &writecontrol);
    GetControlByID(this->permwindow, &lockcontrolid, &lockcontrol);

    entrynum = GetControl32BitValue(popupcontrol);

    text = CFArrayGetValueAtIndex(this->acl, entrynum + 1);
    array = CFStringCreateArrayBySeparatingStrings(NULL, text, CFSTR("\t"));
    if (CFArrayGetCount(array) != 2)
        return paramErr;
    perm = CFStringGetIntValue(CFArrayGetValueAtIndex(array, 1));

    SetControl32BitValue(lookupcontrol, (perm & PRSFS_LOOKUP) != 0);
    SetControl32BitValue(insertcontrol, (perm & PRSFS_INSERT) != 0);
    SetControl32BitValue(deletecontrol, (perm & PRSFS_DELETE) != 0);
    SetControl32BitValue(admincontrol, (perm & PRSFS_ADMINISTER) != 0);
    SetControl32BitValue(readcontrol, (perm & PRSFS_READ) != 0);
    SetControl32BitValue(writecontrol, (perm & PRSFS_WRITE) != 0);
    SetControl32BitValue(lockcontrol, (perm & PRSFS_LOCK) != 0);

    CFRelease(array);
    return 0;
}

static void
updateApplyButton(ArlaCMMType *this)
{
    CFStringRef acl_string;
    ControlHandle applycontrol;
    ControlID applycontrolid = {kControlID, kApplyButtonControl};

    acl_string = CFStringCreateByCombiningStrings(NULL, this->acl, CFSTR("\n"));
    GetControlByID(this->permwindow, &applycontrolid, &applycontrol);

    if (CFStringCompare(acl_string, this->aclcopy, 0) == 0)
	DeactivateControl(applycontrol);
    else
	ActivateControl(applycontrol);

}

static OSStatus
redrawAclList(ArlaCMMType *this, SInt32 position)
{
    ControlHandle popupcontrol;
    ControlID popupcontrolid = {kControlID, kPopUpMenuControl};
    MenuRef menu;
    SInt32 aclpos;
    SInt32 aclneg;
    int i;
    CFStringRef text;
    CFArrayRef array;
    CFStringRef username;
    OSStatus ret;

    GetControlByID(this->permwindow, &popupcontrolid, &popupcontrol);
    menu = GetControlPopupMenuHandle(popupcontrol);
    DeleteMenuItems(menu, 1, CountMenuItems(menu));

    aclpos = CFStringGetIntValue(CFArrayGetValueAtIndex(this->acl, 0));
    aclneg = CFStringGetIntValue(CFArrayGetValueAtIndex(this->acl, 1));
    for (i = 0; i < aclpos; i++) {
        text = CFArrayGetValueAtIndex(this->acl, i + 2);
        array = CFStringCreateArrayBySeparatingStrings(NULL, text,
						       CFSTR("\t"));
        if (CFArrayGetCount(array) == 2) {
            username = CFArrayGetValueAtIndex(array, 0);
            AppendMenuItemTextWithCFString(menu, username, 0,
					   kMenuStart - 2 + i, NULL);
        }
    }

    SetControl32BitMaximum(popupcontrol, aclpos);
    if (position)
	SetControl32BitValue(popupcontrol, position);
    else
	SetControl32BitValue(popupcontrol, 1);

    ret = showAclItem(this);
    if (ret != noErr)
        return ret;

    return 0;
}

static OSStatus
changeAclItem(ArlaCMMType *this)
{
    ControlHandle popupcontrol;
    ControlID popupcontrolid = {kControlID, kPopUpMenuControl};
    ControlHandle lookupcontrol;
    ControlHandle insertcontrol;
    ControlHandle deletecontrol;
    ControlHandle admincontrol;
    ControlHandle readcontrol;
    ControlHandle writecontrol;
    ControlHandle lockcontrol;
    SInt32 entrynum;
    CFStringRef text;
    CFArrayRef array;
    int perm;

    if (this->acl == NULL)
        return paramErr;
        
    GetControlByID(this->permwindow, &popupcontrolid, &popupcontrol);

    GetControlByID(this->permwindow, &lookupcontrolid, &lookupcontrol);
    GetControlByID(this->permwindow, &insertcontrolid, &insertcontrol);
    GetControlByID(this->permwindow, &deletecontrolid, &deletecontrol);
    GetControlByID(this->permwindow, &admincontrolid, &admincontrol);
    GetControlByID(this->permwindow, &readcontrolid, &readcontrol);
    GetControlByID(this->permwindow, &writecontrolid, &writecontrol);
    GetControlByID(this->permwindow, &lockcontrolid, &lockcontrol);

    entrynum = GetControl32BitValue(popupcontrol);

    perm = 0;

    if (GetControl32BitValue(lookupcontrol))
	perm |= PRSFS_LOOKUP;
    if (GetControl32BitValue(insertcontrol))
	perm |= PRSFS_INSERT;
    if (GetControl32BitValue(deletecontrol))
	perm |= PRSFS_DELETE;
    if (GetControl32BitValue(admincontrol))
	perm |= PRSFS_ADMINISTER;
    if (GetControl32BitValue(readcontrol))
	perm |= PRSFS_READ;
    if (GetControl32BitValue(writecontrol))
	perm |= PRSFS_WRITE;
    if (GetControl32BitValue(lockcontrol))
	perm |= PRSFS_LOCK;

    text = CFArrayGetValueAtIndex(this->acl, entrynum + 1);
    array = CFStringCreateArrayBySeparatingStrings(NULL, text, CFSTR("\t"));
    if (CFArrayGetCount(array) != 2)
        return paramErr;
    text = CFStringCreateWithFormat(NULL, NULL, CFSTR("%@\t%d"),
				    CFArrayGetValueAtIndex(array, 0), perm);
    CFArraySetValueAtIndex(this->acl, entrynum + 1, text);

    CFRelease(text);
    CFRelease(array);
    updateApplyButton(this);
    return 0;
}

static OSStatus
removeAclItem(ArlaCMMType *this)
{
    SInt32 aclpos;
    SInt32 entrynum;
    CFStringRef text;
    ControlHandle popupcontrol;
    ControlID popupcontrolid = {kControlID, kPopUpMenuControl};

    if (this->acl == NULL)
        return paramErr;
        
    GetControlByID(this->permwindow, &popupcontrolid, &popupcontrol);

    aclpos = CFStringGetIntValue(CFArrayGetValueAtIndex(this->acl, 0));

    if (aclpos == 0)
	return paramErr;

    entrynum = GetControl32BitValue(popupcontrol);

    if (entrynum < 1)
	return paramErr;

    CFArrayRemoveValueAtIndex(this->acl, entrynum+1);
    
    text = CFStringCreateWithFormat(NULL, NULL, CFSTR("%d"),
				    aclpos - 1);
    CFArraySetValueAtIndex(this->acl, 0, text);
    CFRelease(text);

    redrawAclList(this, 0);
    updateApplyButton(this);

    return 0;
}

OSStatus
addAclItem(ArlaCMMType *this, CFStringRef username)
{
    SInt32 aclpos;
    CFStringRef text;
    ControlHandle popupcontrol;
    ControlID popupcontrolid = {kControlID, kPopUpMenuControl};
    CFArrayRef array;
    CFStringRef username2;
    int i;

    if (this->acl == NULL)
        return paramErr;
        
    GetControlByID(this->permwindow, &popupcontrolid, &popupcontrol);

    aclpos = CFStringGetIntValue(CFArrayGetValueAtIndex(this->acl, 0));

    for (i = 0; i < aclpos; i++) {
        text = CFArrayGetValueAtIndex(this->acl, i + 2);
        array = CFStringCreateArrayBySeparatingStrings(NULL, text,
						       CFSTR("\t"));
        if (CFArrayGetCount(array) == 2) {
            username2 = CFArrayGetValueAtIndex(array, 0);
	    if (CFStringCompare(username, username2, 0) == 0) {
		redrawAclList(this, i + 1);
		return 0;
	    }
        }
    }

    text = CFStringCreateWithFormat(NULL, NULL, CFSTR("%@\t0"),
				    username);
    CFArrayInsertValueAtIndex(this->acl, aclpos + 2, text);
    CFRelease(username);
    CFRelease(text);
    
    text = CFStringCreateWithFormat(NULL, NULL, CFSTR("%d"),
				    aclpos + 1);
    CFArraySetValueAtIndex(this->acl, 0, text);
    CFRelease(text);

    redrawAclList(this, aclpos + 1);
    updateApplyButton(this);

    return 0;
}

static OSStatus
applyAcl(ArlaCMMType *this)
{
    CFStringRef acl_string;
    CFIndex acl_length;
    CFIndex path_length;
    OSStatus ret;
    UInt8 *acl_buffer;
    UInt8 *path_buffer;

    acl_string = CFStringCreateByCombiningStrings(NULL, this->acl, CFSTR("\n"));

    acl_length = CFStringGetMaximumSizeForEncoding(
	CFStringGetLength(acl_string),
	kCFStringEncodingUTF8);
    path_length = CFStringGetMaximumSizeForEncoding(
	CFStringGetLength(this->path),
	kCFStringEncodingUTF8);
    acl_buffer = malloc(acl_length);
    if (acl_buffer == NULL) {
	CFRelease(acl_string);
	return memFullErr;
    }
    path_buffer = malloc(path_length);
    if (path_buffer == NULL) {
	free(acl_buffer);
	CFRelease(acl_string);
	return memFullErr;
    }

    ret = CFStringGetCString(acl_string, acl_buffer, acl_length,
			     kCFStringEncodingUTF8);
    if (!ret) {
	free(path_buffer);
	free(acl_buffer);
	CFRelease(acl_string);
	return paramErr;	
    }

    ret = CFStringGetCString(this->path, path_buffer, path_length,
			     kCFStringEncodingUTF8);
    if (!ret) {
	free(path_buffer);
	free(acl_buffer);
	CFRelease(acl_string);
	return paramErr;	
    }

    ret = setacl(path_buffer, acl_buffer);

    if (ret == 0) {
	CFRelease(this->aclcopy);
	this->aclcopy = CFStringCreateCopy(NULL, acl_string);
    }

    updateApplyButton(this);
    return ret;
}

static pascal OSStatus
MainWindowEventHandler(EventHandlerCallRef handlerRef,
		       EventRef event, void *userData)
{
    HICommand command;
    OSStatus ret = eventNotHandledErr;
    ArlaCMMType *this = (ArlaCMMType *)userData;
    
    GetEventParameter(event, kEventParamDirectObject, typeHICommand,
		      NULL, sizeof(HICommand), NULL, &command);
    switch (command.commandID) {
        case kCloseButtonCmd:
            HideWindow(this->permwindow);
            ret = noErr;
            break;
        case kApplyButtonCmd:
	    ret = applyAcl(this);
	    if (ret)
		SysBeep(1);
            break;
        case kDeleteButtonCmd:
	    ret = removeAclItem(this);
            break;
        case kPopUpMenuCmd:
            ret = showAclItem(this);
            break;
        case kChangeCheckCmd:
	    ret = changeAclItem(this);
            break;
        case kAddButtonCmd:
            ret = addUserWindow(this);
            break;
    }
    return ret;
}

static pascal OSStatus
CloseWindowEventHandler(EventHandlerCallRef handlerRef,
		       EventRef event, void *userData)
{
    ArlaCMMType *this = (ArlaCMMType *)userData;

    HideWindow(this->permwindow);

    return noErr;
}

static OSStatus
createWindow(ArlaCMMType *this)
{
    IBNibRef 		nibRef;
    CFBundleRef bundle;
    OSStatus ret;
    WindowRef window;
    EventTypeSpec commandspec = {kEventClassCommand, kEventProcessCommand };
    EventTypeSpec closespec = {kEventClassWindow, kEventWindowClose };

    if (this->permwindow)
        return 0;
        
    bundle = CFBundleGetBundleWithIdentifier(
	CFSTR("se.kth.stacken.arla.macosx.cmm"));
    ret = CreateNibReferenceWithCFBundle(bundle, CFSTR("dialog"), &nibRef);
    if (ret != noErr)
        return ret;
    ret = CreateWindowFromNib(nibRef, CFSTR("Dialog"), &window);
    if (ret != noErr)
        return ret;
    DisposeNibReference(nibRef);
    this->permwindow = window;
    InstallWindowEventHandler(this->permwindow,
			      NewEventHandlerUPP(MainWindowEventHandler),
			      1, &commandspec,
                              this, NULL);
    InstallWindowEventHandler(this->permwindow,
			      NewEventHandlerUPP(CloseWindowEventHandler),
			      1, &closespec,
                              this, NULL);
    return 0;
}

OSStatus
permissionWindow (ArlaCMMType *this, UInt8 *path)
{
    OSStatus ret;
    ControlHandle textcontrol;
    ControlID textcontrolid = {kControlID, kFileNameControl};
    CFStringRef aclstring;
    CFArrayRef array;

    ret = createWindow(this);
    if (ret != noErr)
        return ret;
    GetControlByID(this->permwindow, &textcontrolid, &textcontrol);
    this->path = CFStringCreateWithCString(NULL, path, kCFStringEncodingUTF8);
    ret = SetControlData(textcontrol, 0, kControlEditTextCFStringTag,
			 sizeof(CFStringRef), &this->path);

    if (this->acl)
        CFRelease(this->acl);
        
    aclstring = getacl(path);
    if (aclstring == NULL)
        return paramErr;

    this->aclcopy = CFStringCreateCopy(NULL, aclstring);

    array = CFStringCreateArrayBySeparatingStrings(NULL, aclstring,
						   CFSTR("\n"));
    this->acl = CFArrayCreateMutableCopy(NULL, 0, array);
    CFRelease(array);
    CFRelease(aclstring);
    if (this->acl == NULL)
        return memFullErr;

    ret = redrawAclList(this, 0);
    if (ret)
	return ret;

    updateApplyButton(this);
    
    ShowWindow(this->permwindow);
    return 0;
}
