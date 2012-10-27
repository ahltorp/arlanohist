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

RCSID("$Id: adduserwin.c,v 1.4 2002/04/23 12:38:04 ahltorp Exp $");

static OSStatus
fillAddUserGroupsList(ArlaCMMType *this)
{
    ControlHandle popupcontrol;
    ControlID popupcontrolid = {kAddUserWindowID, kAddUserPopUpMenu};
    CFArrayRef array;
    CFStringRef strs[3];
    MenuRef menu;
    CFStringRef text;
    SInt32 len;
    int i;
    
    if (this->groups)
        return 0;
    
    strs[0] = CFSTR("Common groups");
    strs[1] = CFSTR("system:administrators");
    strs[2] = CFSTR("system:authuser");
    strs[3] = CFSTR("system:anyuser");
    
    array = CFArrayCreate(NULL, (void *)strs, 4, &kCFTypeArrayCallBacks);
    
    GetControlByID(this->adduserwindow, &popupcontrolid, &popupcontrol);
    menu = GetControlPopupMenuHandle(popupcontrol);
    DeleteMenuItems(menu, 1, CountMenuItems(menu));

    len = CFArrayGetCount(array);

    for (i = 0; i < len; i++) {
        text = CFArrayGetValueAtIndex(array, i);
        AppendMenuItemTextWithCFString(menu, text, 0, 0, NULL);
    }

    SetControl32BitMaximum(popupcontrol, len);
    SetControl32BitValue(popupcontrol, 1);
    
    this->groups = CFArrayCreateMutableCopy(NULL, 0, array);
    CFRelease(array);
    
    return 0;
}

static OSStatus
addUserCopyFromList(ArlaCMMType *this)
{
    ControlHandle popupcontrol;
    ControlID popupcontrolid = {kAddUserWindowID, kAddUserPopUpMenu};
    ControlHandle textcontrol;
    ControlID textcontrolid = {kAddUserWindowID, kAddUserTextField};
    SInt32 entrynum;
    CFStringRef text;
    OSStatus ret;

    if (this->groups == NULL)
        return 0;

    GetControlByID(this->adduserwindow, &popupcontrolid, &popupcontrol);
    GetControlByID(this->adduserwindow, &textcontrolid, &textcontrol);

    entrynum = GetControl32BitValue(popupcontrol);

    if (entrynum == 1)
        return 0;

    text = CFArrayGetValueAtIndex(this->groups, entrynum - 1);
    ret = SetControlData(textcontrol, 0, kControlEditTextCFStringTag,
			 sizeof(CFStringRef), &text);
    if (ret != noErr)
        return ret;
    DrawOneControl(textcontrol);

    return 0;
}

static pascal OSStatus
AddUserWindowEventHandler(EventHandlerCallRef handlerRef,
			  EventRef event, void *userData)
{
    HICommand command;
    OSStatus ret = eventNotHandledErr;
    ArlaCMMType *this = (ArlaCMMType *)userData;
    CFStringRef username;
    Size outActualsize;
    ControlHandle textcontrol;
    ControlID textcontrolid = {kAddUserWindowID, kAddUserTextField};
    
    GetEventParameter(event, kEventParamDirectObject, typeHICommand,
		      NULL, sizeof(HICommand), NULL, &command);
    switch (command.commandID) {
        case kHICommandOK:
	    GetControlByID(this->adduserwindow, &textcontrolid, &textcontrol);
	    ret = GetControlData(textcontrol, 0, kControlEditTextCFStringTag,
				 sizeof(CFStringRef), &username,
				 &outActualsize);
	    addAclItem(this, username);
            ret = HideSheetWindow(this->adduserwindow);
            break;
        case kHICommandCancel:
            ret = HideSheetWindow(this->adduserwindow);            
            break;
        case kAddUserPopUpMenuCommand:
            ret = addUserCopyFromList(this);
            break;
    }
    return ret;
}

static OSStatus
createAddUserWindow(ArlaCMMType *this)
{
    IBNibRef 		nibRef;
    CFBundleRef bundle;
    OSStatus ret;
    WindowRef window;
    EventTypeSpec commandspec = {kEventClassCommand, kEventProcessCommand };

    if (this->adduserwindow)
        return 0;
        
    bundle = CFBundleGetBundleWithIdentifier(
	CFSTR("se.kth.stacken.arla.macosx.cmm"));
    ret = CreateNibReferenceWithCFBundle(bundle, CFSTR("dialog"), &nibRef);
    if (ret != noErr)
        return ret;
    ret = CreateWindowFromNib(nibRef, CFSTR("adduser"), &window);
    if (ret != noErr)
        return ret;
    DisposeNibReference(nibRef);
    this->adduserwindow = window;
    InstallWindowEventHandler(this->adduserwindow,
			      NewEventHandlerUPP(AddUserWindowEventHandler),
			      1, &commandspec,
                              this, NULL);
    fillAddUserGroupsList(this);
    return 0;
}

OSStatus
addUserWindow (ArlaCMMType *this)
{
    OSStatus ret;

    ret = createAddUserWindow(this);
    if (ret == noErr) {
        ret = ShowSheetWindow(this->adduserwindow, this->permwindow);
    }
    
    return 0;
}
