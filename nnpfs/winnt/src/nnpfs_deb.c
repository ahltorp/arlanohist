/*
 * Copyright (c) 1999, 2000, 2002-2004 Kungliga Tekniska Högskolan
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

/* $Id: nnpfs_deb.c,v 1.9 2004/05/13 08:21:08 tol Exp $ */

#include <nnpfs_locl.h>

LONG nnpfsdeb_SequenceNumber = 0;

static unsigned long debug_mask = 0;

LONG
nnpfs_log_new_seq (void)
{
    return nnpfsdeb_SequenceNumber++;
}


void
nnpfs_log(PDEVICE_OBJECT device, ULONG UniqueId,
	NTSTATUS ErrorCode, NTSTATUS Status)
{
    PIO_ERROR_LOG_PACKET errorLogEntry;
    
    errorLogEntry = (PIO_ERROR_LOG_PACKET)
	IoAllocateErrorLogEntry(device,
				(UCHAR)(sizeof(IO_ERROR_LOG_PACKET) + 
					sizeof(DEVICE_OBJECT)));
    
    if (errorLogEntry != NULL) {
	errorLogEntry->SequenceNumber	= 0;
	errorLogEntry->MajorFunctionCode = 0;
	errorLogEntry->RetryCount	= 0;
        errorLogEntry->ErrorCode 	= ErrorCode;
        errorLogEntry->UniqueErrorValue	= UniqueId;
        errorLogEntry->FinalStatus 	= Status;
	errorLogEntry->DumpDataSize	= 1;
	errorLogEntry->StringOffset	= sizeof(errorLogEntry);
	errorLogEntry->NumberOfStrings	= 0;

        /*
	 * The following is necessary because DumpData is of type ULONG
	 * and DeviceObject can be more than that
	 */
        RtlCopyMemory(
            &errorLogEntry->DumpData[0],
            &device,
            sizeof(DEVICE_OBJECT));
        errorLogEntry->DumpDataSize = sizeof(DEVICE_OBJECT);
        IoWriteErrorLogEntry(errorLogEntry);
    }
}

void
nnpfs_debug (unsigned long level, char *fmt, ...)
{
    va_list args;
    char str[300];
    
    if ((debug_mask & level) == 0)
	return;
    
    va_start (args, fmt);
    vsprintf (str, fmt, args);
    va_end (args);
    DbgPrint ("%4.4d: %s", PsGetCurrentProcessId(), str);
}
