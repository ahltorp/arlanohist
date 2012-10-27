/*
 * Copyright (c) 1999, 2002, 2003 Kungliga Tekniska Högskolan
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


#define INITGUID /* XXX why */

#include "nnpfs_locl.h"

#define NNPFS_FS_NAME	L"\\Device\\NNPFS"


struct nnpfs_channel NNPFSGlobalData;

/*
 * initialize events
 */

int
init_event (struct nnpfs_channel *chan)
{
    if (chan->init_event == 0) {
	KeInitializeEvent (&chan->pending_event, SynchronizationEvent, FALSE);
	KeInitializeEvent (&chan->wake_event, NotificationEvent, FALSE);
	KeInitializeSemaphore (&chan->message_sem, 1, 1);
	KeInitializeSemaphore (&chan->sleep_sem, 1, 1);
	chan->init_event = 1;
    }
    return STATUS_SUCCESS;
}

/*
 * Add a new device
 */

static NTSTATUS
nnpfs_adddevice(PDRIVER_OBJECT driver,
	      PDEVICE_OBJECT PhysicalDeviceObject)
{
    int 		RC;
    UNICODE_STRING	devname;


    /* Create device */
    RtlInitUnicodeString(&devname, NNPFS_FS_NAME);
    RC = IoCreateDevice(driver,
			0,
			&devname,
			FILE_DEVICE_DISK_FILE_SYSTEM, //FILE_DEVICE_NETWORK_FILE_SYSTEM,
			0,
			FALSE,
			&NNPFSGlobalData.device);


    if (!NT_SUCCESS (RC)) {
	nnpfs_debug (XDEBLKM, "IoCreateDevice failed with %d\n", (int)RC);
	return RC;
    }

    /*
     * Init message queue
     */

    XLIST_LISTHEAD_INIT(&NNPFSGlobalData.messageq);
    XLIST_LISTHEAD_INIT(&NNPFSGlobalData.sleepq);

    init_event(&NNPFSGlobalData);


    /*
     * Init nodes
     */
    
    ExInitializeFastMutex(&NNPFSGlobalData.NodeListMutex);
    XLIST_LISTHEAD_INIT(&NNPFSGlobalData.nodes);
    
    /*
     * Tell io manager that we have initialized.
     */

    NNPFSGlobalData.device->Flags &= ~DO_DEVICE_INITIALIZING;

    IoRegisterFileSystem (NNPFSGlobalData.device);

#if 0
    RC = IoRegisterShutdownNotification(NNPFSGlobalData.device);
    if (!NT_SUCCESS(RC))
	try_return (RC);
    RegShutdown = TRUE;
#endif

    nnpfs_debug (XDEBLKM, "IoCreateDevice done\n");

    return RC;
}


/*
 *
 */

NTSTATUS
nnpfs_start_device(PDEVICE_OBJECT driver, PIRP irp)
{
    nnpfs_debug (XDEBLKM, "nnpfs_start_device\n");
    IoCompleteRequest (irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/*
 *
 */

NTSTATUS
nnpfs_remove_device(PDEVICE_OBJECT driver, PIRP irp)
{
    nnpfs_debug (XDEBLKM, "nnpfs_remove_device\n");
    IoCompleteRequest (irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/*
 *
 */

static NTSTATUS
nnpfs_pnp(PDEVICE_OBJECT driver, PIRP irp)
{
    IO_STACK_LOCATION *io_stack;
    int RC;

    nnpfs_debug (XDEBLKM, "nnpfs_pnp\n");

    io_stack = IoGetCurrentIrpStackLocation(irp);
    ASSERT(io_stack);

    switch (io_stack->MinorFunction) {
    case IRP_MN_START_DEVICE:
	RC = nnpfs_start_device (driver, irp);
	break;
    case IRP_MN_REMOVE_DEVICE:
	RC = nnpfs_remove_device (driver, irp);
	break;
    case IRP_MN_DEVICE_USAGE_NOTIFICATION:
    default:
	IoCompleteRequest (irp, IO_NO_INCREMENT);
	RC = STATUS_SUCCESS;
    }
    nnpfs_debug (XDEBLKM, "nnpfs_pnp: returns %d\n", (int)RC);

    return RC;
}

/*
 *
 */

static NTSTATUS
nnpfs_power(PDEVICE_OBJECT driver, PIRP irp)
{
    UNREFERENCED_PARAMETER(driver);

    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/*
 * 
 */

VOID
nnpfs_unload(PDRIVER_OBJECT driver)
{
    nnpfs_channel *chan = &NNPFSGlobalData;
#if 0
    if (RegShutdown)
	IoUnregisterShutdownNotification(chan->device);
#endif

    /* delete device */
    if (chan->device) {
	IoDeleteDevice(chan->device);
	chan->device = NULL;
    }

    /* FreeDNLC & co*/

    nnpfs_dnlc_shutdown(chan->dnlc);
    nnpfs_free(chan->dnlc, sizeof(*(chan->dnlc)));

    if ( NNPFS_TESTFLAGS (chan->flags, NNPFSCHAN_FLAGS_GLOBALLOCK))
	ExDeleteResourceLite(&chan->lock);

    nnpfs_log(chan->device, 4711,
	    STATUS_SUCCESS, STATUS_NO_MEDIA_IN_DEVICE);

    return;
}

/*
 * Set up the IRP table for `driver'
 */

static void
nnpfs_initdevice(nnpfs_channel *chan)
{
    DRIVER_OBJECT *driver = chan->driver;
    FAST_IO_DISPATCH *fastio;

#if 0
#define PRINT_FUNC_ADDR(x) \
    nnpfs_debug(XDEBLKM, #x " %08x\n", x)

    PRINT_FUNC_ADDR (nnpfs_create);
    PRINT_FUNC_ADDR (nnpfs_close);
    PRINT_FUNC_ADDR (nnpfs_readwrite);
    PRINT_FUNC_ADDR (nnpfs_fileinfo);
    PRINT_FUNC_ADDR (nnpfs_flush);
    PRINT_FUNC_ADDR (nnpfs_dirctl);
    PRINT_FUNC_ADDR (nnpfs_devctl);
    PRINT_FUNC_ADDR (nnpfs_shutdown);
    PRINT_FUNC_ADDR (nnpfs_cleanup);
    PRINT_FUNC_ADDR (nnpfs_queryvol);
    PRINT_FUNC_ADDR (nnpfs_fscontrol);
    PRINT_FUNC_ADDR (nnpfs_get_root);
    PRINT_FUNC_ADDR (nnpfs_message_rpc);

#undef PRINT_FUNC_ADDR
#endif

    driver->MajorFunction[IRP_MJ_CREATE]		= nnpfs_fsd_create;
    driver->MajorFunction[IRP_MJ_CLOSE]			= nnpfs_fsd_close;
    driver->MajorFunction[IRP_MJ_READ]			= nnpfs_fsd_readwrite;
    driver->MajorFunction[IRP_MJ_WRITE]			= nnpfs_fsd_readwrite;
    driver->MajorFunction[IRP_MJ_QUERY_INFORMATION]	= nnpfs_fsd_fileinfo;
    driver->MajorFunction[IRP_MJ_SET_INFORMATION]	= nnpfs_fsd_fileinfo;


    driver->MajorFunction[IRP_MJ_FLUSH_BUFFERS]		= nnpfs_fsd_flush;
    driver->MajorFunction[IRP_MJ_DIRECTORY_CONTROL]	= nnpfs_fsd_dirctl;

    driver->MajorFunction[IRP_MJ_DEVICE_CONTROL]	= nnpfs_fsd_devctl;
    driver->MajorFunction[IRP_MJ_SHUTDOWN]		= nnpfs_fsd_shutdown;

    driver->MajorFunction[IRP_MJ_CLEANUP]		= nnpfs_fsd_cleanup;

    driver->MajorFunction[IRP_MJ_QUERY_VOLUME_INFORMATION] = nnpfs_fsd_queryvol;

    driver->MajorFunction[IRP_MJ_FILE_SYSTEM_CONTROL] 	= nnpfs_fsd_fscontrol;

#if 0
    driver->MajorFunction[IRP_MJ_PNP]			= nnpfs_fsd_pnp;
    driver->MajorFunction[IRP_MJ_POWER]			= nnpfs_fsd_power;
    driver->DriverExtension->AddDevice            	= nnpfs_fsd_adddevice;
#endif
    driver->DriverUnload                          	= nnpfs_unload;


    /* not implemented yet ... */

#if 0

    /* volume junk */
    driver->MajorFunction[IRP_MJ_SET_VOLUME_INFORMATION] = foo;

    /* byte range locks */
    // driver->MajorFunction[IRP_MJ_LOCK_CONTROL] = LockControl;

    /* extended security */
    driver->MajorFunction[IRP_MJ_QUERY_SECURITY] = Security;
    driver->MajorFunction[IRP_MJ_SET_SECURITY] = Security;

    /* extended attributes */
    driver->MajorFunction[IRP_MJ_QUERY_EA] = ExtendedAttr;
    driver->MajorFunction[IRP_MJ_SET_EA] = ExtendedAttr;
#endif

    /*  fast-io */
    fastio = driver->FastIoDispatch = &(chan->fastio_dispatch);
    fastio->SizeOfFastIoDispatch = sizeof(chan->fastio_dispatch);

    fastio->FastIoCheckIfPossible	= nnpfs_fastio_possible;
    fastio->FastIoRead			= nnpfs_fastio_read;
    fastio->FastIoWrite			= nnpfs_fastio_write;

    fastio->AcquireFileForNtCreateSection = nnpfs_createsec_acq;
    fastio->ReleaseFileForNtCreateSection = nnpfs_createsec_rel;

    fastio->AcquireForModWrite		= nnpfs_modwrite_acq;
    fastio->ReleaseForModWrite		= nnpfs_modwrite_rel;

#if 0
    fastio->FastIoQueryBasicInfo	= FastIoQueryBasicInfo;
    fastio->FastIoQueryStandardInfo	= FastIoQueryStdInfo;
    fastio->FastIoLock			= FastIoLock;
    fastio->FastIoUnlockSingle		= FastIoUnlockSingle;
    fastio->FastIoUnlockAll		= FastIoUnlockAll;
    fastio->FastIoUnlockAllByKey	= FastIoUnlockAllByKey;

#if(_WIN32_WINNT >= 0x0400)
    fastio->FastIoQueryNetworkOpenInfo = FastIoQueryNetInfo;
//    fastio->AcquireForModWrite		= FastIoAcqModWrite;
//    fastio->ReleaseForModWrite		= FastIoRelModWrite;
    fastio->AcquireForCcFlush		= FastIoAcqCcFlush;
    fastio->ReleaseForCcFlush		= FastIoRelCcFlush;

    /* things for using MDLs */
    fastio->MdlRead			= FastIoMdlRead;
    fastio->MdlReadComplete		= FastIoMdlReadComplete;
    fastio->PrepareMdlWrite		= FastIoPrepareMdlWrite;
    fastio->MdlWriteComplete		= FastIoMdlWriteComplete;
#endif	// (_WIN32_WINNT >= 0x0400)
#endif

    /* Cache Manager callbacks */
    chan->cc_callbacks.AcquireForLazyWrite = nnpfs_lazywrite_acq;
    chan->cc_callbacks.ReleaseFromLazyWrite = nnpfs_lazywrite_rel;
    chan->cc_callbacks.AcquireForReadAhead = nnpfs_readahead_acq;
    chan->cc_callbacks.ReleaseFromReadAhead = nnpfs_readahead_rel;

    return;
}

/*
 * Allocate the zone's for Node and CCB
 */

#define DEFAULT_ZONE_SIZE 100


static NTSTATUS
InitFS (nnpfs_channel *chan)
{
    NTSTATUS				RC = STATUS_SUCCESS;
    uint32_t ccbzone_sz = 
	(40 * DEFAULT_ZONE_SIZE * AlignPointer(sizeof(nnpfs_ccb))) +
	sizeof(ZONE_SEGMENT_HEADER);
    uint32_t nodezone_sz = 
	(40 * DEFAULT_ZONE_SIZE * AlignPointer(sizeof(struct nnpfs_node))) +
	sizeof(ZONE_SEGMENT_HEADER);
    uint32_t linkzone_sz = 
	(4 * DEFAULT_ZONE_SIZE * AlignPointer(sizeof(struct nnpfs_link))) +
	sizeof(ZONE_SEGMENT_HEADER);

    /* XXX MmQuerySystemSize() and MmIsThisAnNtAsSystem() */

    ExInitializeFastMutex(&chan->ZoneAllocationMutex);

    chan->CCBZone = ExAllocatePool(NonPagedPool, ccbzone_sz);
    if (chan->CCBZone == NULL) {
	nnpfs_debug (XDEBLKM, "ExAllocatePool failed for CCBZone\n");
	RC = STATUS_INSUFFICIENT_RESOURCES;
	return RC;
    }
    chan->NodeZone = ExAllocatePool(NonPagedPool, nodezone_sz);
    if (chan->NodeZone == NULL) {
	nnpfs_debug (XDEBLKM, "ExAllocatePool failed for NodeZone\n");
	RC = STATUS_INSUFFICIENT_RESOURCES;
	return RC;
    }
    chan->LinkZone = ExAllocatePool(NonPagedPool, linkzone_sz);
    if (chan->LinkZone == NULL) {
	nnpfs_debug (XDEBLKM, "ExAllocatePool failed for LinkZone\n");
	RC = STATUS_INSUFFICIENT_RESOURCES;
	return RC;
    }

    RC = ExInitializeZone(&(chan->CCBZoneHeader),
			  AlignPointer(sizeof(nnpfs_ccb)),
			  chan->CCBZone,
			  ccbzone_sz);

    if (!NT_SUCCESS (RC)) {
	nnpfs_debug (XDEBLKM,
		   "ExInitializeZone failed for CCBZone with %d\n", RC);
	return RC;
    }
    RC = ExInitializeZone(&(chan->NodeZoneHeader),
			  AlignPointer(sizeof(struct nnpfs_node)),
			  chan->NodeZone,
			  nodezone_sz);

    if (!NT_SUCCESS (RC)) {
	nnpfs_debug (XDEBLKM,
		   "ExInitializeZone failed for NodeZone with %d\n", RC);
	return RC;
    }
    RC = ExInitializeZone(&(chan->LinkZoneHeader),
			  AlignPointer(sizeof(struct nnpfs_link)),
			  chan->LinkZone,
			  linkzone_sz);

    if (!NT_SUCCESS (RC)) {
	nnpfs_debug (XDEBLKM,
		   "ExInitializeZone failed for NodeZone with %d\n", RC);
	return RC;
    }

    return RC;
}


/*
* The entrypoint for the driver
*/


NTSTATUS
DriverEntry(PDRIVER_OBJECT driver,
	    PUNICODE_STRING	RegistryPath)
{
    NTSTATUS		RC = STATUS_SUCCESS;
    BOOLEAN		RegShutdown = FALSE;
    nnpfs_channel         *chan = &NNPFSGlobalData;

    nnpfs_debug (XDEBLKM, "DriverEntry: Trying to load\n");
   
    RtlZeroMemory(chan, sizeof(*chan));
    chan->magic = NNPFS_DEV_DATA_MAGIC;
   
    /* init resource */
    RC = ExInitializeResourceLite(&(chan->lock));
    ASSERT(NT_SUCCESS(RC));
    NNPFS_SETFLAGS (chan->flags, NNPFSCHAN_FLAGS_GLOBALLOCK);
   
   
    /* save entry for later use */
    chan->driver = driver;
   
#if 0
    /* init logical volume block structure */
    InitializeListHead(&(chan->NextVCB));
#endif
   
   
    /* Create DNLC
     *        Locking
     */

    chan->dnlc = nnpfs_alloc(sizeof(*(chan->dnlc)), 'ide1');
    if (chan->dnlc == NULL)
	try_return(RC = STATUS_NO_MEMORY); /* XXX cleanup */

    nnpfs_dnlc_init(chan->dnlc);
   
    /* set up function pointer */
    RC = InitFS (chan);
    if (!NT_SUCCESS(RC))
	try_return(RC);
    nnpfs_initdevice(chan);
   
    RC = nnpfs_adddevice (driver, NULL);

    nnpfs_debug (XDEBLKM, "DriverEntry: ended up with: %d\n", (int) RC);
   
    if (NT_SUCCESS(RC)) {
	NNPFS_SETFLAGS (chan->flags, NNPFSCHAN_FLAGS_OPEN);
	return STATUS_SUCCESS;
    }

 try_exit: 
   
    nnpfs_debug (XDEBLKM, "DriverEntry: bailed out\n");

    nnpfs_log(chan->device, 4711, RC,
	    STATUS_NO_MEDIA_IN_DEVICE);

    nnpfs_unload (driver);

    return RC;
}

