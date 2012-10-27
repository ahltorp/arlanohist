/*
 * Copyright (c) 1999 Kungliga Tekniska Högskolan
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

#ifndef _NNPFS_NNPFS_LOCL_H
#define _NNPFS_NNPFS_LOCL_H

#include <stdio.h>
#include <ntddk.h>
#include <ntifs.h>
#include <stdarg.h>

#include <nnpfs_type.h>
#include <nnpfs_list.h>
#include <nnpfs/nnpfs_message.h>
#include <nnpfs_deb.h>
#include <nnpfs_dnlc.h>
#include <nnpfs_fastio.h>

struct NNPFS_VCB;
struct nnpfs_node;
struct nnpfs_ccb;

/* try-finally simulation */
#define try_return(S)	{ S; goto try_exit; }
#define try_return1(S)	{ S; goto try_exit1; }
#define try_return2(S)	{ S; goto try_exit2; }

#define NNPFS_DEV_DATA_MAGIC	0x4711C00E
#define NNPFS_DEV_NAME		L"nnpfs"

#define NNPFS_SETFLAGS(v,f) ((v) |= (f))
#define NNPFS_RESETFLAGS(v,f) ((v) &= ~(f))
#define NNPFS_TESTFLAGS(v,f) (((v) & (f)) == (f))

typedef enum _NNPFS_IDENTIFIER_TYPE {
    NNPFS_TYPE_FCB = 4711,
    NNPFS_TYPE_VCB,
    NNPFS_TYPE_CCB
} NNPFS_IDENTIFIER_TYPE;



/*
 * struct to keep track of info for nodes that might be deleted/moved
 */

typedef struct {
    char name[NNPFS_MAX_NAME + 1];
    struct nnpfs_node *link;
    struct nnpfs_node *parent;
} nnpfs_path_info;

typedef struct {
    int flags;
    char *name;
    unsigned long disposition;
    unsigned long attributes;
    unsigned long options;
    unsigned long information;
    nnpfs_path_info pathinfo;
} nnpfs_lookup_args;

#define NNPFS_LOOKUP_GETLINK  0x1 /* need last symlink node? */
#define NNPFS_LOOKUP_GETDIR   0x2 /* open target directory */
#define NNPFS_LOOKUP_CREATE   0x4 /* create if entry doesn't exist */
#define NNPFS_LOOKUP_TAIL     0x8 /* we're at the last component */

/*
 *
 */

struct nnpfs_link {
    int			flags;
#define	NNPFS_LINK_NOT_FROM_ZONE				(0x00000001)
#define	NNPFS_LINK_RPC				        (0x00000002)

    KEVENT		event;
    XLIST_ENTRY(nnpfs_link) link;
    struct nnpfs_message_header *message;
    u_int 		error_or_size; /* error on sleepq and size on */
};

/*
 * CCB structure for NNPFS
 */

typedef struct nnpfs_ccb {
    LIST_ENTRY	    NextCCB;		/* Link of CCB's */
    struct nnpfs_node *node;		/* pointer to nnpfs_node */
    PFILE_OBJECT    FileObject;	        /* File Object */
    uint32_t	    ByteOffset;		/* Offset when in directory searches */
    UNICODE_STRING  SearchPattern;	/* Save search pattern i dir searches */
    uint32_t	    time;		/* User time */
    uint32_t	    flags;
    uint32_t        opentokens;

    nnpfs_cred     *cred;
    nnpfs_path_info   *pathinfo;          /* how this node was looked up */
} nnpfs_ccb;

#define	NNPFS_CCB_OPENED_FOR_SYNC_ACCESS			(0x00000002)
#define	NNPFS_CCB_OPENED_FOR_SEQ_ACCESS			(0x00000004)
#define	NNPFS_CCB_CLEANED					(0x00000008)
#define	NNPFS_CCB_ACCESSED				(0x00000010)
#define	NNPFS_CCB_MODIFIED				(0x00000020)
#define	NNPFS_CCB_ACCESS_TIME_SET				(0x00000040)
#define	NNPFS_CCB_MODIFY_TIME_SET				(0x00000080)
#define	NNPFS_CCB_CREATE_TIME_SET				(0x00000100)

#define	NNPFS_CCB_VOLUME_OPEN				(0x00001000)

#define	NNPFS_CCB_NOT_FROM_ZONE				(0x80000000)


/*
 * The nnpfs_node is really a FCB
 */

typedef 
struct nnpfs_node {
    FSRTL_COMMON_FCB_HEADER	fcb;
    SECTION_OBJECT_POINTERS	section_objects;
    ERESOURCE			MainResource;
    ERESOURCE			PagingIoResource;

    struct nnpfs_channel *chan;
    XLIST_ENTRY(nnpfs_node)       lru_entry; /* accounting */

    long	    refcount;	        /* -- on IRP_MJ_CLOSE free when == 0 */
    long	    handlecount;	/* -- on IRP_MJ_CLEANUP */

    uint32_t	    flags;		/* the state of the node */
    
    struct nnpfs_attr attr;		/* XXX attr */
    uint32_t 	    offset;             /* data available */
    uint32_t	    tokens;		/* tokens */
    
    SHARE_ACCESS    share_access;

    nnpfs_pag_t 	    id[NNPFS_MAXRIGHTS];
    u_char	    rights[NNPFS_MAXRIGHTS];
    u_char          anonrights;    

    nnpfs_handle 	    handle;
    HANDLE	    *data;		/* handle to cache node */
    FILE_OBJECT	    *backfile;		/* cache node file object */

    /* XXX pointer instead of copy? */
    nnpfs_cred      writemapper;       /* creds of the last write mmap */

    ETHREAD	    *lazy_writer;
} NNPFS_FCB, nnpfs_node;

/*
 * winnt-specific flags for nnpfs_node.flags
 * see global nnpfs/nnpfs_message.h for global ones
 */
   
#define NNPFS_FCB_IN_INIT		(0x00010000)
#define	NNPFS_FCB_IN_TEARDOWN		(0x00020000)
#define	NNPFS_FCB_DIRECTORY		(0x00040000)
#define	NNPFS_FCB_ROOT_DIRECTORY	(0x00080000)

#define	NNPFS_FCB_WRITE_THROUGH		(0x00100000)
#define	NNPFS_FCB_WRITEMAPPED		(0x00200000)
#define	NNPFS_FCB_DELETE_ON_CLOSE	(0x00400000)
#define	NNPFS_FCB_MODIFIED		(0x00800000)

#define	NNPFS_FCB_FASTIO_READING	(0x01000000)
#define	NNPFS_FCB_FASTIO_WRITING	(0x02000000)
#define	NNPFS_MAIN_RESOURCE_INITED	(0x04000000)
#define	NNPFS_PAGING_RESOURCE_INITIED	(0x08000000)

#define	NNPFS_FCB_DUMMY           	(0x10000000)
#define	NNPFS_FCB_EXECUTE		(0x20000000)
#define	NNPFS_FCB_NOT_FROM_ZONE		(0x40000000)

#define NNPFS_VALID_DATAHANDLE(n) ((n)->data != NULL)

#define DATA_FROM_XNODE(t) (t)->data 

/*
 *
 */

typedef struct nnpfs_channel {
    int32_t		magic;		/* magic */
    ERESOURCE		lock;	        /* global lock */
    PDRIVER_OBJECT	driver;	        /* created by I/O mgr*/
    PDEVICE_OBJECT	device;	        /* to be able to do IOCTL*/
    CACHE_MANAGER_CALLBACKS cc_callbacks; /* for callbacks fr. cachemgr */
    uint32_t		flags;		/* varius flags */
#define NNPFSCHAN_FLAGS_GLOBALLOCK 	0x01
#define NNPFSCHAN_FLAGS_OPEN		0x02
#define NNPFSCHAN_CHANNEL_WAITING		0x04

    /*
     *
     */

    int			init_event;
    int 		pending_count;
    KEVENT		pending_event; /* some msg is ready for completion */

    uint32_t		nsequence;

    KSEMAPHORE		message_sem; /* protecting messageq */
    XLIST_LISTHEAD(nnpfs_link) messageq; /* msgs waiting for completion */
    
    KSEMAPHORE		sleep_sem;   /* protecting sleepq */
    XLIST_LISTHEAD(nnpfs_link) sleepq; /* waiting for res from userland? */

    KEVENT		wake_event; /* channel has closed, abort waits */

    struct nnpfs_dnlc     *dnlc;        /* directory name lookup cache */

    /*
     * nnpfs_nodes
     */

    struct nnpfs_node	*root;
    XLIST_LISTHEAD(nnpfs_node)        nodes; /* accounting node list */
    FAST_MUTEX		NodeListMutex;

    /*
     * Zones for memory allocation.
     */

    FAST_MUTEX		ZoneAllocationMutex;
    ZONE_HEADER		CCBZoneHeader;
    void		*CCBZone;
    ZONE_HEADER		NodeZoneHeader;
    void		*NodeZone;
    ZONE_HEADER		LinkZoneHeader;
    void		*LinkZone;

    /* XXX FastIOPath and some other junk here */
    FAST_IO_DISPATCH    fastio_dispatch;
} nnpfs_channel;

extern struct nnpfs_channel NNPFSGlobalData;	/* global data for nnpfs driver */

/*
 *
 */

typedef struct NNPFS_VCB {
    ERESOURCE		VCBResource;
    LIST_ENTRY		NextVCB;
    VPB			*VPB;
    uint32_t		flags;
    uint32_t		OpenCount;
    LIST_ENTRY		NextFCB;	/* All FCB on the VCB */ 
    PDEVICE_OBJECT	device;		/* the device we are  */
    uint8_t		VolumePath;	/* The drive letter we are on */

    /* Supposedly used by CM */
    LARGE_INTEGER	AllocationSize;
    LARGE_INTEGER	FileSize;
    LARGE_INTEGER	ValidDataLength;
} NNPFS_VCB;

#define	NNPFS_VCB_FLAGS_VOLUME_MOUNTED	(0x00000001)
#define	NNPFS_VCB_FLAGS_VOLUME_LOCKED	(0x00000002)
#define	NNPFS_VCB_FLAGS_BEING_DISMOUNTED	(0x00000004)
#define	NNPFS_VCB_FLAGS_SHUTDOWN		(0x00000008)
#define	NNPFS_VCB_FLAGS_VOLUME_READ_ONLY	(0x00000010)
#define	NNPFS_VCB_FLAGS_VCB_INITIALIZED	(0x00000020)


#define NNPFS_MAX_SYMLINKS 17

#define NNPFS_PANIC_IDENTIFIER 0x47111147

#define	NNPFSPanic(arg1, arg2, arg3)					\
	(KeBugCheckEx(NNPFS_PANIC_IDENTIFIER, __LINE__, 			\
        (uint32_t)(arg1), (uint32_t)(arg2), (uint32_t)(arg3)))


#include <nnpfs_proto.h>
#include <nnpfs_ioctl.h>
#include <nnpfs_dev.h>
#include <nnpfs_node.h>

#define bcopy(s,d,l)	memcpy((d),(s),(l))
#define bzero(d,l)	memset((d),0,(l))

#define assert(expr) if (!(expr)) DbgBreakPoint()

#define htonl(x) ((x>>24) + \
		  (((x>>16) & 0xff)<< 8) + \
		  (((x>>8) & 0xff)<< 16) + \
		  ((x & 0xff)<< 24))

#define ntohl(x) htonl(x)

#define htons(x) (((x>>8) & 0xff) + \
		  ((x & 0xff)<< 8))

#define ntohs(x) htons(x)

#define ENOENT STATUS_NO_SUCH_FILE
#define EEXIST STATUS_OBJECT_NAME_EXISTS
#define ENOMEM STATUS_NO_MEMORY

#define NNPFS_FBUF_HANDLE HANDLE

#endif /* _NNPFS_NNPFS_LOCL_H */
