/*
 * Copyright (c) 2000, 2002, 2005-2006 Kungliga Tekniska Högskolan
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

#include <dummer.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <arla-pioctl.h>
#include <sha.h>

dummer_state state = DISCONNECTED;
int debug = 0;
struct nnpfs nnpfs_dev;
struct nnpfs *nnpfsp = &nnpfs_dev;

static int dummer_done = 0;

#define DUMMER_NFDS 10

typedef struct {
    struct nnpfs_node *node;
    unsigned writep;
} fhandle;
static fhandle open_nodes[DUMMER_NFDS];

static int
nnpfs_data_valid(struct nnpfs_node *node, uint32_t tok,
		 uint64_t offset, uint64_t end);

static struct nnpfs_node *
get_open_node(unsigned fdnum);

static int
start_socket(int port)
{
    int ret;
    struct sockaddr_in addr;
    memset((char *) &addr, 0, sizeof(addr));
    
    int listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_socket == -1) {
	printf("socket returned %d\n", errno);
	exit(1);
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(0x7f000001); /* 127.0.0.1 */
    addr.sin_port = htons(port);
    
    ret = bind(listen_socket, (struct sockaddr *) &addr, sizeof(addr));
    if (ret == -1) {
	printf("bind returned %d\n", errno);
	exit(1);
    }

    ret = listen(listen_socket, 1);
    if (ret != 0) {
	printf("listen returned %d\n", errno);
	exit(1);
    }

#if 1
    {
	struct linger linger;
	socklen_t len = sizeof(linger);
	/* ret = getsockopt(listen_socket, SOL_SOCKET, SO_LINGER, &linger, &len); */
	
	linger.l_onoff  = 1; /*on*/
	linger.l_linger = 0; /*timeout*/

	ret = setsockopt(listen_socket, SOL_SOCKET, SO_LINGER, &linger, len);
    }
#endif

    return listen_socket;
}

#if 0
/*
 * allocates a buffer and reads entire dir into it
 * caller must free buffer
 *
 * returns buffer or NULL on failure
 */
static void *
readdirdata(struct nnpfs_node *node, ssize_t *retlen)
{
    ssize_t nread;
    ssize_t len;
    char *buf;
    int fd;
    int ret = 0;

    if (!XA_VALID_SIZE(&node->attr)) {
	printf("readdirdata: no size!\n");
	return NULL;
    }

    /* XXX this is currently wrong, but probably large enough */
    len = node->attr.xa_size;

    buf = malloc(len);
    if (buf == NULL) {
	printf("readdirdata: no buf, got %d!\n", errno);
	return NULL;
    }

    fd = nnpfs_cache_open(node, 0, O_RDONLY);
    if (fd > 0) {
	nread = pread(fd, buf, len, 0);
	if (nread < 0)
	    ret = errno;
	else
	    *retlen = nread;
	
	close(fd);
    } else {
	ret = errno;
    }

    if (ret) {
	printf("readdirdata failed, got %d\n", ret);
	free(buf);
	buf = NULL;
    }

    return buf;
}

/*
 * print directory contents.
 *
 * returns 0 on success, true means retry
 */
static int
printdir(struct nnpfs_node *node)
{
    struct dirent *dp;
    char *p, *buf;
    ssize_t len;

    int ret = nnpfs_data_valid(node, NNPFS_DATA_R, 0, -1);
    if (ret)
	return ret;

    buf = (char *)readdirdata(node, &len);
    if (!buf)
	return 1; /* maybe better luck next time? */

    for (p = buf; p < buf + len; p += dp->d_reclen) {
	dp = (struct dirent *)p;
	printf("%s\n", dp->d_name);
    }

    free(buf);

    return 0;
}
#endif

static int
nnpfs_open_valid(struct nnpfs_node *node, uint32_t tok)
{
    struct nnpfs_message_open msg;
    
    printf("nnpfs_open_valid\n");

    /* nnpfs_handle_stale(node); */

    if (NNPFS_TOKEN_GOT(node, tok))
	return 0;
	
    msg.header.opcode = NNPFS_MSG_OPEN;
    msg.cred.uid = 0;
    msg.cred.pag = 0;
    msg.handle = node->handle;
    msg.tokens = tok;
    
    nnpfs_message_rpc(&msg.header, sizeof(msg));
    return 1;
}

static int
nnpfs_attr_valid(struct nnpfs_node *node, uint32_t tok)
{
    struct nnpfs_message_getattr msg;

    printf("nnpfs_attr_valid\n");

    if (NNPFS_TOKEN_GOT(node, tok)) /*  && nnpfs_has_pag(node, pag) */
	return 0;
    
    msg.header.opcode = NNPFS_MSG_GETATTR;
    msg.cred.uid = 0;
    msg.cred.pag = 0;
    msg.handle = node->handle;
    
    nnpfs_message_rpc(&msg.header, sizeof(msg));
    return 1;
}

/*
 * find first block in given range with validity according to 'validp'
 *
 * returns offset of first such block, or NNPFS_NO_OFFSET if none
 */

static uint64_t
find_first_block(struct nnpfs_node *node, uint64_t offset,
		 uint64_t end, int validp)
{
    uint64_t off;
    
    if (nnpfs_block_empty(&node->data)
	|| offset >= node->attr.xa_size)
	return NNPFS_NO_OFFSET;

    /* get some batch search perhaps? */

    assert(nnpfs_offset(offset) == offset);

    if (end > node->attr.xa_size)
	end = node->attr.xa_size;
	
    for (off = offset; off < end; off += nnpfs_blocksize) {
	int validity = nnpfs_node_block_valid_p(node, off);
	if (validp) {
	    if (validity)
		return off;
	} else {
	    if (!validity)
		return off;
	}
    }

    return NNPFS_NO_OFFSET;
}

/*
 * send a getdata message
 */
static void
do_getdata(struct nnpfs_node *node, uint32_t tok, uint64_t offset, uint64_t end)
{
    struct nnpfs_message_getdata msg;
    
    msg.header.opcode = NNPFS_MSG_GETDATA;
    msg.handle = node->handle;
    msg.tokens = tok;
    msg.offset = offset;
    msg.len = end - offset;
    msg.cred.uid = 0;
    msg.cred.pag = 0;
    
    nnpfs_message_rpc(&msg.header, sizeof(msg));
}

/*
 * get data for node, from offset and end bytes, or until end of
 * file if length is 0
 *
 * returns 0 on success, true means retry
 */
static int
nnpfs_data_valid(struct nnpfs_node *node, uint32_t tok,
		 uint64_t offset, uint64_t end)
{
    uint64_t off;

    /* XXX need valid attributes */

    if (node->attr.xa_type == NNPFS_FILE_DIR) {
	end = 1; /* hack, entire dir goes in 'first block' */
    } else {
	if (end > node->attr.xa_size && (tok & NNPFS_DATA_W) == 0)
	    end = node->attr.xa_size;
    }
    
    /* use find_first_block() ? */
    for (off = offset; off < end; off += nnpfs_blocksize) {
	if (!nnpfs_node_block_valid_p(node, off)) {
	    
	    if (off >= node->attr.xa_size) {
 		/* write beyond length */
 		nnpfs_node_block_create(node, off);
		continue;
 	    }
 	    
	    /*
	     * XXX this triggers unnecessarily many installdata msgs
	     * on reverse sequential reads
	     */
	    
 	    do_getdata(node, tok, off, end);
 	    return 1; /* please call again */
	}
    }
    
    if (!NNPFS_TOKEN_GOT(node, tok)) {
	do_getdata(node, tok, offset, offset + 1);
	return 1; /* please call again */
    }
    
    return 0;
}

/*
 * allocates a buffer and reads 'length' bytes at 'offset' into it.
 * caller must free buffer
 *
 * adapted from arlad/abuf.c: abuf_populate()
 *
 * returns buffer or NULL on failure
 */
static void *
readfiledata(struct nnpfs_node *node, uint64_t offset,
	     uint64_t end, ssize_t *retlen)
{
    uint64_t block_off;
    ssize_t nread;
    ssize_t len = end - offset;
    off_t off = offset;
    char *buf;
    int fd = 0;
    int ret = 0;

    buf = malloc(len);
    if (buf == NULL) {
	printf("readfiledata: no buf, got %d!\n", errno);
	return NULL;
    }

    while (len > 0) {
	block_off = nnpfs_offset(off);
	off_t left = nnpfs_blocksize - (off - block_off);
	off_t r_len = MIN(len, left);

	if ((fd != 0 && close(fd) != 0)
	    || (fd = nnpfs_cache_open(node, block_off, O_RDONLY)) < 0) {
	    ret = errno;
	    fd = 0;
	    break;
	}
	
	nread = pread(fd, buf + off - offset, r_len, off - block_off);
	if (nread != r_len) {
	    ret = errno;
	    if (!ret)
		ret = EINVAL; /* we don't like EOF today */
	    break;
	}

	len -= nread;
	off += nread;
    }

    if (ret) {
	printf("readfiledata failed, got %d\n", ret);
	free(buf);
	buf = NULL;
    } else {
	*retlen = off - offset;
    }

    if (fd)
	close(fd);

    return buf;
}

/*
 * writes 'length' bytes from 'buf' into 'node' at 'offset'.
 *
 * adapted from arlad/abuf.c: abuf_populate()
 */
static void
writefiledata(struct nnpfs_node *node, const char *buf,
	      uint64_t length, uint64_t offset)
{
    uint64_t block_off;
    ssize_t nbytes;
    ssize_t len = length;
    off_t off = offset;
    int fd = 0;
    int ret = 0;

    while (len > 0) {
	block_off = nnpfs_offset(off);
	off_t left = nnpfs_blocksize - (off - block_off);
	off_t w_len = MIN(len, left);

	if ((fd != 0 && close(fd) != 0)
	    || (fd = nnpfs_cache_open(node, block_off, O_WRONLY)) < 0) {
	    ret = errno;
	    fd = 0;
	    break;
	}
	
	nbytes = pwrite(fd, buf + off - offset, w_len, off - block_off);
	if (nbytes != w_len) {
	    ret = errno;
	    break;
	}

	len -= nbytes;
	off += nbytes;
    }

    if (fd)
	close(fd);

    node->flags |= NNPFS_DATA_DIRTY;
    
    assert(!ret);
    
    if (ret == 0 && node->attr.xa_size < offset + length)
	XA_SET_SIZE(&node->attr, offset + length);
    printf("wrote %llu @%llu, length now %llu\n",
	   length, offset, node->attr.xa_size);
}

#if 0
/*
 * allocates a buffer and reads entire file into it
 * caller must free buffer
 *
 * returns buffer or NULL on failure
 */
static void *
readfiledata_all(struct nnpfs_node *node, ssize_t *retlen)
{
    if (!XA_VALID_SIZE(&node->attr)) {
	printf("readfiledata_all: no size!\n");
	return NULL;
    }

    return readfiledata(node, 0, node->attr.xa_size, retlen);
}

/*
 * print file contents.
 *
 * returns 0 on success, true means retry
 */
static int
printdata(struct nnpfs_node *node)
{
    char *buf;
    ssize_t len;
    
    int ret = nnpfs_data_valid(node, NNPFS_DATA_R, 0, -1);
    if (ret)
	return ret;

    buf = (char *)readfiledata_all(node, &len);
    if (!buf)
	return 1; /* maybe better luck next time? */

    buf[len] = '\0';
    printf("----------\n%s\n----------\n", buf);

    free(buf);
    return 0;
}

/*
 * print last few bytes of file contents.
 *
 * returns 0 on success, true means retry
 */
static int
printdata_tail(struct nnpfs_node *node)
{
    char *buf;
    uint64_t len = node->attr.xa_size; /* XXX */
    uint64_t off = nnpfs_offset(len);
    ssize_t retlen;
    int ret;
    
    if (off == len)
	off -= nnpfs_blocksize;

    if (off < 0)
	off = 0;

    ret = nnpfs_data_valid(node, NNPFS_DATA_R, off, len);
    if (ret)
	return ret;

    buf = (char *)readfiledata(node, off, len, &retlen);
    if (!buf)
	return 1; /* maybe better luck next time? */

    buf[retlen] = '\0';
    printf("----------\n%s\n----------\n", buf);

    free(buf);
    return 0;
}
#endif

typedef struct {
    char str[SHA_DIGEST_LENGTH * 2 + 8]; /* give or take */
} sha_checkstr;

/*
 * get a checksum of 'len' bytes of 'data' and convert to hex string
 * in 'cs'
 *
 */

static void
checksum(const void *data, size_t len, sha_checkstr *cs)
{
    SHA_CTX ctx;
    unsigned char res[SHA_DIGEST_LENGTH];
    int i;

    SHA1_Init(&ctx);
    SHA1_Update(&ctx, data, len);
    SHA1_Final(res, &ctx);

    for (i = 0; i < SHA_DIGEST_LENGTH; i ++) {
	int offset = 2 * i;
	snprintf(cs->str + offset, sizeof(cs->str) - offset,
		 "%02x", res[i]);
    }
}


/*
 * check data in given range of node agains the reference checksum
 *
 * returns 0 on success, true means retry
 */
static int
test_read(struct nnpfs_node *node,
	  uint64_t offset, uint64_t length,
	  sha_checkstr *reference_cs, int retval)
{
    char *buf;
    uint64_t off = nnpfs_offset(offset);
    uint64_t end = offset + length;
    sha_checkstr cs;
    ssize_t retlen;
    int ret;

    ret = nnpfs_data_valid(node, NNPFS_DATA_R, off, end);
    if (ret)
	return ret;

    buf = (char *)readfiledata(node, offset, end, &retlen);

    if (retval && !buf)
	return 0; /* failure is expected */
    
    assert(buf);
    assert(retlen == length);

    checksum(buf, retlen, &cs);

    ret = strcmp(cs.str, reference_cs->str);
    printf("(%llx, %llx): %s: ref %s, real %s\n",
	   offset, end, ret ? "BAD" : "OK!",
	   reference_cs->str, cs.str);

    if (retval)
	assert(ret);
    else
	assert(ret == 0);

    free(buf);
    return 0;
}

/*
 *
 */

static void
do_pioctl(uint32_t opcode, 
	  struct arlaViceIoctl *vice_ioctl, struct nnpfs_node *node)
{
    struct nnpfs_message_pioctl msg;

    msg.header.opcode = NNPFS_MSG_PIOCTL;
    msg.header.size = sizeof(msg);
    msg.opcode = opcode;

    msg.insize = vice_ioctl->in_size;
    msg.outsize = vice_ioctl->out_size;
    msg.handle = node->handle;
    msg.cred.uid = 0; /* XXX */ 
    msg.cred.pag = 0; /* XXX */ 

    nnpfs_message_rpc(&msg.header, sizeof(msg)); 
}

/*
 *
 */

static int
do_flushnode(struct nnpfs_node *node)
{
    struct arlaViceIoctl a_params;
    static int done = 0;

    if (done) {
	done = 0;
	return 0;
    }

    a_params.in_size  = 0;
    a_params.out_size = 0;
    a_params.in       = NULL;
    a_params.out      = NULL;

    do_pioctl(ARLA_VIOCFLUSH, &a_params, node);
    done = 1;
    return 1;
}

static void
do_setattr(struct nnpfs_node *xn)
{
    struct nnpfs_message_putattr msg;
    
    printf("do_setattr\n");
    msg.header.opcode = NNPFS_MSG_PUTATTR;
    msg.cred.uid = 0;
    msg.cred.pag = 0;
    msg.handle = xn->handle;
    memcpy(&msg.attr, &xn->attr, sizeof(msg.attr));

    nnpfs_message_rpc(&msg.header, sizeof(msg));
}

/*
 * infrastructure for truncate handling
 *
 * arlad takes care of everything within its state, we just need to
 * take care about our part. That includes forgetting all about any
 * blocks beyond the new length, and making sure any blocks that arlad
 * doesn't know about are properly updated.
 *
 * the trouble here is that we don't know what blocks arlad is aware
 * of, so we handle everything we know just to be on the safe
 * side. Hopefully we don't run into trouble when arlad does the very
 * same for the very same nodes in parallel...
 */

static void
truncate_callback(struct nnpfs_cache_handle *handle,
		  uint64_t offset, void *data)
{
    uint64_t *length = (uint64_t *)data;
    
    if (offset >= *length)
	nnpfs_block_set_have(handle, offset, 0);
}

static void
truncate_previous_last_block(struct nnpfs_node *node,
			     uint64_t old_offset, uint64_t length)
{
    uint64_t new_offset = nnpfs_offset(length);
    uint64_t blocklen;

    int fd = nnpfs_cache_open(node, old_offset, O_WRONLY);
    if (fd < 0) {
	printf("do_truncate: "
	       "open failed at offset 0x%" PRIX64 "\n", old_offset);
	assert(0);
	return;
    }
    
    if (new_offset == old_offset)
	blocklen = length - new_offset;
    else
	blocklen = nnpfs_blocksize;

    if (ftruncate(fd, blocklen)) {
	int ret = errno;
	printf("do_truncate: "
	       "truncate failed at offset 0x%" PRIX64 ": %d\n", old_offset, ret);
	assert(0);
    }
    
    close(fd);
}

/*
 *
 */

static int
do_truncate(struct nnpfs_node *node, uint64_t length)
{
    static uint64_t old_length;
    static int done = 0;

    if (done) {
	done = 0;
	if (!wakeup_error) {
	    nnpfs_block_foreach(&node->data, truncate_callback, &length);
	    
	    /*
	     * when extending dirty nodes, arlad may not know about
	     * the previously last block, and if so cannot adjust its
	     * size. So we do it here.
	     */

	    if (node->flags & NNPFS_DATA_DIRTY) {
		uint64_t old_offset = nnpfs_offset(old_length);
		if (nnpfs_node_block_valid_p(node, old_offset)) 
		    truncate_previous_last_block(node, old_offset, length);
	    }
	}
    } else {
	old_length = node->attr.xa_size;
	printf("truncate: len %lld -> %lld\n", old_length, length);
	XA_SET_SIZE(&node->attr, length);
	do_setattr(node);
	done = 1;
    }
    return done;
}

/*
 *
 */
static void
do_getroot(void) 
{
    struct nnpfs_message_getroot msg;
 
    printf("do_getroot\n");

    msg.header.opcode = NNPFS_MSG_GETROOT;
    msg.cred.uid = 0;
    msg.cred.pag = 0;
    
    nnpfs_message_rpc(&msg.header, sizeof(msg));
}

/*
 *
 */

static void
do_getnode(struct nnpfs_node *dir, const char *name)
{
    struct nnpfs_message_getnode msg;

    msg.header.opcode = NNPFS_MSG_GETNODE;
    msg.parent_handle = dir->handle;
    msg.cred.uid = 0;
    msg.cred.pag = 0;
    strncpy(msg.name, name, NNPFS_MAX_NAME);
    
    nnpfs_message_rpc(&msg.header, sizeof(msg));
}

static struct nnpfs_node *
lookup(struct nnpfs_node *dir, const char *name)
{
    struct nnpfs_node *node = nnpfs_dnlc_lookup(dir, name);
    if (node)
	return node;

    do_getnode(dir, name);
    return NULL;
}

static struct nnpfs_node *lookup_node = NULL;
static char *lookup_path = NULL;
static char *lookup_name = NULL;
static int lookup_in_progress = 0;

static struct nnpfs_node *
lookup_path_int(void)
{
    while (1) {
	if (lookup_name) {
	    struct nnpfs_node *node = lookup(lookup_node, lookup_name);
	    if (!node)
		return NULL;
	    
	    lookup_name = NULL;
	    lookup_node = node;
	}
	
	if (lookup_path) {
	    char *first = strchr(lookup_path, '/');
	    lookup_name = lookup_path;
	    if (first) {
		*first = '\0';
		lookup_path = first + 1;
	    } else {
		/* last component */
		lookup_path = NULL;
	    }
	}
	
	if (!lookup_name && !lookup_path) {
	    lookup_in_progress = 0;
	    return lookup_node;
	}
    }

    return (struct nnpfs_node *)4711;
}

/*
 * path relative root -> node
 *
 * no trailing slashes, please
 *
 * no symlinks for now
 */
static struct nnpfs_node *
pathlookup(const char *path)
{
    if (!nnpfsp->root) {
	do_getroot();
	return NULL;
    }

    if (lookup_in_progress == 0) {
	static char pathbuf[1024]; /* XXX */
	lookup_node = nnpfsp->root;
	strcpy(pathbuf, path);
	lookup_path = pathbuf;
	lookup_in_progress = 1;
    }

    return lookup_path_int();
}

/*
 * send PUTDATA for a block/range
 */

static void
do_putdata(struct nnpfs_node *xn, uint64_t off, uint64_t len)
{
    struct nnpfs_message_putdata msg;

    printf("putdata @%llx, len %llx\n", off, len);

    msg.header.opcode = NNPFS_MSG_PUTDATA;
    msg.cred.uid = 0;
    msg.cred.pag = 0;
    msg.handle = xn->handle;
    msg.flag = NNPFS_WRITE;
    msg.offset = off;
    msg.len = len;

    XA_CLEAR(&msg.attr);

    XA_SET_SIZE(&msg.attr, xn->attr.xa_size);

    /* XA_SET_MTIME(&msg.attr, xn->attr.xa_mtime); */

    nnpfs_message_rpc(&msg.header, sizeof(msg));
}

/*
 * store data for entire node
 *
 * returns 0 on success, true means retry
 */
static int
do_fsync(struct nnpfs_node *node)
{
    static uint64_t off = 0;
    uint64_t len = node->attr.xa_size; /* XXX */
    uint64_t end;

    if ((node->flags & NNPFS_DATA_DIRTY) == 0)
	return 0;

    /* get first valid block */
    off = find_first_block(node, off, len, TRUE);
    if (off >= len || off == NNPFS_NO_OFFSET) {
	node->flags &= ~NNPFS_DATA_DIRTY;
	off = 0;

	return 0; /* no more blocks installed */
    }

    /* find the end of this range of valid blocks */
    end = find_first_block(node, off + nnpfs_blocksize, len, FALSE);
    if (end > len || off == NNPFS_NO_OFFSET)
	end = len;
    
    do_putdata(node, off, end - off);

    if (end >= len) {
	node->flags &= ~NNPFS_DATA_DIRTY;
	off = 0;
    } else {
	off = end;
    }

    return 1; /* wait for reply */
}

/*
 * check data in given range of node agains the reference checksum
 *
 * returns 0 on success, true means retry
 */
static int
do_copy(struct nnpfs_node *src, uint64_t soffset,
	struct nnpfs_node *dst, uint64_t doffset,
	uint64_t length)
{
    char *buf;
    uint64_t soff = nnpfs_offset(soffset);
    uint64_t doff = nnpfs_offset(doffset);
    uint64_t send = soffset + length;
    uint64_t dend = doffset + length;
    ssize_t retlen;
    int ret;

    ret = nnpfs_data_valid(src, NNPFS_DATA_R, soff, send);
    if (ret)
	return ret;

    ret = nnpfs_data_valid(dst, NNPFS_DATA_W, doff, dend);
    if (ret)
	return ret;

    assert(dst->attr.xa_size >= doffset);

    buf = (char *)readfiledata(src, soffset, send, &retlen);
    if (!buf)
	return 1; /* maybe better luck next time? */

    assert(retlen == length);

    writefiledata(dst, buf, length, doffset);

    free(buf);

    return 0;
}

static char *
unafsify(char *path)
{
    if (!strncmp("/afs/", path, 5))
	path += 5;
    return path;
}

/*
 * open path with mode, store as open node #fdnum
 */

static int
do_open(char *path, unsigned writep, unsigned fdnum)
{
    struct nnpfs_node *node;
    int ret;

    assert(fdnum < DUMMER_NFDS);
    assert(open_nodes[fdnum].node == NULL);

    node = pathlookup(path);
    if (!node)
	return 1;

    if (writep)
	ret = nnpfs_open_valid(node, NNPFS_OPEN_NW);
    else
	ret = nnpfs_open_valid(node, NNPFS_OPEN_NR);

    if (ret)
	return ret;

    open_nodes[fdnum].node = node;
    open_nodes[fdnum].writep = writep;

    if (writep)
	node->writers++;
    else
	node->readers++;

    return ret;
}

static struct nnpfs_node *
get_open_node(unsigned fdnum)
{
    struct nnpfs_node *node;

    assert(fdnum < DUMMER_NFDS);
    node = open_nodes[fdnum].node;
    assert(node);

    return node;
}

/*
 *
 */

static void
inactive(struct nnpfs_node *node)
{
    if (!NNPFS_TOKEN_GOT_ANY(node, NNPFS_ATTR_R | NNPFS_ATTR_W)
	|| (node->flags & NNPFS_STALE) == NNPFS_STALE)
	nnpfs_reclaim(node);
}

/*
 * close the open node #fdnum
 */

static int
do_close(unsigned fdnum)
{
    struct nnpfs_node *node = get_open_node(fdnum);
    unsigned writep = open_nodes[fdnum].writep;
    int ret;

    if (writep && node->writers == 1) {
	if (node->flags & NNPFS_DATA_DIRTY) {
	    ret = do_fsync(node);
	    if (ret)
		return ret;

	}
    }

    if (writep)
	node->writers--;
    else
	node->readers--;

    assert(node->writers >= 0);
    assert(node->readers >= 0);
    
    open_nodes[fdnum].node = NULL;
    open_nodes[fdnum].writep = 0;

    /* check for STALE */
    if (!node->writers && !node->readers)
	inactive(node);

    return 0;
}

#define CMD_BUFSIZE 2048

/*
 * try to execute some tests.
 *
 * return true if we expect some kind of reply from daemon, zero if we
 * should be called again immediately
 */

static int
do_processing(void) 
{
    static char command[CMD_BUFSIZE];
    static int have_command = 0;
    int ret;

    if (!have_command) {
	ret = scanf("%2045[^\n]\n", command); /* XXX CMD_BUFSIZE-3 */
	if (ret != 1) {
	    printf("no command.\n");
	    return 1; /* good way to hang */
	}

	have_command = 1;
    }

    if (have_command) {

	/* 
	 * open <path> <writep> <fdnum>
	 * read <fdnum> <offset> <len> <hash> <retval>
	 * copy <srcfd> <srcoffset> <dstfd> <dstoffset> <len>
	 * close <fdnum>
	 * flush <path>
	 * truncate <fdnum> <len>
	 * fsync <fdnum>
	 * assertlen <fdnum> <len>
	 * assertnodata <fdnum> <offset> <len>
	 */
	{
	    uint64_t offset, length;
	    unsigned fdnum;
	    sha_checkstr cs;
	    int retval;

	    ret = sscanf(command,
			 "read %u %llu %llu %48[0-9a-f] %d", /* XXX sizeof(sha_checkstr) */
			 &fdnum, &offset, &length, cs.str, &retval);
	    if (ret == 5) {
		ret = test_read(get_open_node(fdnum), offset, length, &cs, retval);
		if (ret)
		    return ret; /* wait for reply */
		
		have_command = 0; /* previous one taken care of */
		return 0; /* get next one */
	    }
	}

	{
	    uint64_t soffset, doffset, length;
	    unsigned srcfd, dstfd;
	    
	    ret = sscanf(command,
			 "copy %u %llu %u %llu %llu",
			 &srcfd, &soffset, &dstfd, &doffset, &length);
	    if (ret == 5) {
		ret = do_copy(get_open_node(srcfd), soffset, 
			      get_open_node(dstfd), doffset,
			      length);
		if (ret)
		    return ret; /* wait for reply */
		
		have_command = 0; /* previous one taken care of */
		return 0; /* get next one */
	    }
	}

	{
	    char buf[1024];

	    ret = sscanf(command, "flush %1023s", buf);
	    if (ret == 1) {
		char *path = unafsify(buf);
		struct nnpfs_node *node = pathlookup(path);
		if (!node)
		    return 1;

		ret = do_flushnode(node);
		if (ret)
		    return ret; /* wait for reply */
		
		have_command = 0; /* previous one taken care of */
		return 0; /* get next one */
	    }
	}

	{
	    char buf[1024];
	    unsigned writep, fdnum;
	    char *path = buf;

	    ret = sscanf(command,
			 "open %1023s %u %u",
			 buf, &writep, &fdnum);
	    if (ret == 3) {
		path = unafsify(buf);
		ret = do_open(path, writep, fdnum);
		if (ret)
		    return ret; /* wait for reply */
		
		have_command = 0; /* previous one taken care of */
		return 0; /* get next one */
	    }
	}

	{
	    unsigned fdnum;

	    ret = sscanf(command, "close %u", &fdnum);
	    if (ret == 1) {
		ret = do_close(fdnum);
		if (ret)
		    return ret; /* wait for reply */
		
		have_command = 0; /* previous one taken care of */
		return 0; /* get next one */
	    }
	}

	{
	    uint64_t length;
	    unsigned fdnum;

	    ret = sscanf(command, "truncate %u %llu", &fdnum, &length);
	    if (ret == 2) {
		ret = do_truncate(get_open_node(fdnum), length);
		if (ret)
		    return ret; /* wait for reply */
		
		have_command = 0; /* previous one taken care of */
		return 0; /* get next one */
	    }
	}

	{
	    unsigned fdnum;

	    ret = sscanf(command, "fsync %u", &fdnum);
	    if (ret == 1) {
		ret = do_fsync(get_open_node(fdnum));
		if (ret)
		    return ret; /* wait for reply */
		
		have_command = 0; /* previous one taken care of */
		return 0; /* get next one */
	    }
	}

	{
	    uint64_t length;
	    unsigned fdnum;

	    ret = sscanf(command, "assertlen %u %llu", &fdnum, &length);
	    if (ret == 2) {
		struct nnpfs_node *node = get_open_node(fdnum);
		assert(node);

		ret = nnpfs_attr_valid(node, NNPFS_ATTR_R);
		if (ret)
		    return ret;
		
		assert(node->attr.xa_size == length);

		have_command = 0; /* previous one taken care of */
		return 0; /* get next one */
	    }
	}

	{
	    uint64_t offset, length, block;
	    unsigned fdnum;

	    ret = sscanf(command, "assertnodata %u %llu %llu",
			 &fdnum, &offset, &length);
	    if (ret == 3) {
		struct nnpfs_node *node = get_open_node(fdnum);
		assert(node);

		ret = nnpfs_attr_valid(node, NNPFS_ATTR_R);
		if (ret)
		    return ret;
		
		block = find_first_block(node, offset, length, TRUE);
		assert(block == NNPFS_NO_OFFSET);
		
		have_command = 0; /* previous one taken care of */
		return 0; /* get next one */
	    }
	}

	printf("bad command: %s\n", command);
	assert(0);
	have_command = 0;
    }

    return 0;
}

/*
 * Read incoming message batch, handle appropriately
 */
static int
read_messages(const char *buf, int cnt)
{
    const char *p;
    int ret, error = 0;
    struct nnpfs_message_header *msg_buf;

    p = buf;
    while (cnt > 0) {
	msg_buf = (struct nnpfs_message_header *)p;
	if (cnt < msg_buf->size) {
	    printf("badly formed message\n");
	    error = EINVAL;
	    break;
	}
	ret = nnpfs_message_receive(msg_buf, msg_buf->size);
	if (ret)
	    error = ret;

	p += msg_buf->size;
	cnt -= msg_buf->size;
    }

    return error;
}

static void
talk(int arla_socket)
{
    fd_set rfd;
    int ret;
    char msg[NNPFS_MAX_MSG_SIZE];

    while (!dummer_done) {
	FD_ZERO(&rfd);
	FD_SET(arla_socket, &rfd);
	
	/* printf("talk selecting\n"); */
	ret = select(arla_socket + 1, &rfd, NULL, NULL, NULL);
	if (ret == -1) {
	    printf("select returned %d\n", errno);
	    return;
	}

	if (FD_ISSET(arla_socket, &rfd)) {
	    u_long len, left;
	    char out_len[4];
	    char *m = msg;
	    unsigned long *p = (unsigned long *)msg;

	    ret = recv(arla_socket, out_len, sizeof(out_len), 0);
	    if (ret == -1) {
		printf("recv (out_len) returned %d\n", errno);
		return;
	    }

	    memcpy(&len, out_len, sizeof(len));
	    len = ntohl(len);

	    if (len > NNPFS_MAX_MSG_SIZE) {
		printf("recv a too large message (%lu)\n", len);
		return;
	    }
	    /* printf("recv len (%lu)\n", len);	*/
	    left = len;
	    while (left > 0) {
		ret = recv(arla_socket, m, left, 0);
		if (ret == left)
		    break;
		if (ret == -1) {
		    printf("recv (msg) returned %d\n", errno);
		    return;
		} 
		m += ret;
		left -= ret;
	    }

	    if (debug) {
		printf ("message from arlad, size %4lx (%8lx %8lx %8lx)\n",
			len, p[0], p[1], p[2]);
		fflush(stdout);
	    }
	    
	    read_messages(msg, len);
	    
	    if (state == READY
		|| (state == SLEEPING && wakeup_seq == sleep_seq)) {
		sleep_seq = NOSEQ;
		state = READY;
		while (!do_processing())
		    ; /* loop */
	    }

	} else {
	    printf ("select behaves strangely\n");
	}
    }
}

static void
accept_loop(int listen_socket)
{
    struct sockaddr_in addr;
    socklen_t size = sizeof(addr);

    while (!dummer_done) {
	int arla_socket = accept(listen_socket, (struct sockaddr *)&addr, &size);
	if (arla_socket == -1) {
	    printf ("accept returned %d\n", errno);
	    exit (1);
	}
	
	if (debug)
	    printf ("got a connection from: %s\n", inet_ntoa(addr.sin_addr));
	
	state = CONNECTED;

	nnpfsp->fd = arla_socket;
	talk(arla_socket);
	nnpfsp->fd = -1;

	state = DISCONNECTED;

	close(arla_socket);
    }
}


int
main (int argc, char **argv)
{
    int listen_socket;

    if (argc != 2) {
	printf("usage: %s <cachedir>\n", argv[0]);
	exit(1);
    }

    if (chdir(argv[1])) {
	perror("chdir");
	exit(1);
    }

    debug = 0;

    memset(nnpfsp, 0, sizeof(*nnpfsp));

    nnpfs_init_head(&nnpfsp->nodehead);

    listen_socket = start_socket(NNPFS_PORT);
    
    accept_loop(listen_socket);

    close(listen_socket);

    return 0;
}
