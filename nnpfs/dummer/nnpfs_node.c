/*
 * Copyright (c) 2002 - 2006, Stockholms Universitet
 * (Stockholm University, Stockholm Sweden)
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
 * 3. Neither the name of the university nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <dummer.h>
#include <inttypes.h>

/* RCSID("$Id: nnpfs_node.c,v 1.2 2006/10/24 16:33:27 tol Exp $"); */

#define nnpfs_hash(node) \
  (((node)->a+(node)->b+(node)->c+(node)->d) % XN_HASHSIZE)


/*
 * open indicated cache block file. needs to be closed by caller.
 */

int
nnpfs_cache_open_id(uint32_t id, uint64_t blockindex, int flags, int dirp)
{
    static char cachename[NNPFS_MAX_NAME];
    int fd;
    int ret;

    if (dirp)
	ret = snprintf(cachename, sizeof(cachename) - 1,
		       NNPFS_CACHE_DIR_PATH,
		       id / 0x100, id % 0x100);
    else
	ret = snprintf(cachename, sizeof(cachename) - 1,
		       NNPFS_CACHE_FILE_PATH,
		       id / 0x100, id % 0x100,
		       (unsigned long long)blockindex);
    
    if (ret <= 0) {
	printf("cache_open: failed to get cache name\n");
	return -1;
    }

    fd = open(cachename, flags, S_IRUSR|S_IWUSR);
    if (fd < 0)
	printf("cache_open: open(%s) -> %d\n", cachename, errno);

    return fd;
}

/*
 * open indicated cache block file. needs to be closed by caller.
 */

int
nnpfs_cache_open(struct nnpfs_node *node, uint64_t offset, int flags)
{
    if (!nnpfs_node_block_valid_p(node, offset)) {
	printf("cache_open: block not valid\n");
	errno = ENOENT;
	return -1;
    }
    return nnpfs_cache_open_id(node->index, nnpfs_block_index(offset),
			       flags, nnpfs_dirp(node));
}

/*
 * Init the nnp node storage system
 */

void
nnpfs_init_head(struct nnpfs_nodelist_head *head)
{
    int i;

    for (i = 0; i < XN_HASHSIZE; i++)
	NNPQUEUE_INIT(&head->nh_nodelist[i]);
}

/*
 * find the node, identifed by `handlep', and put it in *node
 *
 * return 0, ENOENT, or EISDIR (for limbo nodes)
 */

int
nnpfs_node_find(nnpfs_handle *handlep, struct nnpfs_node **node)
{
    struct nh_node_list *h;
    struct nnpfs_node *nn;
    struct nnpfs_nodelist_head *head = &nnpfsp->nodehead;
    int ret = 0;

    h = &head->nh_nodelist[nnpfs_hash(handlep)];

    NNPQUEUE_FOREACH(nn, h, nn_hash) {
	if (nnpfs_handle_eq(handlep, &nn->handle))
	    break;
    }

    if (nn == NULL)
	ret = ENOENT;
    else if (nn->flags & NNPFS_LIMBO)
	ret = EISDIR;

    *node = nn;

    return ret;
}

/*
 * Remove the node `node' from the node storage system.
 */

void
nnpfs_remove_node(struct nnpfs_nodelist_head *head, struct nnpfs_node *node)
{
    struct nh_node_list *h;

    h = &head->nh_nodelist[nnpfs_hash(&node->handle)];
    NNPQUEUE_REMOVE(node, h, nn_hash);
}

/*
 * Add the node `node' from the node storage system.
 */

void
nnpfs_insert(struct nnpfs_nodelist_head *head, struct nnpfs_node *node)
{
    struct nh_node_list *h;

    h = &head->nh_nodelist[nnpfs_hash(&node->handle)];
    NNPQUEUE_INSERT_HEAD(h, node, nn_hash);
}

/*
 * Update `old_handlep' in the node list `head' to `new_handlep'.
 */

int
nnpfs_update_handle(nnpfs_handle *old_handlep, nnpfs_handle *new_handlep)
{
    struct nnpfs_node *node;
    int ret;

    ret = nnpfs_node_find(new_handlep, &node);
    if (ret != ENOENT)
	return EEXIST;

    ret = nnpfs_node_find(old_handlep, &node);
    if (ret)
	return ret;

    nnpfs_remove_node(&nnpfsp->nodehead, node);

    {
	struct nnpfs_node *node2;
	ret = nnpfs_node_find(old_handlep, &node2);
	if (ret != ENOENT)
	    printf("nnpfs_update_handle: (%d, %d, %d, %d) is still there",
		   old_handlep->a, old_handlep->b, old_handlep->c, old_handlep->d);
    }
    node->handle = *new_handlep;
    nnpfs_insert(&nnpfsp->nodehead, node);

    return 0;
}

/*
 * Create a new nnpfs_node
 *
 * prevent creation of duplicates?
*/

int
nnpfs_new_node(struct nnpfs_msg_node *node, struct nnpfs_node **xpp)
{
    struct nnpfs_node *result;
    int error;

    printf("nnpfs_new_node (%d,%d,%d,%d)\n",
	   node->handle.a, node->handle.b, node->handle.c, node->handle.d);

    /* Does not allow duplicates */
    error = nnpfs_node_find(&node->handle, &result);
    if (error == ENOENT) {
	result = malloc(sizeof(*result));
	/* if (result == NULL) */

	memset(result, 0, sizeof(*result));

	result->handle = node->handle;

	/* nnpfs_node_find(handle, &check); */
	nnpfs_insert(&nnpfsp->nodehead, result);

    } else if (error == EISDIR) {
	/* node is about to be deleted */
	printf("nnpfs_new_node: node deleted\n");
	return error;
    } else {
	/* Node is already cached */
    }

    result->tokens = node->tokens;
    if (result->writers == 0) /* XXX readers? */
	result->attr = node->attr;
    
    *xpp = result;

    return 0;
}

/*
 * free node.
 */
void  
nnpfs_free_node(struct nnpfs_node *node)
{
    printf("nnpfs_free_node(%lx) (%d,%d,%d,%d)\n", (unsigned long)node,
	   node->handle.a, node->handle.b, node->handle.c, node->handle.d);
    
    nnpfs_remove_node(&nnpfsp->nodehead, node);

    free(node);
}

int
nnpfs_reclaim(struct nnpfs_node *node)
{
    struct nnpfs_message_inactivenode msg;

    printf("nnpfs_reclaim(%lx) (%d,%d,%d,%d)\n", (unsigned long)node,
	   node->handle.a, node->handle.b, node->handle.c, node->handle.d);
    
    node->flags |= NNPFS_LIMBO;

    NNPFS_TOKEN_CLEAR(node,
		      ~0,
		      NNPFS_OPEN_MASK | NNPFS_ATTR_MASK |
		      NNPFS_DATA_MASK | NNPFS_LOCK_MASK);

    nnpfs_block_free(&node->data);
    nnpfs_dnlc_uncache(node);

    msg.header.opcode = NNPFS_MSG_INACTIVENODE;
    msg.handle = node->handle;
    msg.flag   = NNPFS_NOREFS | NNPFS_DELETE;
    nnpfs_message_send(&msg.header, sizeof(msg));

    return 0;
}



/**
 ** dnlc things
 **/

typedef struct nnpfs_dnlc_entry {
    struct nnpfs_handle dir;
    char name[NNPFS_MAX_NAME];
    struct nnpfs_node *node;
} nnpfs_dnlc_entry;

#define DNLC_SZ 13

static nnpfs_dnlc_entry dnlc[DNLC_SZ];
static int dnlc_index = 0;

void
nnpfs_dnlc_init(void)
{
    memset(dnlc, 0, sizeof(dnlc));
}

void
nnpfs_dnlc_shutdown(void)
{
}

static struct nnpfs_dnlc_entry *
nnpfs_dnlc_find_entry(struct nnpfs_node *dir, const char *name)
{
    int len = strlen(name);
    int i;

    for (i = 0; i < DNLC_SZ; i++) {
	nnpfs_dnlc_entry *e = &dnlc[i];
    
	if (nnpfs_handle_eq(&e->dir, &dir->handle)
	    && !strncmp(name, e->name, len))
	    return e;
    }

    return NULL;
}

/*
 *
 */

void
nnpfs_dnlc_enter(struct nnpfs_node *dir,
		 const char *name,
		 struct nnpfs_node *node)
{
    int len = strlen(name);
    nnpfs_dnlc_entry *e;

    if (len > NNPFS_MAX_NAME) {
	printf("nnpfs_dnlc_enter: name %s is too long!\n", name);
	return; /* XXX */
    }

    e = nnpfs_dnlc_find_entry(dir, name);
    if (e) {
	e->node = node;
	return;
    }

    e = &dnlc[dnlc_index++ % DNLC_SZ];
    e->dir = dir->handle;
    e->node = node;
    strncpy(e->name, name, len);

    return;
}

static void
nnpfs_dnlc_drop_entry(nnpfs_dnlc_entry *e)
{
    memset(e, 0, sizeof(*e));
}

static void
nnpfs_dnlc_drop_children(struct nnpfs_node *dir)
{
    nnpfs_dnlc_entry *e;
    int i;
    
    for (i = 0; i < DNLC_SZ; i++) {
	e = &dnlc[i];
	if (nnpfs_handle_eq(&e->dir, &dir->handle))
	    nnpfs_dnlc_drop_entry(e);
    }
}

/*
 * simply drop the node from cache
 */

static void
nnpfs_dnlc_drop(struct nnpfs_node *node)
{
    nnpfs_dnlc_entry *e;
    int i;

    for (i = 0; i < DNLC_SZ; i++) {
	e = &dnlc[i];
	if (e->node == node)
	    nnpfs_dnlc_drop_entry(e);
    }
}

/*
 * drop deleted node from cache, plus any children
 */

void
nnpfs_dnlc_uncache(struct nnpfs_node *node)
{
    nnpfs_dnlc_drop(node);
    if (node->attr.xa_type == NNPFS_FILE_DIR)
	nnpfs_dnlc_drop_children(node);
}

/*
 *
 */

struct nnpfs_node *
nnpfs_dnlc_lookup(struct nnpfs_node *dir, const char *name)
{
    nnpfs_dnlc_entry *e = nnpfs_dnlc_find_entry(dir, name);    
    if (e)
	return e->node;
    return NULL;
}


/*
 * return true if block at offset is present in cache
 */

int
nnpfs_node_block_valid_p(struct nnpfs_node *node, uint64_t offset)
{
    return nnpfs_block_have_p(&node->data, offset);
}

/*
 * mark block as present in cache
 */

void
nnpfs_node_block_setvalid(struct nnpfs_node *node, uint64_t offset)
{
    nnpfs_block_set_have(&node->data, offset, 1);
}

/*
 * create the indicated block and mark it as present in cache.
 *
 * intended for writes beyond EOF
 */

void
nnpfs_node_block_create(struct nnpfs_node *node, uint64_t offset)
{
    int fd;

    assert(!nnpfs_node_block_valid_p(node, offset));
    assert(!nnpfs_dirp(node));

    fd = nnpfs_cache_open_id(node->index, nnpfs_block_index(offset),
			     O_CREAT, nnpfs_dirp(node));
    assert(fd >= 0);
    close(fd);

    printf("created block at off 0x%llx\n", offset);

    nnpfs_node_block_setvalid(node, offset);
}
