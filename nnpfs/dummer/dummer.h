#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <sys/types.h> 
#include <sys/socket.h> 
#include <sys/param.h> 
#include <netinet/in.h>
#include <nnpfs/nnpfs_message.h>
#include <nnpfs/nnpfs_queue.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <bool.h>

/*
 * some offset/block utilities needed by nnpfs_blocks.h 
 */

#define XN_HASHSIZE	17

NNPQUEUE_HEAD(nh_node_list, nnpfs_node);

struct nnpfs_nodelist_head {
    struct nh_node_list	nh_nodelist[XN_HASHSIZE];
};

struct nnpfs {
    struct nnpfs_node *root;
    struct nnpfs_nodelist_head nodehead;
    uint64_t blocksize;
    int fd;
};

extern struct nnpfs *nnpfsp;

#define nnpfs_blocksize     (nnpfsp->blocksize)


/* block handling routines */
#include <nnpfs/nnpfs_blocks.h>

/*
 * Keep track of basic state in dummy nnpfs
 */

typedef enum { DISCONNECTED, CONNECTED, READY, SLEEPING } dummer_state;

extern dummer_state state;

extern int debug;

extern int32_t sleep_seq;
extern int32_t wakeup_seq;
extern int32_t wakeup_error;

#define NOSEQ (-1)
#define NNPFS_PORT 5000

struct nnpfs_node {
    uint32_t index;
    struct nnpfs_cache_handle data;
    u_int flags;
    u_int tokens;
    int writers;
    int readers;
    nnpfs_handle handle;
    struct nnpfs_attr attr;
    NNPQUEUE_ENTRY(nnpfs_node) nn_hash;
};

#define nnpfs_dirp(node) ((node)->attr.xa_type == NNPFS_FILE_DIR)


void
nnpfs_dnlc_init(void);

void
nnpfs_dnlc_shutdown(void);

void
nnpfs_dnlc_enter(struct nnpfs_node *p, const char *name, struct nnpfs_node *c);

struct nnpfs_node *
nnpfs_dnlc_lookup(struct nnpfs_node *dir, const char *name);

void
nnpfs_dnlc_uncache(struct nnpfs_node *node);

int
nnpfs_message_rpc(struct nnpfs_message_header *message, u_int size);

int
nnpfs_message_send(struct nnpfs_message_header *message, u_int size);

int
nnpfs_message_receive(struct nnpfs_message_header *message,
		      u_int size);

int
nnpfs_cache_open(struct nnpfs_node *node, uint64_t offset, int flags);

int
nnpfs_cache_open_id(uint32_t id, uint64_t blockindex, int flags, int dirp);

void
nnpfs_init_head(struct nnpfs_nodelist_head *head);

int
nnpfs_new_node(struct nnpfs_msg_node *node, struct nnpfs_node **xpp);

int
nnpfs_node_find(nnpfs_handle *handlep, struct nnpfs_node **node);

void
nnpfs_remove_node(struct nnpfs_nodelist_head *head, struct nnpfs_node *node);

void
nnpfs_insert(struct nnpfs_nodelist_head *head, struct nnpfs_node *node);

int
nnpfs_update_handle(nnpfs_handle *old_handlep, nnpfs_handle *new_handlep);

void
nnpfs_free_node(struct nnpfs_node *node);

int
nnpfs_reclaim(struct nnpfs_node *node);

int
nnpfs_node_block_valid_p(struct nnpfs_node *node, uint64_t offset);

void
nnpfs_node_block_setvalid(struct nnpfs_node *node, uint64_t offset);

void
nnpfs_node_block_create(struct nnpfs_node *node, uint64_t offset);
