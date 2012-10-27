#ifndef _nnpfs_h
#define _nnpfs_h

#include <nnpfs/nnpfs_common.h>
#include <nnpfs/nnpfs_node.h>

#include <sys/types.h>

/*
 * Filesystem struct.
 */
struct nnpfs {
  u_int status;		/* Inited, opened or mounted */
#define NNPFS_MOUNTED	0x1
  struct vfs *vfsp;
  struct nnpfs_node *root;
  u_int nnodes;

  struct nnpfs_node *nodes;		/* replace with hash table */
  int fd;
};

#define VFS_TO_NNPFS(v)      ((struct nnpfs *) ((v)->vfs_data))
#define NNPFS_TO_VFS(x)      ((x)->vfsp)

#define NNPFS_FROM_VNODE(vp) VFS_TO_NNPFS((vp)->v_vfsp)
#define NNPFS_FROM_XNODE(xp) NNPFS_FROM_VNODE(XNODE_TO_VNODE(xp))

extern struct nnpfs nnpfs[];

extern struct vnodeops nnpfs_vnodeops;

struct nnpfs_node *nnpfs_node_find _PARAMS((struct nnpfs *, struct nnpfs_handle *));
struct nnpfs_node *new_nnpfs_node _PARAMS((struct nnpfs *, struct nnpfs_msg_node *));
void free_nnpfs_node _PARAMS((struct nnpfs_node *));
void free_all_nnpfs_nodes _PARAMS((struct nnpfs *nnpfsp));

extern int 
nnpfs_dnlc_enter _PARAMS((struct vnode *, char *, struct vnode *));
extern struct vnode *
nnpfs_dnlc_lookup _PARAMS((struct vnode *, char *));
extern void nnpfs_dnlc_purge _PARAMS((void));

void
nnpfs_attr2vattr _PARAMS((const struct nnpfs_attr *xa, struct vattr *va, int clear_node));

void
vattr2nnpfs_attr _PARAMS((const struct vattr *va, struct nnpfs_attr *xa));

#endif /* _nnpfs_h */
