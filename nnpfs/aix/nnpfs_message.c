/*
 * Copyright (c) 1995 - 2000 Kungliga Tekniska H�gskolan
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

#include <nnpfs/nnpfs_locl.h>
#include <nnpfs/nnpfs_deb.h>
#include <nnpfs/nnpfs_fs.h>
#include <nnpfs/nnpfs_message.h>
#include <nnpfs/nnpfs_msg_locl.h>

RCSID("$Id: nnpfs_message.c,v 1.12 2002/09/07 10:44:33 lha Exp $");

int
nnpfs_message_installroot(int fd,
			struct nnpfs_message_installroot *message,
			u_int size)
{
  int error = 0;

  NNPFSDEB(XDEBMSG, ("nnpfs_message_installroot\n"));

  if (nnpfs[fd].root != 0)
    {
      printf("NNPFS PANIC Warning: nnpfs_message_installroot again\n");
      error = EBUSY;
    }
  else
    {
      nnpfs[fd].root = new_nnpfs_node(&nnpfs[fd], &message->node); /* VNOP_HOLD's */
      nnpfs[fd].root->vn.v_flag |= VROOT;
    }
  return error;
}

int
nnpfs_message_installnode(int fd,
			struct nnpfs_message_installnode *message,
			u_int size)
{
  int error = 0;
  struct nnpfs_node *n, *dp;

  dp = nnpfs_node_find(&nnpfs[fd], &message->parent_handle);
  if (dp)
    {
      n = new_nnpfs_node(&nnpfs[fd], &message->node); /* VNOP_HOLD's */
      nnpfs_dnlc_enter(XNODE_TO_VNODE(dp), message->name, XNODE_TO_VNODE(n));
      VNOP_RELE(XNODE_TO_VNODE(n));
    }
  else
    {
      printf("NNPFS PANIC Warning: nnpfs_message_install could not find parent\n");
      error = ENOENT;
    }
  return error;
}

int
nnpfs_message_installattr(int fd,
			struct nnpfs_message_installattr *message,
			u_int size)
{
  int error = 0;
  struct nnpfs_node *t;

  t = nnpfs_node_find(&nnpfs[fd], &message->node.handle);
  if (t != 0)
    {
      t->tokens = message->node.tokens;
      nnpfs_attr2vattr(&message->node.attr, &t->attr, 0);
      bcopy((caddr_t)message->node.id,
	    (caddr_t)t->id, sizeof(t->id));
      bcopy((caddr_t)message->node.rights,
	    (caddr_t)t->rights, sizeof(t->rights));
      t->anonrights = message->node.anonrights;
    }
  else
    {
      NNPFSDEB(XDEBMSG, ("nnpfs_message_installattr: no such node\n"));
    }
  return error;
}

int
nnpfs_message_installdata(int fd,
			struct nnpfs_message_installdata *message,
			u_int size)
{
  struct nnpfs_node *t;
  struct vnode *vp;
  int error = 0;

  NNPFSDEB(XDEBMSG, ("nnpfs_message_installdata\n"));

  t = nnpfs_node_find(&nnpfs[fd], &message->node.handle);
  if (t != 0)
    {
      message->cache_name[sizeof(message->cache_name)-1] = '\0';
      printf("cache name = '%s'\n", message->cache_name);

      error = VNOP_LOOKUP(U.U_cdir, &vp, message->cache_name, 0, NULL, U.U_cred);
      if (error == 0)
	{
	  if (DATA_FROM_XNODE(t))
	    {
	      VNOP_RELE(DATA_FROM_XNODE(t));
	    }
	  SET_DATA_FROM_XNODE(t, vp);
#if 0
	  DATA_FROM_XNODE(t) = vp; /* VNOP_LOOKUP does an implicit VNOP_HOLD? */
#endif
	  t->tokens = message->node.tokens;
	  nnpfs_attr2vattr(&message->node.attr, &t->attr, 1);
	  bcopy((caddr_t)message->node.id,
		(caddr_t)t->id, sizeof(t->id));
	  bcopy((caddr_t)message->node.rights,
		(caddr_t)t->rights, sizeof(t->rights));
	  t->anonrights = message->node.anonrights;
	}
      else
	printf("NNPFS PANIC Warning: nnpfs_message_installdata failed to lookup cache file = %s, error = %d\n", message->cache_name, error);
    }
  else
    {
      printf("NNPFS PANIC Warning: nnpfs_message_installdata didn't find node!\n");
      error = ENOENT;
    }
  return error;
}

int
nnpfs_message_invalidnode(int fd,
			struct nnpfs_message_invalidnode *message,
			u_int size)
{
  int error = 0;
  struct nnpfs_node *t;
  
  t = nnpfs_node_find(&nnpfs[fd], &message->handle);
  if (t != 0)
    {
      /* XXX Really need to put back dirty data first. */
      if (DATA_FROM_XNODE(t))
	{
	  VNOP_RELE(DATA_FROM_XNODE(t));
#if 0
	  DATA_FROM_XNODE(t) = (struct vnode *) 0;
#endif
	  SET_DATA_FROM_XNODE(t, (struct vnode *)0);
	}
      NNPFS_TOKEN_CLEAR(t, ~0,
		     NNPFS_OPEN_MASK | NNPFS_ATTR_MASK |
		     NNPFS_DATA_MASK | NNPFS_LOCK_MASK);
    }
  else
    {
#if 0
      printf("NNPFS PANIC Warning: nnpfs_message_invalidnode didn't find node!\n");
#endif
      error = ENOENT;
    }
  return error;
}

int
nnpfs_message_updatefid(int fd,
		      struct nnpfs_message_updatefid * message,
		      u_int size)
{
    int error = 0;
    struct nnpfs_node *t;

    t = nnpfs_node_find (&nnpfs[fd], &message->old_handle);
    if (t != NULL) {
	t->handle = message->new_handle;
    } else {
	printf ("NNPFS PANIC WARNING! nnpfs_message_updatefid: no node!\n");
	error = ENOENT;
    }
    return error;
}

/*
 * Try to clean out nodes for the userland daemon
 */

static void
gc_vnode (struct vnode *vp)
{
    /* nothing here yet XXX */
}

int
nnpfs_message_gc_nodes(int fd,
		     struct nnpfs_message_gc_nodes *message,
		     u_int size)
{
    NNPFSDEB(XDEBMSG, ("nnpfs_message_gc\n"));

    if (message->len == 0) {
	struct nnpfs_node *xp, *next;

	for (xp = nnpfs[fd].nodes; xp != NULL; xp = next) {
	    next = xp->next;
	    gc_vnode(XNODE_TO_VNODE(xp));
	}
    } else {
	struct nnpfs_node *t;
	int i;

	for (i = 0; i < message->len; i++) {
	    t = nnpfs_node_find (&nnpfs[fd], &message->handle[i]);
	    if (t == NULL)
		continue;

	    gc_vnode(XNODE_TO_VNODE(t));
	}
    }

    return 0;
}

/*
 * Probe what version of nnpfs this support
 */

int
nnpfs_message_version(int fd,
		    struct nnpfs_message_version *message,
		    u_int size)
{
    struct nnpfs_message_wakeup msg;
    int ret;

    ret = NNPFS_VERSION;

    msg.header.opcode = NNPFS_MSG_WAKEUP;
    msg.sleepers_sequence_num = message->header.sequence_num;
    msg.error = ret;

    return nnpfs_message_send(fd, (struct nnpfs_message_header *) &msg, sizeof(msg));
}
