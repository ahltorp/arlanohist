/*
 * Copyright (c) 2002 Kungliga Tekniska Högskolan
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

/* $Id: nnpfs_list.h,v 1.1 2002/10/29 16:51:56 tol Exp $ */

#ifndef _NNPFS_NNPFS_LIST_H
#define _NNPFS_NNPFS_LIST_H

/*
 * XXX - we should make this a circular list
 */

#define XLIST_LISTHEAD(type) \
struct { \
    struct type *head; \
    struct type *tail; \
}


#define XLIST_LISTHEAD_INIT(xhead) \
(xhead)->head = (xhead)->tail = NULL;


#define XLIST_ENTRY(type) \
struct { \
    struct type *prev; \
    struct type *next; \
}

#define XLIST_INIT(container, field) \
(container)->field.prev = (container)->field.next = NULL;


#define XLIST_ADD_HEAD(xhead, container, field) { \
if ((xhead)->head != NULL) \
    (xhead)->head->field.prev = (container); \
(container)->field.next = (xhead)->head; \
(container)->field.prev = NULL; \
(xhead)->head = (container); \
if ((xhead)->tail == NULL) \
    (xhead)->tail = (container); \
}


#define XLIST_ADD_TAIL(xhead, container, field) { \
if ((xhead)->tail != NULL) \
    (xhead)->tail->field.next = (container); \
(container)->field.prev = (xhead)->tail; \
(container)->field.next = NULL; \
(xhead)->tail = (container); \
if ((xhead)->head == NULL) \
    (xhead)->head = (container); \
}


#define XLIST_REMOVE(xhead, container, field) { \
if ((xhead)->head == (container)) \
    (xhead)->head = (container)->field.next; \
else \
    ((container)->field.prev)->field.next = (container)->field.next; \
if ((xhead)->tail == (container)) \
    (xhead)->tail = (container)->field.prev; \
else \
    ((container)->field.next)->field.prev = (container)->field.prev; \
XLIST_INIT(container, field); \
}


#define XLIST_REMOVE_HEAD(xhead, container, field) { \
ASSERT((xhead)->head != NULL); \
(container) = (xhead)->head; \
XLIST_REMOVE(xhead, (container), field); \
}


#define XLIST_REMOVE_TAIL(xhead, container, field) { \
ASSERT((xhead)->tail != NULL); \
(container) = (xhead)->tail; \
XLIST_REMOVE(xhead, (container), field); \
}


#define XLIST_EMPTY(xhead) ((xhead)->head == NULL)
#define XLIST_HEAD(xhead) ((xhead)->head)
#define XLIST_TAIL(xhead) ((xhead)->tail)
#define XLIST_PREV(container, field) ((container)->field.prev)
#define XLIST_NEXT(container, field) ((container)->field.next)

#define XLIST_ONQ(xhead, container, field) \
((container)->field.prev != NULL || (container)->field.next != NULL \
  || (xhead)->head == (container))

#define XLIST_FOREACH(xhead, container, field) \
for ((container) = (xhead)->head; \
(container); \
(container) = (container)->field.next)

#define XLIST_FOREACH_REVERSE(xhead, container, field) \
for ((container) = (xhead)->tail; \
(container); \
(container) = (container)->field.prev)

#endif /* _NNPFS_NNPFS_LIST_H */
