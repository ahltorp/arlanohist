/* $Id: process.hpux.S,v 1.2 2006/12/29 12:05:06 tol Exp $ */

/*
****************************************************************************
*        Copyright IBM Corporation 1988, 1989 - All Rights Reserved        *
*                                                                          *
* Permission to use, copy, modify, and distribute this software and its    *
* documentation for any purpose and without fee is hereby granted,         *
* provided that the above copyright notice appear in all copies and        *
* that both that copyright notice and this permission notice appear in     *
* supporting documentation, and that the name of IBM not be used in        *
* advertising or publicity pertaining to distribution of the software      *
* without specific, written prior permission.                              *
*                                                                          *
* IBM DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING ALL *
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL IBM *
* BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY      *
* DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER  *
* IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING   *
* OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.    *
****************************************************************************
*/

#include <config.h>

#undef RCSID

#ifdef AFS_BSD_ENV
#ifdef AFS_BSD_PIC_ENV
/* this code is PIC */
	.CODE

	/*
	; savecontext(f, area1, newsp)
	;    int (*f)();
	;    struct savearea *area1;
	;    char *newsp;
	*/
savecontext
	.PROC
	/*
	; Callinfo sets up register saves using the ENTRY_GR
	; and ENTRY_FR parameters.  ENTRY_FR=21 is only valid
	; for PA 1.1.  (How to deal with this for 800?)
	*/
	.CALLINFO CALLER,FRAME=0,SAVE_RP,ENTRY_GR=18,ENTRY_FR=21
	.ENTRY
	STW   %r2, -20(%sr0,%r30)
	stwm  %r3, 0x80(%r30)
	stw   %r4, -0x40(%r30)
	stw   %r5, -0x3c(%r30)
	stw   %r6, -0x38(%r30)
	stw   %r7, -0x34(%r30)
	stw   %r8, -0x30(%r30)
	stw   %r9, -0x2c(%r30)
	stw   %r10, -0x28(%r30)
	stw   %r11, -0x24(%r30)
	stw   %r12, -0x20(%r30)
	stw   %r13, -0x1c(%r30)
	stw   %r14, -0x18(%r30)
	stw   %r15, -0x14(%r30)
	stw   %r16, -0x10(%r30)
	stw   %r17, -0x0c(%r30)
	stw   %r18, -0x08(%r30)
	stw   %r19, -0x04(%r30)

	LDI   1,%r1				/* Store a (char) 1 in */
	LDW   T%PRE_Block(%sr0,%r19),%r31    	/* global variable */
	STW   %r1,0(%sr0,%r31)			/* PRE_Block. */


	COPY  %arg0,%r22	/* Copy arg0 (f) to dyncall's input register */

	COMIB,= 0,%arg2,L$0001	/* Compare arg2 (newsp) to 0.  Execute the */
				/* next instruction regardless of value. */
	STW   %r30,0(%sr0,%arg1)/* Store the stack pointer in the first */
				/* element (0th offset) of arg1 (area1). */
	COPY  %arg2,%r30	/* Move arg2 (newsp) into the stack ptr. */

L$0001
	ldo   64(%r30), %r30
	.CALL
	BL    $$dyncall,%r31	/* Dynamic call using pointer in r22. */
	COPY  %r31,%r2
	COPY  %r20, %r19        /* restore link table. */

	.CALL
	BL    exit,%r2		/* Can't get here, so abort. */
	NOP
	.LEAVE
	.PROCEND

	/* returnto(area2)
	 *    struct savearea *area2;
	 */
returnto
	.PROC
	.CALLINFO CALLER,FRAME=0,SAVE_RP,ENTRY_GR=18,ENTRY_FR=21
	/*  No ENTRY is used since this is a magic routine. */
	LDWS  0(0,%arg0),%r30	/* Load the stack pointer from area2 */

	ldw   -0x04(%r30), %r19
	ldw   -0x08(%r30), %r18
	ldw   -0x0c(%r30), %r17
	ldw   -0x10(%r30), %r16
	ldw   -0x14(%r30), %r15
	ldw   -0x18(%r30), %r14
	ldw   -0x1c(%r30), %r13
	ldw   -0x20(%r30), %r12
	ldw   -0x24(%r30), %r11
	ldw   -0x28(%r30), %r10
	ldw   -0x2c(%r30), %r9
	ldw   -0x30(%r30), %r8
	ldw   -0x34(%r30), %r7
	ldw   -0x38(%r30), %r6
	ldw   -0x3c(%r30), %r5
	ldw   -0x40(%r30), %r4
	ldw,mb -0x80(%r30), %r3
	LDW   T%PRE_Block(0,%r19),%r31   /* set PRE_Block = 0; */
	LDW   -20(%sr0,%r30), %r2
	BV    %r0(%r2)
	STW   %r0,0(0,%r31)
	.LEAVE
	.PROCEND

	.EXPORT savecontext,ENTRY
	.EXPORT returnto,ENTRY
	.IMPORT PRE_Block,DATA
	.IMPORT $$dyncall,MILLICODE
	.IMPORT exit,CODE

	.END
#else  /* AFS_BSD_PIC_ENV */
/* non-pic'ified code */
	.IMPORT $global$,DATA
	.IMPORT PRE_Block,DATA
	.IMPORT $$dyncall,MILLICODE
	.IMPORT abort,CODE

	.text

	/*
	; savecontext(f, area1, newsp)
	;    int (*f)();
	;    struct savearea *area1;
	;    char *newsp;
	*/
	.EXPORT savecontext,ENTRY
savecontext
	.PROC
	/*
	; Callinfo sets up register saves using the ENTRY_GR
	; and ENTRY_FR parameters.  ENTRY_FR=21 is only valid
	; for PA 1.1.  (How to deal with this for 800?)
	*/
	.CALLINFO CALLER,FRAME=0,SAVE_RP,ENTRY_GR=18,ENTRY_FR=21
	.ENTRY
	STW   %r2, -20(%sr0,%r30)
	stwm  %r3, 0x80(%r30)
	stw   %r4, -0x40(%r30)
	stw   %r5, -0x3c(%r30)
	stw   %r6, -0x38(%r30)
	stw   %r7, -0x34(%r30)
	stw   %r8, -0x30(%r30)
	stw   %r9, -0x2c(%r30)
	stw   %r10, -0x28(%r30)
	stw   %r11, -0x24(%r30)
	stw   %r12, -0x20(%r30)
	stw   %r13, -0x1c(%r30)
	stw   %r14, -0x18(%r30)
	stw   %r15, -0x14(%r30)
	stw   %r16, -0x10(%r30)
	stw   %r17, -0x0c(%r30)
	stw   %r18, -0x08(%r30)
	stw   %r19, -0x04(%r30)

	LDI   1,%r31				/* Store a (char) 1 in */
	ADDIL L%PRE_Block-$global$,%r27		/* global variable */
	STW   %r31,R%PRE_Block-$global$(0,%r1)	/* PRE_Block. */

	COPY  %r26,%r22		/* Copy arg0 (f) to dyncall's input register. */

	COMIB,= 0,%r24,L$0001	/* Compare arg2 (newsp) to 0.  Execute the */
				/* next instruction regardless of value. */
	STWS  %r30,0(0,%r25)	/* Store the stack pointer in the first */
				/* element (0th offset) of arg1 (area1). */
	COPY  %r24,%r30		/* Move arg2 (newsp) into the stack ptr. */

L$0001
	ldo   64(%r30), %r30
	.CALL
	BL    $$dyncall,%r31	/* Dynamic call using pointer in r22. */
	COPY  %r31,%r2

	.CALL
	BL    abort,%r2		/* Can't get here, so abort. */
	NOP
	.EXIT
	.PROCEND

	.text

	/*
	; returnto(area2)
	;    struct savearea *area2;
	*/
	.EXPORT returnto,ENTRY
returnto
	.PROC
	.CALLINFO CALLER,FRAME=0,SAVE_RP,ENTRY_GR=18,ENTRY_FR=21
	.ENTRY
	LDWS  0(0,%r26),%r30	/* Load the stack pointer from area2 */
	ADDIL L%PRE_Block-$global$,%r27		/* PRE_Block = 0 */

	ldw   -0x04(%r30), %r19
	ldw   -0x08(%r30), %r18
	ldw   -0x0c(%r30), %r17
	ldw   -0x10(%r30), %r16
	ldw   -0x14(%r30), %r15
	ldw   -0x18(%r30), %r14
	ldw   -0x1c(%r30), %r13
	ldw   -0x20(%r30), %r12
	ldw   -0x24(%r30), %r11
	ldw   -0x28(%r30), %r10
	ldw   -0x2c(%r30), %r9
	ldw   -0x30(%r30), %r8
	ldw   -0x34(%r30), %r7
	ldw   -0x38(%r30), %r6
	ldw   -0x3c(%r30), %r5
	ldw   -0x40(%r30), %r4
	ldw,mb -0x80(%r30), %r3
	LDW   -20(%sr0,%r30), %r2
	BV    %r0(%r2)
	STW   %r0,R%PRE_Block-$global$(0,%r1)
	.EXIT
	.PROCEND

	.END
#endif /* AFS_BSD_PIC_ENV */
#endif /* AFS_BSD_ENV */
