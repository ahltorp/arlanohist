/*	$OpenBSD: print.c,v 1.25 2007/05/07 18:39:28 millert Exp $	*/
/*	$NetBSD: print.c,v 1.15 1996/12/11 03:25:39 thorpej Exp $	*/

/*
 * Copyright (c) 1989, 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Michael Fischbein.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <arla_local.h>
#include <vers.h>

#include "lsprint.h"

RCSID("$Id: lsprint.c,v 1.2 2007/07/18 13:08:07 map Exp $");

#ifndef SECSPERMIN
#define SECSPERMIN      60
#define MINSPERHOUR     60
#define HOURSPERDAY     24
#define DAYSPERWEEK     7
#define DAYSPERNYEAR    365
#define DAYSPERLYEAR    366
#define SECSPERHOUR     (SECSPERMIN * MINSPERHOUR)
#define SECSPERDAY      ((long) SECSPERHOUR * HOURSPERDAY)
#endif

static int	printaname(arla_ftsent *, u_long, u_long);
static void	printlink(arla_ftsent *);
static void	printsize(size_t, off_t);
static void	printtime(time_t);
static int	printtype(u_int);
static int	compute_columns(DISPLAY *, int *);

long blocksize = 1024;		/* block size units */
int f_accesstime;		/* use time of last access */
int f_column;			/* columnated format */
int f_columnacross;		/* columnated format, sorted across */
int f_flags;			/* show flags associated with a file */
int f_grouponly;		/* long listing format without owner */
int f_humanval;			/* show human-readable file sizes */
int f_inode;			/* print inode */
int f_listdir;			/* list actual directory, not contents */
int f_listdot;			/* list files beginning with . */
int f_longform;			/* long listing format */
int f_nonprint;			/* show unprintables as ? */
int f_nosort;			/* don't sort output */
int f_numericonly;		/* don't expand uid to symbolic name */
int f_recursive;		/* ls subdirectories also */
int f_reversesort;		/* reverse whatever sort is used */
int f_sectime;			/* print the real time for all files */
int f_singlecol;		/* use single column output */
int f_size;			/* list size in short listing */
int f_statustime;		/* use time of last mode change */
int f_stream;			/* stream format */
int f_type;			/* add type character for non-regular files */
int f_typedir;			/* add type character for directories */

int termwidth = 80;

#define	IS_NOPRINT(p)	((p)->fts_number == NO_PRINT)

static void
arla_strmode(int mode, char *p)
{
	 /* print type */
	switch (mode & S_IFMT) {
	case S_IFDIR:			/* directory */
		*p++ = 'd';
		break;
	case S_IFCHR:			/* character special */
		*p++ = 'c';
		break;
	case S_IFBLK:			/* block special */
		*p++ = 'b';
		break;
	case S_IFREG:			/* regular */
		*p++ = '-';
		break;
	case S_IFLNK:			/* symbolic link */
		*p++ = 'l';
		break;
	case S_IFSOCK:			/* socket */
		*p++ = 's';
		break;
#ifdef S_IFIFO
	case S_IFIFO:			/* fifo */
		*p++ = 'p';
		break;
#endif
	default:			/* unknown */
		*p++ = '?';
		break;
	}
	/* usr */
	if (mode & S_IRUSR)
		*p++ = 'r';
	else
		*p++ = '-';
	if (mode & S_IWUSR)
		*p++ = 'w';
	else
		*p++ = '-';
	switch (mode & (S_IXUSR | S_ISUID)) {
	case 0:
		*p++ = '-';
		break;
	case S_IXUSR:
		*p++ = 'x';
		break;
	case S_ISUID:
		*p++ = 'S';
		break;
	case S_IXUSR | S_ISUID:
		*p++ = 's';
		break;
	}
	/* group */
	if (mode & S_IRGRP)
		*p++ = 'r';
	else
		*p++ = '-';
	if (mode & S_IWGRP)
		*p++ = 'w';
	else
		*p++ = '-';
	switch (mode & (S_IXGRP | S_ISGID)) {
	case 0:
		*p++ = '-';
		break;
	case S_IXGRP:
		*p++ = 'x';
		break;
	case S_ISGID:
		*p++ = 'S';
		break;
	case S_IXGRP | S_ISGID:
		*p++ = 's';
		break;
	}
	/* other */
	if (mode & S_IROTH)
		*p++ = 'r';
	else
		*p++ = '-';
	if (mode & S_IWOTH)
		*p++ = 'w';
	else
		*p++ = '-';
	switch (mode & (S_IXOTH | S_ISVTX)) {
	case 0:
		*p++ = '-';
		break;
	case S_IXOTH:
		*p++ = 'x';
		break;
	case S_ISVTX:
		*p++ = 'T';
		break;
	case S_IXOTH | S_ISVTX:
		*p++ = 't';
		break;
	}
	*p++ = ' ';		/* will be a '+' if ACL's implemented */
	*p = '\0';
}

static int
putname(char *name)
{
	int len;

	for (len = 0; *name; len++, name++)
		putchar((!isprint(*name) && f_nonprint) ? '?' : *name);
	return len;
}

void
printscol(DISPLAY *dp)
{
	arla_ftsent *p;

	for (p = dp->list; p; p = p->fts_link) {
		if (IS_NOPRINT(p))
			continue;
		(void)printaname(p, dp->s_inode, dp->s_block);
		(void)putchar('\n');
	}
}

void
printlong(DISPLAY *dp)
{
	struct stat *sp;
	arla_ftsent *p;
	NAMES *np;
	char buf[20];

	if (dp->list->fts_level != ARLA_FTS_ROOTLEVEL && (f_longform || f_size))
		(void)printf("total %lu\n", howmany(dp->btotal, blocksize));

	for (p = dp->list; p; p = p->fts_link) {
		if (IS_NOPRINT(p))
			continue;
		sp = p->fts_statp;
		if (f_inode)
			(void)printf("%*u ", dp->s_inode, sp->st_ino);
		if (f_size)
			(void)printf("%*qd ",
			    dp->s_block, howmany(sp->st_blocks, blocksize));
		(void)arla_strmode(sp->st_mode, buf);
		np = p->fts_pointer;
                (void)printf("%s %*u ", buf, dp->s_nlink, sp->st_nlink);
		if (!f_grouponly)
			(void)printf("%-*s  ", dp->s_user, np->user);
		(void)printf("%-*s  ", dp->s_group, np->group);
		if (f_flags)
			(void)printf("%-*s ", dp->s_flags, np->flags);
		if (S_ISCHR(sp->st_mode) || S_ISBLK(sp->st_mode))
			(void)printf("%3d, %3d ",
			    major(sp->st_rdev), minor(sp->st_rdev));
		else if (dp->bcfile)
			(void)printf("%*s%*qd ",
			    8 - dp->s_size, "", dp->s_size, sp->st_size);
		else
			printsize(dp->s_size, sp->st_size);	
		if (f_accesstime)
			printtime(sp->st_atime);
		else if (f_statustime)
			printtime(sp->st_ctime);
		else
			printtime(sp->st_mtime);
		(void)putname(p->fts_name);
		if (f_type || (f_typedir && S_ISDIR(sp->st_mode)))
			(void)printtype(sp->st_mode);
		if (S_ISLNK(sp->st_mode))
			printlink(p);
		(void)putchar('\n');
	}
}

static int
compute_columns(DISPLAY *dp, int *pnum)
{
	int colwidth;
	int mywidth;

	colwidth = dp->maxlen;
	if (f_inode)
		colwidth += dp->s_inode + 1;
	if (f_size)
		colwidth += dp->s_block + 1;
	if (f_type || f_typedir)
		colwidth += 1;

	colwidth += 1;
	mywidth = termwidth + 1;	/* no extra space for last column */

	if (mywidth < 2 * colwidth) {
		printscol(dp);
		return (0);
	}

	*pnum = mywidth / colwidth;
	return (mywidth / *pnum);		/* spread out if possible */
}

void
printcol(DISPLAY *dp)
{
	static arla_ftsent **array;
	static int lastentries = -1;
	arla_ftsent *p;
	int base, chcnt, col, colwidth, num;
	int numcols, numrows, row;

	if ((colwidth = compute_columns(dp, &numcols)) == 0)
		return;
	/*
	 * Have to do random access in the linked list -- build a table
	 * of pointers.
	 */
	if (dp->entries > lastentries) {
		arla_ftsent **a;

		if ((a = realloc(array, dp->entries * sizeof(arla_ftsent *))) ==
		    NULL) {
			free(array);
			array = NULL;
			dp->entries = 0;
			lastentries = -1;
			warn(NULL);
			printscol(dp);
			return;
		}
		lastentries = dp->entries;
		array = a;
	}
	for (p = dp->list, num = 0; p; p = p->fts_link)
		if (p->fts_number != NO_PRINT)
			array[num++] = p;

	numrows = num / numcols;
	if (num % numcols)
		++numrows;

	if (dp->list->fts_level != ARLA_FTS_ROOTLEVEL && (f_longform || f_size))
		(void)printf("total %lu\n", howmany(dp->btotal, blocksize));
	for (row = 0; row < numrows; ++row) {
		for (base = row, col = 0;;) {
			chcnt = printaname(array[base], dp->s_inode, dp->s_block);
			if ((base += numrows) >= num)
				break;
			if (++col == numcols)
				break;
			while (chcnt++ < colwidth)
				putchar(' ');
		}
		(void)putchar('\n');
	}
}

/*
 * print [inode] [size] name
 * return # of characters printed, no trailing characters.
 */
static int
printaname(arla_ftsent *p, u_long inodefield, u_long sizefield)
{
	struct stat *sp;
	int chcnt;

	sp = p->fts_statp;
	chcnt = 0;
	if (f_inode)
		chcnt += printf("%*u ", (int)inodefield, sp->st_ino);
	if (f_size)
		chcnt += printf("%*qd ",
		    (int)sizefield, howmany(sp->st_blocks, blocksize));
	chcnt += putname(p->fts_name);
	if (f_type || (f_typedir && S_ISDIR(sp->st_mode)))
		chcnt += printtype(sp->st_mode);
	return (chcnt);
}

static void
printtime(time_t ftime)
{
	int i;
	char *longstring;

	longstring = ctime(&ftime);
	for (i = 4; i < 11; ++i)
		(void)putchar(longstring[i]);

#define	SIXMONTHS	((DAYSPERNYEAR / 2) * SECSPERDAY)
	if (f_sectime)
		for (i = 11; i < 24; i++)
			(void)putchar(longstring[i]);
	else if (ftime + SIXMONTHS > time(NULL))
		for (i = 11; i < 16; ++i)
			(void)putchar(longstring[i]);
	else {
		(void)putchar(' ');
		for (i = 20; i < 24; ++i)
			(void)putchar(longstring[i]);
	}
	(void)putchar(' ');
}

void
printacol(DISPLAY *dp)
{
	arla_ftsent *p;
	int chcnt, col, colwidth;
	int numcols;

	if ( (colwidth = compute_columns(dp, &numcols)) == 0)
		return;

	if (dp->list->fts_level != ARLA_FTS_ROOTLEVEL && (f_longform || f_size))
		(void)printf("total %lu\n", howmany(dp->btotal, blocksize));
	col = 0;
	for (p = dp->list; p; p = p->fts_link) {
		if (IS_NOPRINT(p))
			continue;
		if (col >= numcols) {
			col = 0;
			(void)putchar('\n');
		}
		chcnt = printaname(p, dp->s_inode, dp->s_block);
		col++;
		if (col < numcols)
			while (chcnt++ < colwidth)
				(void)putchar(' ');
	}
	(void)putchar('\n');
}

void
printstream(DISPLAY *dp)
{
	arla_ftsent *p;
	int col;
	int extwidth;

	extwidth = 0;
	if (f_inode)
		extwidth += dp->s_inode + 1;
	if (f_size)
		extwidth += dp->s_block + 1;
	if (f_type)
		extwidth += 1;

	for (col = 0, p = dp->list; p != NULL; p = p->fts_link) {
		if (IS_NOPRINT(p))
			continue;
		if (col > 0) {
			(void)putchar(','), col++;
			if (col + 1 + extwidth + p->fts_namelen >= termwidth)
				(void)putchar('\n'), col = 0;
			else
				(void)putchar(' '), col++;
		}
		col += printaname(p, dp->s_inode, dp->s_block);
	}
	(void)putchar('\n');
}

static int
printtype(u_int mode)
{
	switch (mode & S_IFMT) {
	case S_IFDIR:
		(void)putchar('/');
		return (1);
	case S_IFIFO:
		(void)putchar('|');
		return (1);
	case S_IFLNK:
		(void)putchar('@');
		return (1);
	case S_IFSOCK:
		(void)putchar('=');
		return (1);
	}
	if (mode & (S_IXUSR | S_IXGRP | S_IXOTH)) {
		(void)putchar('*');
		return (1);
	}
	return (0);
}

static void
printlink(arla_ftsent *p)
{
	if (p->fts_linkname) {
	    (void)printf(" -> ");
	    (void)putname(p->fts_linkname);
	}
}

static void
printsize(size_t width, off_t bytes)
{
#if 0
	char ret[FMT_SCALED_STRSIZE];

	if ((f_humanval) && (fmt_scaled(bytes, ret) != -1)) {
		(void)printf("%*s ", (u_int)width, ret);
		return;
	}
#endif
	(void)printf("%*qd ", (u_int)width, bytes);
}

