/*
 * Copyright (c) 1997, 1998, 1999, 2000 Kungliga Tekniska H�gskolan
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

#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include "config.h"
#include "roken.h"
#include <err.h>
#include <parse_time.h>
#include "kconf.h"

/* $Heimdal: config_file.c,v 1.38 1999/12/02 17:05:08 joda Exp $ */

#ifdef RCSID
RCSID("$Id: kconf.c,v 1.5 2002/10/01 23:34:57 lha Exp $");
#endif

static int parse_section(char *p, kconf_config_section **s,
			 kconf_config_section **res,
			 char **error_message);
static int parse_binding(FILE *f, unsigned *lineno, char *p,
			 kconf_config_binding **b,
			 kconf_config_binding **parent,
			 char **error_message);
static int parse_list(FILE *f, unsigned *lineno, kconf_config_binding **parent,
		      char **error_message);

/*
 * Parse a section:
 *
 * [section]
 *	foo = bar
 *	b = {
 *		a
 *	    }
 * ...
 * 
 * starting at the line in `p', storing the resulting structure in
 * `s' and hooking it into `parent'.
 * Store the error message in `error_message'.
 */

static int
parse_section(char *p, kconf_config_section **s, kconf_config_section **parent,
	      char **error_message)
{
    char *p1;
    kconf_config_section *tmp;

    p1 = strchr (p + 1, ']');
    if (p1 == NULL) {
	*error_message = "missing ]";
	return -1;
    }
    *p1 = '\0';
    tmp = malloc(sizeof(*tmp));
    if (tmp == NULL) {
	*error_message = "out of memory";
	return -1;
    }
    tmp->name = strdup(p+1);
    if (tmp->name == NULL) {
	*error_message = "out of memory";
	return -1;
    }
    tmp->type = kconf_config_list;
    tmp->u.list = NULL;
    tmp->next = NULL;
    if (*s)
	(*s)->next = tmp;
    else
	*parent = tmp;
    *s = tmp;
    return 0;
}

/*
 * Parse a brace-enclosed list from `f', hooking in the structure at
 * `parent'.
 * Store the error message in `error_message'.
 */

static int
parse_list(FILE *f, unsigned *lineno, kconf_config_binding **parent,
	   char **error_message)
{
    char buf[BUFSIZ];
    int ret;
    kconf_config_binding *b = NULL;
    unsigned beg_lineno = *lineno;

    while(fgets(buf, sizeof(buf), f) != NULL) {
	char *p;

	++*lineno;
	buf[strcspn(buf, "\n")] = '\0';
	p = buf;
	while(isspace((unsigned char)*p))
	    ++p;
	if (*p == '#' || *p == ';' || *p == '\0')
	    continue;
	while(isspace((unsigned char)*p))
	    ++p;
	if (*p == '}')
	    return 0;
	if (*p == '\0')
	    continue;
	ret = parse_binding (f, lineno, p, &b, parent, error_message);
	if (ret)
	    return ret;
    }
    *lineno = beg_lineno;
    *error_message = "unclosed {";
    return -1;
}

/*
 *
 */

static int
parse_binding(FILE *f, unsigned *lineno, char *p,
	      kconf_config_binding **b, kconf_config_binding **parent,
	      char **error_message)
{
    kconf_config_binding *tmp;
    char *p1, *p2;
    int ret = 0;

    p1 = p;
    while (*p && *p != '=' && !isspace((unsigned char)*p))
	++p;
    if (*p == '\0') {
	*error_message = "no =";
	return -1;
    }
    p2 = p;
    while (isspace((unsigned char)*p))
	++p;
    if (*p != '=') {
	*error_message = "no =";
	return -1;
    }
    ++p;
    while(isspace((unsigned char)*p))
	++p;
    tmp = malloc(sizeof(*tmp));
    if (tmp == NULL) {
	*error_message = "out of memory";
	return -1;
    }
    *p2 = '\0';
    tmp->name = strdup(p1);
    tmp->next = NULL;
    if (*p == '{') {
	tmp->type = kconf_config_list;
	tmp->u.list = NULL;
	ret = parse_list (f, lineno, &tmp->u.list, error_message);
    } else {
	p1 = p;
	p = p1 + strlen(p1);
	while(p > p1 && isspace((unsigned char)*(p-1)))
	    --p;
	*p = '\0';
	tmp->type = kconf_config_string;
	tmp->u.string = strdup(p1);
    }
    if (*b)
	(*b)->next = tmp;
    else
	*parent = tmp;
    *b = tmp;
    return ret;
}

int
kconf_init (kconf_context *context)
{
    *context = emalloc (sizeof(*context));
    if (*context == NULL) return errno;
    (*context)->cf = NULL;
    return 0;
}

void
kconf_free (kconf_context context)
{
    free (context);
}

/*
 * Parse the config file `fname', generating the structures into `res'
 * returning error messages in `error_message'
 */

int
kconf_config_parse_file_debug (const char *fname,
			       kconf_config_section **res,
			       unsigned *lineno,
			       char **error_message)
{
    FILE *f;
    kconf_config_section *s;
    kconf_config_binding *b;
    char buf[BUFSIZ];
    int ret;

    s = NULL;
    b = NULL;
    *lineno = 0;
    f = fopen (fname, "r");
    if (f == NULL) {
	*error_message = "cannot open file";
	return -1;
    }
    *res = NULL;
    while (fgets(buf, sizeof(buf), f) != NULL) {
	char *p;

	++*lineno;
	buf[strcspn(buf, "\n")] = '\0';
	p = buf;
	while(isspace((unsigned char)*p))
	    ++p;
	if (*p == '#' || *p == ';')
	    continue;
	if (*p == '[') {
	    ret = parse_section(p, &s, res, error_message);
	    if (ret)
		return ret;
	    b = NULL;
	} else if (*p == '}') {
	    *error_message = "unmatched }";
	    return -1;
	} else if(*p != '\0') {
	    ret = parse_binding(f, lineno, p, &b, &s->u.list, error_message);
	    if (ret)
		return ret;
	}
    }
    fclose (f);
    return 0;
}

int
kconf_config_parse_file (const char *fname, kconf_config_section **res)
{
    char *foo;
    unsigned lineno;

    return kconf_config_parse_file_debug (fname, res, &lineno, &foo);
}


static void
free_binding (kconf_context context, kconf_config_binding *b)
{
    kconf_config_binding *next_b;

    while (b) {
	free (b->name);
	if (b->type == kconf_config_string)
	    free (b->u.string);
	else if (b->type == kconf_config_list)
	    free_binding (context, b->u.list);
	else
	    errx (1, "unknown binding type (%d) in free_binding", 
		  b->type);
	next_b = b->next;
	free (b);
	b = next_b;
    }
}

int
kconf_config_file_free (kconf_context context, kconf_config_section *s)
{
    free_binding (context, s);
    return 0;
}

const void *
kconf_config_get_next (kconf_context context,
		       kconf_config_section *c,
		       kconf_config_binding **pointer,
		       int type,
		       ...)
{
    const char *ret;
    va_list args;

    va_start(args, type);
    ret = kconf_config_vget_next (context, c, pointer, type, args);
    va_end(args);
    return ret;
}

const void *
kconf_config_vget_next (kconf_context context,
			kconf_config_section *c,
			kconf_config_binding **pointer,
			int type,
			va_list args)
{
    kconf_config_binding *b;
    const char *p;

    if(c == NULL)
	c = context->cf;

    if (c == NULL)
	return NULL;

    if (*pointer == NULL) {
	b = (c != NULL) ? c : context->cf;
	p = va_arg(args, const char *);
	if (p == NULL)
	    return NULL;
    } else {
	b = *pointer;
	p = b->name;
	b = b->next;
    }

    while (b) {
	if (strcmp (b->name, p) == 0) {
	    if (*pointer == NULL)
		p = va_arg(args, const char *);
	    else
		p = NULL;
	    if (type == b->type && p == NULL) {
		*pointer = b;
		return b->u.generic;
	    } else if(b->type == kconf_config_list && p != NULL) {
		b = b->u.list;
	    } else {
		return NULL;
	    }
	} else {
	    b = b->next;
	}
    }
    return NULL;
}

const void *
kconf_config_get (kconf_context context,
		  kconf_config_section *c,
		  int type,
		  ...)
{
    const void *ret;
    va_list args;

    va_start(args, type);
    ret = kconf_config_vget (context, c, type, args);
    va_end(args);
    return ret;
}

const void *
kconf_config_vget (kconf_context context,
		   kconf_config_section *c,
		   int type,
		   va_list args)
{
    kconf_config_binding *foo = NULL;

    return kconf_config_vget_next (context, c, &foo, type, args);
}

const kconf_config_binding *
kconf_config_get_list (kconf_context context,
		       kconf_config_section *c,
		       ...)
{
    const kconf_config_binding *ret;
    va_list args;

    va_start(args, c);
    ret = kconf_config_vget_list (context, c, args);
    va_end(args);
    return ret;
}

const kconf_config_binding *
kconf_config_vget_list (kconf_context context,
			kconf_config_section *c,
			va_list args)
{
    return kconf_config_vget (context, c, kconf_config_list, args);
}

const char *
kconf_config_get_string (kconf_context context,
			 kconf_config_section *c,
			 ...)
{
    const char *ret;
    va_list args;

    va_start(args, c);
    ret = kconf_config_vget_string (context, c, args);
    va_end(args);
    return ret;
}

const char *
kconf_config_get_string_default (kconf_context context,
				 kconf_config_section *c,
				 const char *def,
				 ...)
{
    const char *ret;
    va_list args;

    va_start(args, def);
    ret = kconf_config_vget_string (context, c, args);
    va_end(args);
    if (ret == NULL)
	return def;
    return ret;
}

const char *
kconf_config_vget_string (kconf_context context,
			  kconf_config_section *c,
			  va_list args)
{
    return kconf_config_vget (context, c, kconf_config_string, args);
}

char **
kconf_config_vget_strings(kconf_context context,
			  kconf_config_section *c,
			  va_list args)
{
    char **strings = NULL;
    int nstr = 0;
    kconf_config_binding *b = NULL;
    const char *p;

    while((p = kconf_config_vget_next(context, c, &b, 
				      kconf_config_string, args))) {
	char *tmp = strdup(p);
	char *pos = NULL;
	char *s;
	if(tmp == NULL)
	    goto cleanup;
	s = strtok_r(tmp, " \t", &pos);
	while(s){
	    char **tmp = realloc(strings, (nstr + 1) * sizeof(*strings));
	    if(tmp == NULL)
		goto cleanup;
	    strings = tmp;
	    strings[nstr] = strdup(s);
	    nstr++;
	    if(strings[nstr-1] == NULL)
		goto cleanup;
	    s = strtok_r(NULL, " \t", &pos);
	}
	free(tmp);
    }
    if(nstr){
	char **tmp = realloc(strings, (nstr + 1) * sizeof(*strings));
	if(strings == NULL)
	    goto cleanup;
	strings = tmp;
	strings[nstr] = NULL;
    }
    return strings;
 cleanup:
    while(nstr--)
	free(strings[nstr]);
    free(strings);
    return NULL;

}

char**
kconf_config_get_strings(kconf_context context,
			 kconf_config_section *c,
			 ...)
{
    va_list ap;
    char **ret;
    va_start(ap, c);
    ret = kconf_config_vget_strings(context, c, ap);
    va_end(ap);
    return ret;
}

void
kconf_config_free_strings(char **strings)
{
    char **s = strings;
    while(s && *s){
	free(*s);
	s++;
    }
    free(strings);
}

kconf_boolean
kconf_config_vget_bool_default (kconf_context context,
				kconf_config_section *c,
				kconf_boolean def_value,
				va_list args)
{
    const char *str;
    str = kconf_config_vget_string (context, c, args);
    if(str == NULL)
	return def_value;
    if(strcasecmp(str, "yes") == 0 ||
       strcasecmp(str, "true") == 0 ||
       atoi(str)) return KCONF_TRUE;
    return KCONF_FALSE;
}

kconf_boolean
kconf_config_vget_bool  (kconf_context context,
			 kconf_config_section *c,
			 va_list args)
{
    return kconf_config_vget_bool_default (context, c, KCONF_FALSE, args);
}

kconf_boolean
kconf_config_get_bool_default (kconf_context context,
			       kconf_config_section *c,
			       kconf_boolean def_value,
			       ...)
{
    va_list ap;
    kconf_boolean ret;
    va_start(ap, def_value);
    ret = kconf_config_vget_bool_default(context, c, def_value, ap);
    va_end(ap);
    return ret;
}

kconf_boolean
kconf_config_get_bool (kconf_context context,
		       kconf_config_section *c,
		       ...)
{
    va_list ap;
    kconf_boolean ret;
    va_start(ap, c);
    ret = kconf_config_vget_bool (context, c, ap);
    va_end(ap);
    return ret;
}

int
kconf_config_vget_time_default (kconf_context context,
				kconf_config_section *c,
				int def_value,
				va_list args)
{
    const char *str;
    str = kconf_config_vget_string (context, c, args);
    if(str == NULL)
	return def_value;
    return parse_time (str, NULL);
}

int
kconf_config_vget_time  (kconf_context context,
			 kconf_config_section *c,
			 va_list args)
{
    return kconf_config_vget_time_default (context, c, -1, args);
}

int
kconf_config_get_time_default (kconf_context context,
			       kconf_config_section *c,
			       int def_value,
			       ...)
{
    va_list ap;
    int ret;
    va_start(ap, def_value);
    ret = kconf_config_vget_time_default(context, c, def_value, ap);
    va_end(ap);
    return ret;
}

int
kconf_config_get_time (kconf_context context,
		       kconf_config_section *c,
		       ...)
{
    va_list ap;
    int ret;
    va_start(ap, c);
    ret = kconf_config_vget_time (context, c, ap);
    va_end(ap);
    return ret;
}


int
kconf_config_vget_int_default (kconf_context context,
			       kconf_config_section *c,
			       int def_value,
			       va_list args)
{
    const char *str;
    str = kconf_config_vget_string (context, c, args);
    if(str == NULL)
	return def_value;
    else { 
	char *endptr; 
	long l; 
	l = strtol(str, &endptr, 0); 
	if (endptr == str) 
	    return def_value; 
	else 
	    return l;
    }
}

int
kconf_config_vget_int  (kconf_context context,
			kconf_config_section *c,
			va_list args)
{
    return kconf_config_vget_int_default (context, c, -1, args);
}

int
kconf_config_get_int_default (kconf_context context,
			      kconf_config_section *c,
			      int def_value,
			      ...)
{
    va_list ap;
    int ret;
    va_start(ap, def_value);
    ret = kconf_config_vget_int_default(context, c, def_value, ap);
    va_end(ap);
    return ret;
}

int
kconf_config_get_int (kconf_context context,
		      kconf_config_section *c,
		      ...)
{
    va_list ap;
    int ret;
    va_start(ap, c);
    ret = kconf_config_vget_int (context, c, ap);
    va_end(ap);
    return ret;
}

#ifdef TEST

static int print_list (kconf_context context, FILE *f, 
		       kconf_config_binding *l, unsigned level);
static int print_binding (kconf_context context, FILE *f, 
			  kconf_config_binding *b, unsigned level);
static int print_section (kconf_context context, FILE *f, 
			  kconf_config_section *s, unsigned level);
static int print_config (kconf_context context, FILE *f, 
			 kconf_config_section *c);

static void
tab (FILE *f, unsigned count)
{
    while(count--)
	fprintf (f, "\t");
}

static int
print_list (kconf_context context, 
	    FILE *f, 
	    kconf_config_binding *l, 
	    unsigned level)
{
    while(l) {
	print_binding (context, f, l, level);
	l = l->next;
    }
    return 0;
}

static int
print_binding (kconf_context context, 
	       FILE *f, 
	       kconf_config_binding *b, 
	       unsigned level)
{
    tab (f, level);
    fprintf (f, "%s = ", b->name);
    if (b->type == kconf_config_string)
	fprintf (f, "%s\n", b->u.string);
    else if (b->type == kconf_config_list) {
	fprintf (f, "{\n");
	print_list (context, f, b->u.list, level + 1);
	tab (f, level);
	fprintf (f, "}\n");
    } else
	errx (1, "unknown binding type (%d) in print_binding", b->type);
    return 0;
}

static int
print_section (kconf_context context, FILE *f, kconf_config_section *s,
	       unsigned level)
{
    fprintf (f, "[%s]\n", s->name);
    print_list (context, f, s->u.list, level + 1);
    return 0;
}

static int
print_config (kconf_context context, FILE *f, kconf_config_section *c)
{
    while (c) {
	print_section (context, f, c, 0);
	c = c->next;
    }
    return 0;
}


int
main(void)
{
    kconf_context context;
    kconf_config_section *c;
    int ret;

    kconf_init (&context);

    ret = kconf_config_parse_file ("/etc/krb5.conf", &c);
    if (ret) errx (1, "kconf_config_parse_file");

    print_config (context, stdout, c);
    printf ("[libdefaults]ticket_lifetime = %s\n",
	    kconf_config_get_string (context, c,
				     "libdefaults",
				     "ticket_lifetime",
				     NULL));
    printf ("[realms]foo = %s\n",
	    kconf_config_get_string (context, c,
				     "realms",
				     "foo",
				     NULL));
    printf ("[realms]ATHENA.MIT.EDU/v4_instance_convert/lithium = %s\n",
	    kconf_config_get_string (context, c,
				     "realms",
				     "ATHENA.MIT.EDU",
				     "v4_instance_convert",
				     "lithium",
				     NULL));
    kconf_free (context);
    return 0;
}

#endif /* TEST */
