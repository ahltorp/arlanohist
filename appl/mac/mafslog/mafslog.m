/*
 * Copyright (c) 2002, Stockholms Universitet
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <sys/ioctl.h>

#include <stdio.h>
#include <errno.h>
#include <inttypes.h>
#include <strings.h>

#include <krb5.h>
#include <kafs.h>
#include <arla-pioctl.h>

#include <fs.h>
#include <arlalib.h>

#import "mafslog.h"

@implementation mafslog

#ifdef RCSID
RCSID("$Id: mafslog.m,v 1.4 2005/10/28 14:33:36 tol Exp $");
#endif

static krb5_context mafslog_context = NULL;
static krb5_ccache mafslog_id;
static NSMutableArray *tokens = NULL;

struct token_ctx {
    int i;
    id ttc;
    id tts;
    id tte;
};

static int
token_func (const char *secret, size_t secret_sz,
            const struct ClearToken *ct,
            const char *cell,
            void *arg)
{
    NSMutableDictionary *d;
    struct token_ctx *c = arg;
    char ts[100];
    time_t t = time(NULL);
    
    d = [NSMutableDictionary dictionaryWithCapacity:3];
    
    if (ct->EndTimestamp > t) {
        t = ct->EndTimestamp - t;
        snprintf(ts, sizeof(ts), "%2d:%02d", (int)t / 60 / 60, (int) (t / 60) % 60);
    } else
        snprintf(ts, sizeof(ts), "Expired");

    [d setObject:[NSString stringWithCString:cell] forKey:c->ttc];
    [d setObject:@"Ok" forKey:c->tts];
    [d setObject:[NSString stringWithCString:ts] forKey:c->tte];
    
    [tokens insertObject:d atIndex:c->i];
    c->i++;
    return 0;
}

static void
update_token_array(id tt, id ttc, id tts, id tte)
{
    struct token_ctx c;
    c.i = 0;
    c.ttc = [ttc identifier];
    c.tts = [tts identifier];
    c.tte = [tte identifier];
    [tokens removeAllObjects];
    arlalib_token_iter(NULL, token_func, &c);
    [tt reloadData];
}

static void
do_afslog(id tt, NSProgressIndicator *p, id sender)
{
    int ret;

    if (!k_hasafs_recheck()) {
	if (sender == nil)
	    return;
        NSBeginAlertSheet(@"Error", @"Ok", nil, nil, [tt window],
            nil, nil, nil, NULL, @"You haven't started a AFS client yet");
	return;
    }

    if (mafslog_context == NULL)
        return;

    [p startAnimation:sender];
    ret = krb5_afslog(mafslog_context, mafslog_id, NULL, NULL);
    [p stopAnimation:sender];
#if 0
    if (ret && sender)
        NSBeginAlertSheet(@"Error", @"Ok", nil, nil, [tt window],
            nil, nil, nil, NULL, @"Try get new kerberos tickets");
#endif
}

- (void)awakeFromNib
{
    tokens = [[NSMutableArray arrayWithCapacity:1] retain];
    
    [progress setUsesThreadedAnimation:TRUE];

    if(krb5_init_context(&mafslog_context))
        return;

    krb5_cc_default(mafslog_context, &mafslog_id);
   
    if (!k_hasafs_recheck())
        return;

    do_afslog(tokenTable, progress, nil);

    update_token_array(tokenTable, tokenTableCell, tokenTableStatus, tokenTableExpire);
}

- (IBAction)unlog:(id)sender
{
    struct ViceIoctl parms;

    parms.in = NULL;
    parms.in_size = 0;
    parms.out = NULL;
    parms.out_size = 0;
	
    if (k_pioctl(NULL, ARLA_VIOCUNLOG, &parms, 0) != 0)
        printf("error unlogging\n");

    update_token_array(tokenTable, tokenTableCell, tokenTableStatus, tokenTableExpire);
}

- (IBAction)authenticate:(id)sender
{
    do_afslog(tokenTable, progress, sender);
    update_token_array(tokenTable, tokenTableCell, tokenTableStatus, tokenTableExpire);
}

- (int)numberOfRowsInTableView:(NSTableView *)aTableView
{
    int count = 0;
    if (tokens)
        count = [tokens count]; 
    return count;
}

- (id)tableView:(NSTableView *)aTableView
    objectValueForTableColumn:(NSTableColumn *)aTableColumn
    row:(int)rowIndex
{
    NSMutableDictionary *d;
    
    d = [tokens objectAtIndex:rowIndex];
    return [d objectForKey:[aTableColumn identifier]];
}


@end
