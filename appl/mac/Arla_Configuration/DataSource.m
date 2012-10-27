#import "DataSource.h"
#import "ReadCells.h"
#import "Controller.h"
#include <stdio.h>
#include <sys/ioctl.h>
#include <arla-pioctl.h>
#include <kafs.h>
#include "config.h"
#include <roken.h>
#include <parse_units.h>
#include <sys/wait.h>

static struct units size_units[] = {
    { "G", 1024 * 1024 * 1024 },
    { "M", 1024 * 1024 },
    { "k", 1024 },
    { NULL, 0 }
};

static void
drainfile(FILE *f)
{
    char buffer[100];
    while(fread(buffer, 1, sizeof(buffer), f) != 0);
}

static void
drainproc()
{
    pid_t pid;
    int status;
    do {
	pid = wait(&status);
    } while (pid != -1);
}

static int
getdaemonpid(AuthorizationRef authorization, char *buffer, int len)
{
    char *argv[3];
    OSStatus status;
    FILE *output;
    int n;

    argv[0] = "/var/run/arlad.pid";
    argv[1] = NULL;

    status = AuthorizationExecuteWithPrivileges(authorization, "/bin/cat", 0, argv, &output);
    if (status == noErr) {
        n = fread(buffer, 1, len - 1, output);
        if (n == 0) {
            fclose(output);
            return -1;
        }
        buffer[n] = '\0';
        fclose(output);
	drainproc();
        return 0;
    } else {
        return -1;
    }
}

static int
checkdaemonpid(AuthorizationRef authorization, char *pid)
{
    char *argv[4];
    OSStatus status;
    FILE *output;
    char buffer[1000];
    int n;

    argv[0] = "cocommand=";
    argv[1] = "-p";
    argv[2] = pid;
    argv[3] = NULL;
    status = AuthorizationExecuteWithPrivileges(authorization, "/bin/ps", 0, argv, &output);
    n = fread(buffer, 1, sizeof(buffer) - 1, output);
    if (n == 0) {
        fclose(output);
        return -1;
    }
    buffer[n] = '\0';
    fclose(output);
    drainproc();
    if (strcmp(buffer, "\narlad\n") == 0)
        return 1;
    return 0;
}

static int
nnpfs_umount(AuthorizationRef authorization)
{
    char *argv[2];
    OSStatus status;
    FILE *output;

    argv[0] = "/afs";
    argv[1] = NULL;

    status = AuthorizationExecuteWithPrivileges(authorization, "/usr/arla/sbin/umount_nnpfs", 0, argv, &output);
    if (status == noErr) {
        drainfile(output);
        fclose(output);
	drainproc();
        return 0;
    } else {
        return -1;
    }
}

static int
nnpfs_mount(AuthorizationRef authorization)
{
    char *argv[3];
    OSStatus status;
    FILE *output;

    argv[0] = "/dev/nnpfs0";
    argv[1] = "/afs";
    argv[2] = NULL;

    status = AuthorizationExecuteWithPrivileges(authorization, "/usr/arla/sbin/mount_nnpfs", 0, argv, &output);
    if (status == noErr) {
        drainfile(output);
        fclose(output);
	drainproc();
        return 0;
    } else {
        return -1;
    }
}

static int
stoparlad(AuthorizationRef authorization)
{
    char *argv[3];
    OSStatus status;
    FILE *output;
    char pid[100];
    int ret;

    ret = getdaemonpid(authorization, pid, sizeof(pid));
    if (ret == -1)
        return -1;

    argv[0] = pid;
    argv[1] = NULL;

    status = AuthorizationExecuteWithPrivileges(authorization, "/bin/kill", 0, argv, &output);
    if (status == noErr) {
        drainfile(output);
        fclose(output);
	drainproc();
        return 0;
    } else {
        return -1;
    }
}

static int
startarlad(AuthorizationRef authorization)
{
    char *argv[3];
    OSStatus status;
    FILE *output;

    argv[0] = "-D";
    argv[1] = NULL;

    status = AuthorizationExecuteWithPrivileges(authorization, "/usr/arla/libexec/arlad", 0, argv, &output);
    if (status == noErr) {
        drainfile(output);
        fclose(output);
	drainproc();
        return 0;
    } else {
        return -1;
    }
}

static int
kmodunload(AuthorizationRef authorization)
{
    char *argv[3];
    OSStatus status;
    FILE *output;

    sleep(2); /* wait 2 secs for arlad to clean up */

    argv[0] = "/usr/arla/bin/nnpfs.kext";
    argv[1] = NULL;

    status = AuthorizationExecuteWithPrivileges(authorization, "/sbin/kextunload", 0, argv, &output);
    if (status == noErr) {
        drainfile(output);
        fclose(output);
	drainproc();
        return 0;
    } else {
        return -1;
    }
}

static int
kmodload(AuthorizationRef authorization)
{
    char *argv[3];
    OSStatus status;
    FILE *output;

    argv[0] = "/usr/arla/bin/nnpfs.kext";
    argv[1] = NULL;

    status = AuthorizationExecuteWithPrivileges(authorization, "/sbin/kextload", 0, argv, &output);
    if (status == noErr) {
        drainfile(output);
        fclose(output);
	drainproc();
        return 0;
    } else {
        return -1;
    }
}

static int
mkafsdir(AuthorizationRef authorization)
{
    char *argv[3];
    OSStatus status;
    FILE *output;

    argv[0] = "/afs";
    argv[1] = NULL;

    status = AuthorizationExecuteWithPrivileges(authorization, "/bin/mkdir",
						0, argv, &output);
    if (status == noErr) {
        drainfile(output);
        fclose(output);
	drainproc();
        return 0;
    } else {
        return -1;
    }
}

static int
getcacheparam(int32_t opcode, int64_t *val)
{
    struct arlaViceIoctl a_params;

    a_params.in_size  = sizeof(opcode);
    a_params.out_size = sizeof(*val);
    a_params.in       = (char *)&opcode;
    a_params.out      = (char *)val;

    if (k_pioctl(NULL, ARLA_AIOC_GETCACHEPARAMS, (void *)&a_params, 0) == -1)
	return errno;

    return 0;
}

static int
getcache(int64_t *high_bytes,
	 int64_t *used_bytes,
	 int64_t *low_bytes,
	 int64_t *high_vnodes,
	 int64_t *used_vnodes,
	 int64_t *low_vnodes)
{
    int ret;
    
    if (!k_hasafs_recheck())
	return ENOSYS;
    
    if ((ret = getcacheparam(arla_GETCACHEPARAMS_OPCODE_HIGHBYTES, high_bytes) != 0)
	|| (ret = getcacheparam(arla_GETCACHEPARAMS_OPCODE_USEDBYTES, used_bytes) != 0)
	|| (ret = getcacheparam(arla_GETCACHEPARAMS_OPCODE_LOWBYTES, low_bytes) != 0)
	|| (ret = getcacheparam(arla_GETCACHEPARAMS_OPCODE_HIGHVNODES, high_vnodes) != 0)
	|| (ret = getcacheparam(arla_GETCACHEPARAMS_OPCODE_USEDVNODES, used_vnodes) != 0)
	|| (ret = getcacheparam(arla_GETCACHEPARAMS_OPCODE_LOWVNODES, low_vnodes) != 0))
	return ret;
    
    return 0;
}

static int
setcache(long long high_bytes, long long low_bytes,
	 long long high_vnodes, long long low_vnodes,
	 AuthorizationRef authorization)
{
    char *argv[6];
    OSStatus status;
    FILE *output;

    argv[0] = "setcachesize";
    argv[1] = malloc(100);
    argv[2] = malloc(100);
    argv[3] = malloc(100);
    argv[4] = malloc(100);
    argv[5] = NULL;

    snprintf(argv[1], 100, "%lld", high_bytes / 1024);
    snprintf(argv[2], 100, "%lld", low_bytes / 1024);
    snprintf(argv[3], 100, "%lld", high_vnodes);
    snprintf(argv[4], 100, "%lld", low_vnodes);

    status = AuthorizationExecuteWithPrivileges(authorization,
						"/usr/arla/bin/fs",
						0, argv, &output);
    if (status == noErr) {
        drainfile(output);
        fclose(output);
	drainproc();
        return 0;
    } else {
        return -1;
    }

    return 0;
}

@implementation DataSource

NSMutableArray *authArray;
NSMutableArray *showArray;
NSMutableArray *cellArray;

- (int) numberOfRowsInTableView:(NSTableView *) aTableView {
    return [ authArray count ];
}

- (id)tableView:(NSTableView *)tableView objectValueForTableColumn:(NSTableColumn *)tableColumn row:(int) row {
    if (tableColumn == authColumn)
        return [ authArray objectAtIndex: row ];
    else if (tableColumn == showColumn)
        return [ showArray objectAtIndex: row ];
    else if (tableColumn == cellNameColumn)
        return [ cellArray objectAtIndex: row ];
    else
        return nil;
}

- (void)tableView:(NSTableView *)aTableView setObjectValue:(id)anObject forTableColumn:(NSTableColumn *)aTableColumn
row:(int)row {
    if (aTableColumn == authColumn) {
        NSTableView *t = tableView;
        NSNumber *value = anObject;
        [ authArray replaceObjectAtIndex: row withObject: anObject ];
        [controller authChanged];
        if ([value intValue] == NSOnState) {
            [ showArray replaceObjectAtIndex: row withObject: anObject ];
            [controller showChanged];
        }
        [ t reloadData ];
    }
    else if (aTableColumn == showColumn)  {
        [ showArray replaceObjectAtIndex: row withObject: anObject ];
        [controller showChanged];
    }
    else if (aTableColumn == cellNameColumn) {
        [ cellArray replaceObjectAtIndex: row withObject: anObject ];
    }
}

- (void) awakeFromNib {
    NSButtonCell *aCell = [ [NSButtonCell alloc] init ];
    NSTableView *t = tableView;

    [aCell setButtonType: NSSwitchButton ];
    [aCell setTitle: @""];

    [authColumn setDataCell: aCell];
    [showColumn setDataCell: aCell];
    [aCell release];
    
    authArray = [ [NSMutableArray alloc] init ];
    showArray = [ [NSMutableArray alloc] init ];
    cellArray = [ [NSMutableArray alloc] init ];
    
    [ReadCells auth: authArray show: showArray cell: cellArray];
    [ t reloadData ];
}

- (void)addRowWithAuth: (NSNumber*)auth show: (NSNumber*)show cell: (NSString*)cell {
    [ authArray addObject: auth ];
    [ showArray addObject: show ];
    [ cellArray addObject: cell ];
    [ controller authChanged];
    [ controller showChanged];
}

- (void)deleteRow:(unsigned)row {
    [ authArray removeObjectAtIndex: row ];
    [ showArray removeObjectAtIndex: row ];
    [ cellArray removeObjectAtIndex: row ];    
}

- (NSString *)getDataForArray: anArray {
    NSNumber *aNumber;
    NSString *resultString;
    int i;
    int count;

    count = [anArray count];

    resultString = @"";

    for (i = 0; i < count; i++) {
        aNumber = [anArray objectAtIndex: i];
        if ([aNumber intValue] == NSOnState) {
            resultString = [resultString stringByAppendingString: [cellArray objectAtIndex: i]];
            resultString = [resultString stringByAppendingString: @"\n"];
        }
    }
    
    return resultString;
}

- (OSStatus) fetchData: (NSMutableString *) data file: (char *) file auth: (AuthorizationRef) authorization {
    char *argv[2];
    OSStatus status;
    FILE *output;
    char buffer[1000];
    int n;

    argv[0] = file;
    argv[1] = NULL;

    status = AuthorizationExecuteWithPrivileges(authorization, "/bin/cat", 0, argv, &output);
    if (status == noErr) {
        n = fread(buffer, 1, sizeof(buffer) - 1, output);
        if (n == 0) {
            fclose(output);
            return -1;
        }
        buffer[n] = '\0';
        fclose(output);
	drainproc();
	[data appendString: [[NSString alloc] initWithCString: buffer]];
        return 0;
    } else {
        return -1;
    }
}

- (OSStatus) storeData: (NSString *) data file: (char *) file auth: (AuthorizationRef) authorization {
    const char *s;
    char *argv[2];
    OSStatus status;
    FILE *output;

    argv[0] = file;
    argv[1] = NULL;

    status = AuthorizationExecuteWithPrivileges(authorization, "/usr/bin/tee", 0, argv, &output);
    if (status == noErr) {
        s = [data cString];
        fwrite(s, [data length], 1, output);
        fclose(output);
	drainproc();
        return noErr;
    } else {
        return status;
    }
}

- (OSStatus)saveShowData: (AuthorizationRef) authorization {
    NSString *data;
    data = [self getDataForArray: showArray];
    return [self storeData: data file: "/usr/arla/etc/DynRootDB" auth: authorization];
}

- (OSStatus)saveAuthData: (AuthorizationRef) authorization {
    NSString *data;
    data = [self getDataForArray: authArray];
    return [self storeData: data file: "/usr/arla/etc/TheseCells" auth: authorization];
}

- (NSDictionary *) parseConfLine: (const char *) line {
    char *save = NULL;
    char *n;
    char *v;
    long long val;
    char *endptr;
    char *line1;
    NSDictionary *dict;
    
    if (line[0] == '#')
	return nil;
    
    line1 = strdup(line);
    if (line1 == NULL)
	return nil;
    
    n = strtok_r (line1, " \t", &save);
    if (n == NULL) {
	free(line1);
	return nil;
    }
    
    v = strtok_r (NULL, " \t", &save);
    if (v == NULL) {
	free(line1);
	return nil;
    }
    
    /* parse_units is currently broken, so we roll our own for now */
    val = strtoll(v, &endptr, 0);
    
    if (endptr == v) {
	free(line1);
	return nil;
    }

    if (*endptr != '\0') {
	struct units *u = size_units;
	
	while (u->name != NULL) {
	    if (!strcmp(endptr, u->name)) {
		val *= u->mult;
		break;
	    }
	    u++;
	}
    }

    dict = [NSDictionary dictionaryWithObject: [NSNumber numberWithLongLong: val]
			 forKey: [NSString stringWithCString: n]];
    free(line1);
    return dict;
}

- (void)parseConf: (NSString *) data dict: (NSMutableDictionary *) dict {
    NSRange curRange;
    NSRange nextRange;
    NSMutableCharacterSet *newLine;
    NSDictionary *linedict;

    unsigned length = [data length];

    newLine = [[NSMutableCharacterSet alloc] init];
    [newLine addCharactersInString: @"\n"];

    curRange.location = 0;
    while(1) {
	curRange.length = length - curRange.location;
	nextRange = [data rangeOfCharacterFromSet: newLine
			  options: NSLiteralSearch
			  range: curRange];
	if (nextRange.length == 0)
	    break;
	curRange.length = nextRange.location - curRange.location;
	linedict = [self parseConfLine:
			     [[data substringWithRange: curRange] cString]];
	if (dict)
	    [dict addEntriesFromDictionary: linedict];

	curRange.location = nextRange.location + nextRange.length;
    }
}

- (void)writeConf: (NSMutableString *) data dict: (NSDictionary *) dict {
    
    NSEnumerator *enumerator = [dict keyEnumerator];
    NSString *key;
    
    while ((key = [enumerator nextObject])) {
	[data appendString: [NSString stringWithFormat: @"%s %lld\n",
				      [key cString],
				      [[dict objectForKey: key] longLongValue]]];
    }
}

- (OSStatus)getCache: (AuthorizationRef) authorization
	    maxBytes: (int64_t *) maxBytes minBytes: (int64_t *) minBytes
	    maxFiles: (int64_t *) maxFiles minFiles: (int64_t *) minFiles
	    curBytes: (int64_t *) curBytes curFiles: (int64_t *) curFiles {
    NSMutableString *data;
    NSMutableDictionary *dict;

    if (getcache(maxBytes, curBytes, minBytes, maxFiles, curFiles, minFiles) == 0)
	return 0;

    data = [[[NSMutableString alloc] init] autorelease];
    dict = [[[NSMutableDictionary alloc] init] autorelease];

    [self fetchData: data file: "/usr/arla/etc/arla.conf" auth: authorization];

    [self parseConf: data dict: dict];
    
    *maxBytes = [[dict objectForKey: @"high_bytes"] longLongValue];
    *minBytes = [[dict objectForKey: @"low_bytes"] longLongValue];
    *maxFiles = [[dict objectForKey: @"high_vnodes"] longLongValue];
    *minFiles = [[dict objectForKey: @"low_vnodes"] longLongValue];
    *curBytes = 0;
    *curFiles = 0;

    return 0;
}
    

- (OSStatus)saveConfData: (AuthorizationRef) authorization
		maxBytes: (long long) maxBytes
		minBytes: (long long) minBytes
		maxFiles: (long long) maxFiles
		minFiles: (long long) minFiles
	     startAtBoot: (int) startAtBoot {
    NSMutableString *data;
    NSMutableDictionary *dict;

    data = [[NSMutableString alloc] init];
    dict = [[NSMutableDictionary alloc] init];

    [self fetchData: data file: "/usr/arla/etc/arla.conf" auth: authorization];

    [self parseConf: data dict: dict];

    [data setString: @""];

    [dict setObject: [NSNumber numberWithLongLong: maxBytes]
	  forKey: @"high_bytes"];
    [dict setObject: [NSNumber numberWithLongLong: minBytes]
	  forKey: @"low_bytes"];
    [dict setObject: [NSNumber numberWithLongLong: maxFiles]
	  forKey: @"high_vnodes"];
    [dict setObject: [NSNumber numberWithLongLong: minFiles]
	  forKey: @"low_vnodes"];
    
    [self writeConf: data dict: dict];
    
    [self storeData: data file: "/usr/arla/etc/arla.conf" auth: authorization];

    setcache(maxBytes, minBytes, maxFiles, minFiles, authorization);

    if (startAtBoot)
	[self storeData: @"yes" file: "/usr/arla/etc/startatboot"
	      auth: authorization];
    else
	[self storeData: @"no" file: "/usr/arla/etc/startatboot"
	      auth: authorization];

    return 0;
}

- (int) getStartAtBoot: (AuthorizationRef) authorization {
    NSMutableString *data;
    OSStatus status;

    data = [[[NSMutableString alloc] init] autorelease];

    status = [self fetchData: data
		   file: "/usr/arla/etc/startatboot"
		   auth: authorization];
    if (status)
	return 0;
    if (strcmp([data cString], "yes") == 0)
	return 1;
    return 0;
}

+ (int) getDaemonStatus: (AuthorizationRef) authorization {
    int ret;
    char buffer[1000];

    ret = getdaemonpid(authorization, buffer, sizeof(buffer));
    if (ret == -1)
        return -1;

    ret = checkdaemonpid(authorization, buffer);
    return ret;
}

+ (void) startDaemon: (AuthorizationRef) authorization {
    int i;
    struct timeval t;

    mkafsdir(authorization);
    kmodload(authorization);
    startarlad(authorization);
    for (i = 0; i < 40; i++) {
	if ([self getDaemonStatus: authorization] == 1)
	    break;
	t.tv_sec = 0;
	t.tv_usec = 250000;
	select(0, NULL, NULL, NULL, &t);
    }
    nnpfs_mount(authorization);
}

+ (void) stopDaemon: (AuthorizationRef) authorization {
    nnpfs_umount(authorization);
    stoparlad(authorization);
    kmodunload(authorization);
}


@end
