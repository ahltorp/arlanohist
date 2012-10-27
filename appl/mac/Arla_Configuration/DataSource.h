#import <Cocoa/Cocoa.h>
#include <Security/Authorization.h>
#include <Security/AuthorizationTags.h>

@interface DataSource : NSObject
{
    IBOutlet id authColumn;
    IBOutlet id cellNameColumn;
    IBOutlet id showColumn;
    IBOutlet id tableView;
    IBOutlet id controller;
}
- (void)addRowWithAuth: (NSNumber*)auth show: (NSNumber*)show cell: (NSString*)cell;
- (OSStatus)saveShowData: (AuthorizationRef) gAuthorization;
- (OSStatus)saveAuthData: (AuthorizationRef) gAuthorization;
- (OSStatus)saveConfData: (AuthorizationRef) authorization
		maxBytes: (long long) maxBytes
		minBytes: (long long) minBytes
		maxFiles: (long long) maxFiles
		minFiles: (long long) minFiles
	     startAtBoot: (int) startAtBoot;
- (int) getStartAtBoot: (AuthorizationRef) authorization;
+ (int) getDaemonStatus: (AuthorizationRef) gAuthorization;
+ (void) startDaemon: (AuthorizationRef) gAuthorization;
+ (void) stopDaemon: (AuthorizationRef) gAuthorization;
- (OSStatus)getCache: (AuthorizationRef) authorization
maxBytes: (int64_t *) maxBytes
minBytes: (int64_t *) minBytes
maxFiles: (int64_t *) maxFiles
minFiles: (int64_t *) minFiles
curBytes: (int64_t *) curBytes
curFiles: (int64_t *) curFiles;
@end
