#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <fcntl.h>
#include <stdio.h>

#define BUFSIZE 2048

int
main(void) {
    const char *filename = "/afs/stacken.kth.se/test/TEXT.txt";
    struct stat stat_buf;
    char buf[BUFSIZE];
    int sockets[2];
    off_t offset;
    size_t len;
    int ret;
    int fd;
  
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) < 0) {
	perror("creating socketpair");
	exit(1);
    }
  
    fd = open(filename, O_RDONLY);
    if (fd == -1) {
	perror("opening file");
	exit(1);
    }
  
    fstat(fd, &stat_buf);

    offset = 0;
    len = stat_buf.st_size;

    assert(len < BUFSIZE);

    ret = sendfile(sockets[0], fd, &offset, len);
    if (ret == -1) {
	perror("sendfile");
	exit(1);
    }
    if (ret != len) {
	fprintf(stderr, "sendfile sent %d of %d bytes\n", ret, len);
	exit(1);
    }
    close(fd);
  
    ret = read(sockets[1], buf, BUFSIZE);
    if (ret == -1) {
	perror("read failed");
	exit(1);
    }
    if (ret != len) {
	fprintf(stderr, "read %d of %d bytes\n", ret, len);
	exit(1);
    }
    buf[len] = '\0';

    close(sockets[0]);
    close(sockets[1]);

    fprintf(stderr, "happy: sent and read %d bytes\n", ret);
    printf("%s\n", buf);

    return 0;
} 
