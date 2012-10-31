#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <err.h>
#include <roken.h>
#include <atypes.h>

#ifdef KERBEROS

#include <kafs.h>

int
main(int argc, char **argv)
{
    int fd;

    setprogname (argv[0]);

    if (!k_hasafs())
	errx (1, "no afs");

    fd = open ("foo", O_RDWR|O_CREAT, 0666);
    if (fd < 0)
	err (1, "open");

    dup2 (fd + 1, fd);
    
    if (write (fd, "foo\n", 4) != 4)
	errx (1, "write");

    k_unlog();

    close (fd);
    close (fd + 1);

    exit (0);
}

#else /* !KERBEROS */

int
main (int argc, char **argv)
{
    setprogname (argv[0]);

    errx (1, "no kafs");
}

#endif /* !KERBEROS */
