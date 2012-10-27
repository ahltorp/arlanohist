#ifndef _nnpfs_dev_h
#define _nnpfs_dev_h

#include <nnpfs/nnpfs_common.h>
#include <sys/uio.h>

extern int nnpfs_devopen _PARAMS((dev_t dev, int flags));
extern int nnpfs_devclose _PARAMS((dev_t dev, int flags));
extern int nnpfs_devread _PARAMS((dev_t dev, struct uio *uiop));
extern int nnpfs_devwrite _PARAMS((dev_t dev, struct uio *uiop));
extern int nnpfs_devioctl _PARAMS((dev_t dev, int cmd, caddr_t data, int flags));
extern int nnpfs_devselect _PARAMS((dev_t dev, int rw));

extern int nnpfs_install_device _PARAMS((void));
extern int nnpfs_uninstall_device _PARAMS((void));

extern int nnpfs_install_filesys _PARAMS((void));
extern int nnpfs_uninstall_filesys _PARAMS((void));

extern int nnpfs_install_syscalls _PARAMS((void));
extern int nnpfs_uninstall_syscalls _PARAMS((void));

extern int nnpfs_vdstat_filesys _PARAMS((void));
extern int nnpfs_vdstat_syscalls _PARAMS((void));
extern int nnpfs_vdstat_device _PARAMS((void));

extern int nnpfs_message_send _PARAMS((int fd,
				    struct nnpfs_message_header *message,
				    u_int size));

extern int nnpfs_message_rpc _PARAMS((int fd,
				    struct nnpfs_message_header *message,
				    u_int size));

extern int nnpfs_message_receive _PARAMS((int fd,
					struct nnpfs_message_header *message,
					u_int size));

extern int nnpfs_message_wakeup _PARAMS((int fd,
				       struct nnpfs_message_wakeup *message,
				       u_int size));

extern int
nnpfs_message_wakeup_data _PARAMS((int fd,
				 struct nnpfs_message_wakeup_data *message,
				 u_int size));

#endif /* _nnpfs_dev_h */
