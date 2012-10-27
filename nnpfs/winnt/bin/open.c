
#include <windows.h>
#include "../inc/nnpfs_ioctl.h"

int main (int argc, char **argv)
{
    HANDLE fh;
    unsigned char msg[4000];
    DWORD nread;
    DWORD out = IOCTL_NNPFS_PUTMSG;

    if (argc != 1)
      out = IOCTL_NNPFS_GETMSG;

    if (!DefineDosDevice(DDD_RAW_TARGET_PATH,
			 "nnpfsdev",
			 "\\Device\\NNPFS")) {
	printf ("error creating device file\n");
	goto clean;
    }
    

    fh = CreateFile ("\\\\.\\nnpfsdev", 
		     GENERIC_READ|GENERIC_WRITE,
		     FILE_SHARE_READ|FILE_SHARE_WRITE , NULL,
		     OPEN_EXISTING, 0, NULL);

    if (fh == INVALID_HANDLE_VALUE) {
	LPVOID lpMsgBuf;
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | 
		      FORMAT_MESSAGE_FROM_SYSTEM | 
		      FORMAT_MESSAGE_IGNORE_INSERTS,
		      NULL,
		      GetLastError(),
		      MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		      (LPTSTR) &lpMsgBuf,
		      0,
		      NULL);
#if 0
	MessageBox( NULL, (LPCTSTR)lpMsgBuf, "Error", 
		    MB_OK | MB_ICONINFORMATION );
#else
	printf ("error: %s\n", lpMsgBuf);
#endif
	// Free the buffer.
	LocalFree( lpMsgBuf );
	goto clean;
    }
    printf ("opened file ok\n");

    if (!DeviceIoControl(fh,
			 out,
			 NULL,
			 0,
			 msg,
			 sizeof(msg)-1,
			 &nread,
			 NULL)) {
	printf ("DeviceIoControl failed with %d\n", GetLastError());
    }

    CloseHandle (fh);

 clean:
    
#if 0
    if (!DefineDosDevice(DDD_REMOVE_DEFINITION|DDD_EXACT_MATCH_ON_REMOVE,
			 "\\\\.\\nnpfsdev",
			 NULL))
	printf ("define dos drive (remove) failed: %d\n", GetLastError());
#endif


    return 0;
}
