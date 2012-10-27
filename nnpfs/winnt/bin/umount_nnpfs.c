
#include <windows.h>
#include "../inc/nnpfs_ioctl.h"

int main (int argc, char **argv)
{
    HANDLE fh;

    if (!DefineDosDevice(DDD_REMOVE_DEFINITION, "G:", NULL)) {
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
	return 1;
    }
    return 0;
}
