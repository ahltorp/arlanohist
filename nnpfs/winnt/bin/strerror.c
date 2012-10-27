#include <windows.h>

int
main (int argc, char **argv)
{
    LPVOID lpMsgBuf;
    int num;

    if (argc != 2) {
	printf ("usage: %s number\n", argv[0]);
	exit(1);
    }
    
    num = atoi (argv[1]);
    if (num == 0) {
	printf ("invalid number 0\n");
	exit (1);
    }

    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | 
		  FORMAT_MESSAGE_FROM_SYSTEM | 
		  FORMAT_MESSAGE_IGNORE_INSERTS,
		  NULL,
		  num,
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
    exit (1);
}
