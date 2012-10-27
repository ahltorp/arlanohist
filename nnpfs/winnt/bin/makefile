# $Id: makefile,v 1.7 2002/10/29 22:10:25 tol Exp $

INC=-IC:\\ntddk\\inc -IC:\\ntddk\\inc\\ddk -I$(SRC)\\inc -I$(SRC)\\..\\include
CC=cl

all: open.exe strerror.exe mount_nnpfs.exe umount_nnpfs.exe \
	wakeup.exe nnpfs-helper.exe

{$(SRC)\bin}.c.exe:
	$(CC) $(INC) $<

nnpfs-helper.exe: $(SRC)\bin\nnpfs-helper.c
        $(CC) $(INC) $** /link ws2_32.lib

clean:
	rm -f *.obj *~ *.exe *.stackdump
