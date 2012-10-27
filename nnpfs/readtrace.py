#!/usr/bin/python

import struct
import sys
import time

byteorder = "="
no_offset = 2**64-1

def print_offset(offset):
	if offset == no_offset:
		return "NNPFS_NO_OFFSET"
	return "%u" % offset

def print_handle(handle):
	(a, b, c, d) = struct.unpack(byteorder + "LLLL", handle)
	return "(%d, %d, %d, %d)" % (a, b, c, d)

def print_block_handle(handle):
	(a, b, c, d) = struct.unpack(byteorder + "LLLL", handle[0:16])
	(offset, ) = struct.unpack(byteorder + "Q", handle[16:24])
	return "(%d, %d, %d, %d) @%s" % (a, b, c, d, print_offset(offset))

def print_asciz(s):
	return "\"" + s.split("\0", 1)[0] + "\""

def print_time(sec):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(sec))

def print_valid(s, valid, shift):
	mask = 1 << shift
	if valid & mask == mask:
		return s
	else:
		return "(" + s + ")"

def print_attr(data):
	(valid,mode,nlink,type,uid,gid,atime,mtime,ctime,fileid,size) = struct.unpack(byteorder + "LLLLLLLLLLQ", data)
	l1 = []
	l2 = []
	l1.append(print_valid("mode %o" % mode, valid, 0))
	l1.append(print_valid("lnks %d" % nlink, valid, 1))
	l1.append(print_valid("type %d" % type, valid, 2))
	l1.append(print_valid("uid %d" % uid, valid, 3))
	l1.append(print_valid("gid %d" % gid, valid, 4))
	l1.append(print_valid("fid %d" % fileid, valid, 8))
	l1.append(print_valid("size %d" % size, valid, 9))

	l2.append(print_valid("atime %s" % print_time(atime), valid, 5))
	l2.append(print_valid("mtime %s" % print_time(mtime), valid, 6))
	l2.append(print_valid("ctime %s" % print_time(ctime), valid, 7))
	if len(l1) > 0:
		return (" ".join(l1), " ".join(l2))
	else:
		return (" ".join(l2), "")

def print_right(right):
	s = ""
	if (right & 0x1) == 0x1:
		s = s + "r"
	if (right & 0x2) == 0x2:
		s = s + "w"
	if (right & 0x4) == 0x4:
		s = s + "x"
	if s == "":
		s = "none"
	return s

def print_rights(iddata, rightsdata):
	ids = struct.unpack(byteorder + "8L", iddata)
	rights = struct.unpack(byteorder + "8H", rightsdata)
	ret = []
	for id, right in zip(ids, rights):
		if (id != 4):
			ret.append("%d:%s" % (id, print_right(right)))
	return " ".join(ret)

def bitfield_print(field, template):
	s = []
	for (bit, t) in template:
		if (field & bit) == bit:
			s.append(t)
	return s

def print_tokens(tokens):
	template = [
		(0x0001, "NR"),
		(0x0002, "SR"),
		(0x0004, "NW"),
		(0x0008, "EW"),
		(0x0010, "A_R"),
		(0x0020, "A_W"),
		(0x0040, "D_R"),
		(0x0080, "D_W"),
		(0x0100, "L_R"),
		(0x0200, "L_W")
		]
	return "|".join(bitfield_print(tokens, template))

def print_node(data):
	handle = print_handle(data[0:16])
	(tokens,pad1) = struct.unpack(byteorder + "LL", data[16:24])
	(attr1, attr2) = print_attr(data[24:72])
	rights = print_rights(data[72:104], data[104:120])
	(anonrights,) = struct.unpack(byteorder + "H", data[120:122])
	anonrights_str = print_right(anonrights)
	return ("handle %s tokens %s anonrights %s rights %s" % (handle, print_tokens(tokens), anonrights_str, rights), attr1, attr2)

def process_wakeup(data):
	(seqno, error, len) = struct.unpack(byteorder + "LLL", data[0:12])
	print "wakeup seqno", seqno, "error", error

def process_getroot(data):
	(uid, pag) = struct.unpack(byteorder + "LL", data[0:8])
	print "getroot uid", uid, "pag", pag

def process_getnode(data):
	(uid, pag) = struct.unpack(byteorder + "LL", data[0:8])
	handle = print_handle(data[8:24])
	name = data[24:]
	print "getnode uid", uid, "pag", pag, "parenthandle", handle, "name", print_asciz(name)

def process_inactivenode(data):
	handle = print_handle(data[0:16])
	(flag,) = struct.unpack(byteorder + "L", data[16:20])
	flagtexts = []
	if (flag & 0x1):
		flagtexts.append("norefs")
	if (flag & 0x2):
		flagtexts.append("delete")
	print "inactivenode handle", handle, "flags", "|".join(flagtexts)

def process_open(data):	
	(uid, pag) = struct.unpack(byteorder + "LL", data[0:8])
	handle = print_handle(data[8:24])
	(tokens, ) = struct.unpack(byteorder + "L", data[24:28])
	print "open uid", uid, "pag", pag, "handle", handle, "tokens", print_tokens(tokens)

def process_version(data):
	print "version"

def process_installroot(data):
	(line1, line2, line3) = print_node(data[0:128])
	print "installroot " + line1
	print "      " + line2
	print "      " + line3

def process_installnode(data):
	handle = print_handle(data[0:16])
	name = print_asciz(data[16:272])
	(line1, line2, line3) = print_node(data[272:400])
	print "installnode parenthandle %s name %s" % (handle, name)
	print "      " + line1
	print "      " + line2
	print "      " + line3

def process_getdata(data):
	(uid, pag) = struct.unpack(byteorder + "LL", data[0:8])
	handle = print_handle(data[8:24])
	(tokens, pad1) = struct.unpack(byteorder + "LL", data[24:32])
	(offset, len) = struct.unpack(byteorder + "QQ", data[32:48])
	print "getdata uid", uid, "pag", pag, "handle", handle, "tokens", print_tokens(tokens)
	print "offset", offset, "len", len

def process_installdata(data):
	# don't print cache handle
	(line1, line2, line3) = print_node(data[0:128])
	(flag, id) = struct.unpack(byteorder + "LL", data[128:136])
	(offset,) = struct.unpack(byteorder + "Q", data[136:144])
	off = print_offset(offset)
	template = [
		(0x0001, "INVALID_DNLC"),
		(0x0002, "AFSDIR"),
		(0x0004, "HANDLE_VALID")
		]
	print "installdata " + line1
	print "      " + line2
	print "      " + line3
	print "      flag", "|".join(bitfield_print(flag, template)), "offset", off, "id", id

def process_deletenode(data):
	handle = print_handle(data[0:16])
	print "deletenode handle", handle

def process_putdata(data):
	handle = print_handle(data[0:16])
	(attr1, attr2) = print_attr(data[16:64])
	(uid, pag) = struct.unpack(byteorder + "LL", data[64:72])
	(flag, pad1) = struct.unpack(byteorder + "LL", data[72:80])
	(offset, len) = struct.unpack(byteorder + "QQ", data[80:96])
	print "putdata handle", handle, "offset", offset, "len", len
	print "uid", uid, "pag", pag, "flag", flag
	print "      " + attr1
	print "      " + attr2

def process_create(data):
	handle = print_handle(data[0:16])
	name = print_asciz(data[16:272])
	(attr1, attr2) = print_attr(data[272:320])
	(mode, pad1) = struct.unpack(byteorder + "LL", data[320:328])
	(uid, pag) = struct.unpack(byteorder + "LL", data[328:336])
	print "create parent", handle, "mode", mode, "uid", uid, "pag", pag, "name", name
	print "      " + attr1
	print "      " + attr2

def process_putattr(data):
	handle = print_handle(data[0:16])
	(attr1, attr2) = print_attr(data[16:64])
	(uid, pag) = struct.unpack(byteorder + "LL", data[64:72])
	print "putattr handle", handle, "uid", uid, "pag", pag
	print "      " + attr1
	print "      " + attr2

def process_installattr(data):
	(line1, line2, line3) = print_node(data[0:128])
	(flag, pad1) = struct.unpack(byteorder + "LL", data[128:136])
	print "installattr " + line1
	print "      " + line2
	print "      " + line3
	print "      flag", flag

def process_getattr(data):
	(uid, pag) = struct.unpack(byteorder + "LL", data[0:8])
	handle = print_handle(data[8:24])
	print "getattr handle", handle, "uid", uid, "pag", pag

def process_invalidnode(data):
	handle = print_handle(data[0:16])
	print "invalidnode handle", handle

def process_mkdir(data):
	handle = print_handle(data[0:16])
	name = print_asciz(data[16:272])
	(attr1, attr2) = print_attr(data[272:320])
	(uid, pag) = struct.unpack(byteorder + "LL", data[320:328])
	print "mkdir parent", handle, "uid", uid, "pag", pag, "name", name
	print "      " + attr1
	print "      " + attr2

def process_link(data):
	parenthandle = print_handle(data[0:16])
	name = print_asciz(data[16:272])
	fromhandle = print_handle(data[272:288])
	(uid, pag) = struct.unpack(byteorder + "LL", data[288:296])
	print "link parent", parenthandle, "fromhandle", fromhandle, "name", name

def process_symlink(data):
	parenthandle = print_handle(data[0:16])
	name = print_asciz(data[16:272])
	content = print_asciz(data[272:2320])
	(attr1, attr2) = print_attr(data[2320:2368])
	(uid, pag) = struct.unpack(byteorder + "LL", data[2368:2376])
	print "symlink parent", parenthandle, "uid", uid, "pag", pag
	print "      " + name + "->" + content
	print "      " + attr1
	print "      " + attr2

def process_remove(data):
	parenthandle = print_handle(data[0:16])
	name = print_asciz(data[16:272])
	(uid, pag) = struct.unpack(byteorder + "LL", data[272:280])
	print "remove parent", parenthandle, "uid", uid, "pag", pag, "name", name

def process_rmdir(data):
	parenthandle = print_handle(data[0:16])
	name = print_asciz(data[16:272])
	(uid, pag) = struct.unpack(byteorder + "LL", data[272:280])
	print "rmdir parent", parenthandle, "uid", uid, "pag", pag, "name", name

def process_rename(data):
	oldparenthandle = print_handle(data[0:16])
	oldname = print_asciz(data[16:272])
	newparenthandle = print_handle(data[272:288])
	newname = print_asciz(data[288:544])
	(uid, pag) = struct.unpack(byteorder + "LL", data[544:552])
	print "rename oldparent", oldparenthandle, "oldname", oldname
	print "      newparent", newparenthandle, "newname", newname
	print "      uid", uid, "pag", pag

def ioctl_decode(opcode):
	nr = opcode & 0xff
	type = (opcode >> 8) & 0xff
	size = (opcode >> 16) & 0x3fff
	dir = (opcode >> 30) & 0x3
	if (type > 64 and type < 91):
		typeprint = "%d(%s)" % (type, chr(type))
	else:
		typeprint = "%d" % type
	return (nr, type, typeprint, size, dir)

def pioctl_settok(data):
	return "settok"

def pioctl_flush(data):
	return "flush"

def pioctl_afs_delete_mt_pt(data):
	return "afs_delete_mt_pt"

def pioctl_getfid(data):
	return "getfid"

def pioctl_file_cell_name(data):
	return "file_cell_name"

def print_pioctl(opcode, data):
    try:
	return {(3, 86, 12, 1): pioctl_settok,
		(6, 86, 12, 1): pioctl_flush,
		(22, 86, 12, 1): pioctl_getfid,
		(30, 86, 12, 1): pioctl_file_cell_name,
		(28, 86, 12, 1): pioctl_afs_delete_mt_pt} [opcode] (data)
    except KeyError:
	return "        Unknown opcode" + str(opcode)

def process_pioctl(data):
	(opcode, pad1) = struct.unpack(byteorder + "LL", data[0:8])
	(uid, pag) = struct.unpack(byteorder + "LL", data[8:16])
	(insize, outsize) = struct.unpack(byteorder + "LL", data[16:24])
	msg = data[24:2072]
	handle = print_handle(data[2072:2088])
	print "pioctl opcode %08x uid %d pag %d insize %d outsize %d" % (opcode, uid, pag, insize, outsize)
	print "      handle", handle
	if 0:
		# this is linux specific now
		(nr, type, typeprint, size, dir) = ioctl_decode(opcode)
		print "      type", typeprint, "nr", nr, "size", size, "dir", dir
		print "      " + print_pioctl((nr, type, size, dir), msg)
	s = []
	for i in msg[0:insize]:
		s.append("%02x" % ord(i))
	while len(s) > 8:
		print "      " + " ".join(s[0:8])
		s = s[8:]
	print "      " + " ".join(s)

def process_updatefid(data):
	oldhandle = print_handle(data[0:16])
	newhandle = print_handle(data[16:32])
	print "updatefid oldhandle %s newhandle %s" % (oldhandle, newhandle)

def process_advlock(data):
	print "advlock"

def process_gc(data):
	(len, pad) = struct.unpack(byteorder + "LL", data[0:8])
	print "gc, len", len
	offset = 8
	count = 0
	while count < len:
		print print_block_handle(data[offset:offset+24])
		offset = offset + 24
		count = count + 1

def process_appenddata(data):
	handle = print_block_handle(data[0:24])
	print "appenddata", handle

def process_deletedata(data):
	handle = print_block_handle(data[0:24])
	print "deletedata", handle

def process_accesses(data):
	print "accesses"

def process_installquota(data):
	(appendquota,) = struct.unpack(byteorder + "Q", data[0:8])
	print "installquota", "append", appendquota

def process_message(size, opcode, seqno, data):
    sys.stdout.write (" %4d:" % seqno)
    try:
	{	0: process_version,
		1: process_wakeup,
		2: process_getroot,
		3: process_installroot,
		4: process_getnode,
		5: process_installnode,
		6: process_getattr,
		7: process_installattr,
		8: process_getdata,
		9: process_installdata,
		10: process_inactivenode,
		11: process_invalidnode,
		12: process_open,
		13: process_putdata,
		14: process_putattr,
		15: process_create,
		16: process_mkdir,
		17: process_link,
		18: process_symlink,
		19: process_remove,
		20: process_rmdir,
		21: process_rename,
		22: process_pioctl,
		23: process_updatefid,
		24: process_advlock,
		25: process_gc,
		26: process_deletenode,
		27: process_appenddata,
		28: process_deletedata,
		29: process_accesses,
		30: process_installquota} [opcode] (data)
    except KeyError:
	print "        Unknown opcode", opcode

while 1:
    data = sys.stdin.read(16)
    if len(data) != 16:
	break
    (type, sec, usec, length) = struct.unpack('!LLLL', data)
    if type == 0x00000001:
    	typetext = "nnpfs"
	byteorder = ">"
    elif type == 0x00000002:
	typetext = "arlad"
	byteorder = ">"
    elif type == 0x01000000:
    	typetext = "nnpfs"
	byteorder = "<"
    elif type == 0x02000000:
	typetext = "arlad"
	byteorder = "<"
    else:
	sys.exit(1)

    print time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(sec)) + ".%06d" % usec, typetext, "len", length
    messages = sys.stdin.read(length)
    if len(messages) != length:
	break
    while messages:
	header = messages[0:16]
	(size, opcode, seqno, pad1) = struct.unpack(byteorder + "LLLL", header)
	message = messages[0:size]
	process_message(size, opcode, seqno, message[16:])
	print
	messages = messages[size:]
