#	$Id: linux.gdb,v 1.1 2002/01/26 07:04:27 lha Exp $

# To: linux-kernel
# From: "Andi Kleen" <ak@suse.de> 
# Date: Tue, 8 Aug 2000 04:25:33 +0200
#
# ... "compile a vmlinux with debugging symbols (-g),
# do gdb vmlinux /proc/kcore" ...
# ... "display its tss.esp member and backtrace from that."


define xps 
set $inittask = &(init_task_union.task) 
set $t = $inittask->next_task 
while $t != $inittask 
        output $t 
        output "\t" 
        output $t->pid 
        output "\t" 
        output $t->comm 
        echo 
        set $t = $t->next_task 
end 
end
