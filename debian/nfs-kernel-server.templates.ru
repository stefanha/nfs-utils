Template: nfs-kernel-server/tcpwrappers-mountd
Type: note
Description: in /etc/hosts.{allow,deny}, replace "rpc.mountd" with "mountd"
 The mount daemon uses tcpwrappers to control access.  To configure
 it, use program name "mountd" in /etc/hosts.allow and /etc/hosts.deny.
 .
 Older versions of nfs-kernel-server included a mount daemon that
 called itself "rpc.mountd".  Therefore, you should replace all
 occurrences of "rpc.mountd" with "mountd" in /etc/hosts.allow and
 /etc/hosts.deny.
Description-ru: Замените в /etc/hosts.{allow,deny} "rpc.mountd" на "mountd"
 Демон  монтирования  использует  для управления доступом tcp-врапперы.
 Чтобы  их  настроить,  используйте  имя  "mountd"  в /etc/hosts.allow и
 /etc/hosts.deny.
 .
 Более  старые  версии  nfs-kernel-server  включали демон монтирования,
 который  называл  себя  "rpc.mountd".  Поэтому, вы должны заменить все
 вхождения   "rpc.mountd"  на  "mountd"  в  файлах  /etc/hosts.allow  и
 /etc/hosts.deny.
