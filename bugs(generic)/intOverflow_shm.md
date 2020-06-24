>This bug has a very low impact / not trivial at all. But it was fun detecting it and reporting it to PHP because it was one of my first bugs ever :D
>
>original report(bug #79427): https://bugs.php.net/bug.php?id=79427

## Integer overflow in shmop_open() 
When running the following PHP code:
```php
$shm_id = shmop_open(1337, "c", 0644, 100 ); 
```
It creates an entry in the operating system's SHM with 100 bytes in it and an ID of 1337. But if this ID is already taken so it opens the existing one and the ``size`` changes from ``100`` to the original SHM size. If the SHM size is bigger than ``INT_MAX``, an integer overflow occurs. 

## Analysis

* 1st+2nd commands: showing the ``shm`` structure in memory.

* 3rd+4th command: demonstrating the differences in the types (``shm->shm_segsz`` is actually ``size_t`` but gdb makes it easier by following the typedef of ``size_t``, which is ``unsigned int``)
```
(gdb) ptype shm
type = struct shmid_ds {
    struct ipc_perm shm_perm;
    size_t shm_segsz;
    __time_t shm_atime;
    long unsigned int __glibc_reserved1;
    __time_t shm_dtime;
    long unsigned int __glibc_reserved2;
    __time_t shm_ctime;
    long unsigned int __glibc_reserved3;
    __pid_t shm_cpid;
    __pid_t shm_lpid;
    shmatt_t shm_nattch;
    __syscall_ulong_t __glibc_reserved4;
    __syscall_ulong_t __glibc_reserved5;
}
(gdb) p shm
$1 = {shm_perm = {__key = 1337, uid = 1000, gid = 1000, cuid = 1000, cgid = 1000, mode = 420, __pad1 = 0, __seq = 9, __pad2 = 0, __glibc_reserved1 = 0, __glibc_reserved2 = 0},
  shm_segsz = 2147483652, shm_atime = 1585396834, __glibc_reserved1 = 0, shm_dtime = 1585398415, __glibc_reserved2 = 0, shm_ctime = 1585396778, __glibc_reserved3 = 0, shm_cpid = 12884,
  shm_lpid = 12897, shm_nattch = 0, __glibc_reserved4 = 0, __glibc_reserved5 = 0}

(gdb) ptype shm->shm_segsz
type = unsigned int 
(gdb) ptype shmop->size
type = int
```
right now, the size is what we init in the PHP code(100)
but the value that the operating system returned is ``INT_MAX+5``
```
(gdb) p shmop->size
$2 = 100
(gdb) p shm.shm_segsz
$3 = 2147483652
```
stepping to the next operation (``shmop->size = shm.shm_segsz; ``):
```
(gdb) next 
(gdb) p shmop->size 
$4 = -2147483644
```
an integer overflow occur.

It happens when ``kernel.shmmax``(Linux kernel parameter/setting) is greater than INT_MAX. Because of this, other functions like ``shmop_read`` can not be called because the structure is malformed with a negative number. This prevents PHP from accessing the OS's shared memory to get data.

## Steps to re-produce
so in order to re-produce this bug in linux systems, you'll have to run:
```
$ sysctl -w kernel.shmmax=2147483652
```

And create an SHM segment with a size bigger than INT_MAX:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <errno.h>

#define SHM_SIZE 2147483652  /* INT_MAX+5 */

int main(int argc, char *argv[])
{
    int shmid;
    key_t key;
    char *shm;
    char *s; 

    key = 1337;

    shmid = shmget(key, SHM_SIZE, IPC_CREAT | 0644);
    if(shmid < 0)
    {
        printf("error getting SHM id\n\n");
        puts(strerror(errno));
        exit(1);
    }

    shm = shmat(shmid, NULL, 0);
    strcpy((char *)shm, "AAAAAAAAAAAAAAAAAAAA"); //example buffer

    return 0;
}
```
run the above, and then to make sure the SHM entry was created, run:
```
shaq@ubuntu:~/Desktop/shm-php$ ipcs -m

------ Shared Memory Segments --------
key        shmid      owner      perms      bytes      nattch     status
0x00000539 327683     shaq      644        2147483652 0
```
and then run the test script (provided below)

```php
<?php
$shm_id = shmop_open(1337, "c", 0644, 100 );
echo "opened SHM handle...\n";
echo shmop_write($shm_id, "BBBB", 1) ? "Success" : "Failed";
shmop_close($shm_id);
?>
```

Expected result:
```
opened SHM handle...
Success
```
Actual result:
```
opened SHM handle...
PHP Warning:  shmop_write(): offset out of range in /home/shaq/Desktop/shm-php/poc.php on line 4
Failed
```