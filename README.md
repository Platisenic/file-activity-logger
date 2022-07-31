# logger-library-injection
## Monitor File Activities of Dynamically Linked Programs
For practicing library injection and API hijacking, I implement a simple logger program that can show file-access-related activities of an arbitrary binary running on a Linux operating system.  
The program is divided in two parts. One is a logger program that prepares the runtime environment to inject, load, and execute a monitored binary program.  
The other is a shared object that can be injected into a program by the logger using LD_PRELOAD.  
## How to use
1. Build the source code
```bash
make
```
2. Usage of logger
``` 
$ ./logger
usage: ./logger [-o file] [-p sopath] [--] cmd [cmd args ...]
        -p: set the path to logger.so, default = ./logger.so
        -o: print output to file, print to "stderr" if no file specified
        --: separate the arguments for logger and for the command
```
## Sample Usage
Monitor file activities of ls
```
$ ./logger ls
[logger] fopen("/proc/filesystems", "re") = 0x5573eda9ec00
[logger] fclose("/proc/filesystems") = 0
hw2.c  logger  logger.c  logger.so  Makefile
[logger] fclose("/dev/pts/1") = 0
[logger] fclose("/dev/pts/1") = 0
```
```
$ ./logger ls 2>/dev/null
hw2.c  logger  logger.c  logger.so  Makefile
```
```
$ ./logger -o ls_al.txt -- ls -al
total 92
drwxrwxr-x 3 libos libos  4096  七  31 18:03 .
drwxrwxr-x 7 libos libos  4096  七  31 17:58 ..
drwxrwxr-x 8 libos libos  4096  七  31 17:58 .git
-rw-rw-r-- 1 libos libos     8  七  31 17:58 .gitignore
-rw-rw-r-- 1 libos libos 11349  七  31 17:58 hw2.c
-rwxrwxr-x 1 libos libos 20328  七  31 17:58 logger
-rw-rw-r-- 1 libos libos  2180  七  31 17:58 logger.c
-rwxrwxr-x 1 libos libos 29768  七  31 17:58 logger.so
-rw-rw-r-- 1 libos libos   100  七  31 18:03 ls_al.txt
-rw-rw-r-- 1 libos libos   504  七  31 17:58 Makefile
$ cat ls_al.txt
[logger] fopen("/proc/filesystems", "re") = 0x55e688f32c00
[logger] fclose("/proc/filesystems") = 0
[logger] fclose("/dev/pts/1") = 0
[logger] fclose("/dev/pts/1") = 0
```

