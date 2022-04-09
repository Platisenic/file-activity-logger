#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#include <unistd.h>
#include <ctype.h>
#include <gnu/lib-names.h>

int getlogfd() {
    char *fd_str = getenv("LOGGER_FD");
    int fd_int = 0;
    if(fd_str == NULL) return STDERR_FILENO;
    while(*fd_str){
        fd_int=((*fd_str)-'0') + fd_int*10;
        fd_str++;
    }
    return fd_int;
}

static int (*ori_rename)(const char *, const char *) = NULL;
int rename(const char *oldpath, const char *newpath) {
    if(ori_rename == NULL) {
        void *handle = dlopen(LIBC_SO, RTLD_LAZY);
        if(handle == NULL) return -1;
        if((ori_rename = (int(*)(const char *, const char *))dlsym(handle, "rename")) == NULL) {
            return -1;
        }
    }

    char real_oldpath[1024];
    char real_newpath[1024];
    if(realpath(oldpath, real_oldpath) == NULL) {
        strcpy(real_oldpath, oldpath);
    }
    if(realpath(newpath, real_newpath) == NULL) {
        strcpy(real_newpath, newpath);
    }

    int ret = ori_rename(oldpath, newpath);
    dprintf(getlogfd(), "[logger] rename(\"%s\", \"%s\") = %d\n", real_oldpath, real_newpath, ret);
    return ret;
}

static int (*ori_remove)(const char *) = NULL;
int remove(const char *pathname) {
    if(ori_remove == NULL) {
        void *handle = dlopen(LIBC_SO, RTLD_LAZY);
        if(handle == NULL) return -1;
        if((ori_remove = (int(*)(const char *))dlsym(handle, "remove")) == NULL) {
            return -1;
        }
    }

    char real_pathname[1024];
    if(realpath(pathname, real_pathname) == NULL) {
        strcpy(real_pathname, pathname);
    }

    int ret = ori_remove(pathname);
    dprintf(getlogfd(), "[logger] remove(\"%s\") = %d\n", real_pathname, ret);
    return ret;
}

static int (*ori_chmod)(const char *, mode_t) = NULL;
int chmod(const char *pathname, mode_t mode) {
    if(ori_chmod == NULL) {
        void *handle = dlopen(LIBC_SO, RTLD_LAZY);
        if(handle == NULL) return -1;
        if((ori_chmod = (int(*)(const char *, mode_t))dlsym(handle, "chmod")) == NULL) {
            return -1;
        }
    }

    char real_pathname[1024];
    if(realpath(pathname, real_pathname) == NULL) {
        strcpy(real_pathname, pathname);
    }

    int ret = ori_chmod(pathname, mode);
    dprintf(getlogfd(), "[logger] chmod(\"%s\", %03o) = %d\n", real_pathname, mode, ret);
    return ret;
}

static int (*ori_chown)(const char *, uid_t, gid_t) = NULL;
int chown(const char *pathname, uid_t owner, gid_t group) {
    if(ori_chown == NULL) {
        void *handle = dlopen(LIBC_SO, RTLD_LAZY);
        if(handle == NULL) return -1;
        if((ori_chown = (int(*)(const char *, uid_t, gid_t))dlsym(handle, "chown")) == NULL) {
            return -1;
        }
    }

    char real_pathname[1024];
    if(realpath(pathname, real_pathname) == NULL) {
        strcpy(real_pathname, pathname);
    }

    int ret = ori_chown(pathname, owner, group);
    dprintf(getlogfd(), "[logger] chown(\"%s\", %d, %d) = %d\n", real_pathname, owner, group, ret);
    return ret;
}

static FILE* (*ori_fopen)(const char *, const char *) = NULL;
FILE *fopen(const char *pathname, const char *mode) {
    if(ori_fopen == NULL) {
        void *handle = dlopen(LIBC_SO, RTLD_LAZY);
        if(handle == NULL) return NULL;
        if((ori_fopen = (FILE*(*)(const char *, const char *))dlsym(handle, "fopen")) == NULL) {
            return NULL;
        }
    }

    char real_pathname[1024];
    if(realpath(pathname, real_pathname) == NULL) {
        strcpy(real_pathname, pathname);
    }

    FILE* ret = ori_fopen(pathname, mode);
    dprintf(getlogfd(), "[logger] fopen(\"%s\", \"%s\") = %p\n", real_pathname, mode, ret);
    return ret;
}

static size_t (*ori_fread)(void *, size_t, size_t, FILE *)= NULL;
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    if(ori_fread == NULL) {
        void *handle = dlopen(LIBC_SO, RTLD_LAZY);
        if(handle == NULL) return 0;
        if((ori_fread = (size_t(*)(void *, size_t, size_t, FILE *))dlsym(handle, "fread")) == NULL) {
            return 0;
        }
    }

    int fd;
    if((fd = fileno(stream)) == -1) return 0;
    pid_t pid = getpid();
    char fdpath[1024];
    sprintf(fdpath, "/proc/%d/fd/%d", pid, fd);
    char real_fdpath[1024];
    memset(real_fdpath, 0, 1024);
    if(readlink(fdpath, real_fdpath, 1024) == -1) {
        strcpy(real_fdpath, fdpath);
    }

    char ptrcpy[33];
    memset(ptrcpy, 0, 33);
    memcpy(ptrcpy, ptr, 32);
    for (char *p = ptrcpy; *p; p++) {
        if (isprint(*p) == 0) {
            *p = '.';
        }
    }

    size_t ret = ori_fread(ptr, size, nmemb, stream);
    dprintf(getlogfd(), "[logger] fread(\"%s\", %ld, %ld, \"%s\") = %ld\n",
        ptrcpy, size, nmemb, real_fdpath, ret);

    return ret;
}

static size_t (*ori_fwrite)(const void *, size_t, size_t, FILE *)= NULL;
size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    if(ori_fwrite == NULL) {
        void *handle = dlopen(LIBC_SO, RTLD_LAZY);
        if(handle == NULL) return 0;
        if((ori_fwrite = (size_t(*)(const void *, size_t, size_t, FILE *))dlsym(handle, "fwrite")) == NULL) {
            return 0;
        }
    }

    int fd;
    if((fd = fileno(stream)) == -1) return 0;
    pid_t pid = getpid();
    char fdpath[1024];
    sprintf(fdpath, "/proc/%d/fd/%d", pid, fd);
    char real_fdpath[1024];
    memset(real_fdpath, 0, 1024);
    if(readlink(fdpath, real_fdpath, 1024) == -1) {
        strcpy(real_fdpath, fdpath);
    }

    char ptrcpy[33];
    memset(ptrcpy, 0, 33);
    memcpy(ptrcpy, ptr, 32);
    for (char *p = ptrcpy; *p; p++) {
        if (isprint(*p) == 0) {
            *p = '.';
        }
    }

    size_t ret = ori_fwrite(ptr, size, nmemb, stream);
    dprintf(getlogfd(), "[logger] fwrite(\"%s\", %ld, %ld, \"%s\") = %ld\n",
        ptrcpy, size, nmemb, real_fdpath, ret);

    return ret;
}

static int (*ori_fclose)(FILE *) = NULL;
int fclose(FILE *stream) {
    if(ori_fclose == NULL) {
        void *handle = dlopen(LIBC_SO, RTLD_LAZY);
        if(handle == NULL) return -1;
        if((ori_fclose = (int(*)(FILE *))dlsym(handle, "fclose")) == NULL) {
            return -1;
        }
    }

    int fd;
    if((fd = fileno(stream)) == -1) return -1;
    pid_t pid = getpid();
    char fdpath[1024];
    sprintf(fdpath, "/proc/%d/fd/%d", pid, fd);
    char real_fdpath[1024];
    memset(real_fdpath, 0, 1024);
    if(readlink(fdpath, real_fdpath, 1024) == -1) {
        strcpy(real_fdpath, fdpath);
    }

    int ret = ori_fclose(stream);
    dprintf(getlogfd(), "[logger] fclose(\"%s\") = %d\n", real_fdpath, ret);
    return ret;
}

static FILE* (*ori_tmpfile)() = NULL;
FILE *tmpfile() {
    if(ori_tmpfile == NULL) {
        void *handle = dlopen(LIBC_SO, RTLD_LAZY);
        if(handle == NULL) return NULL;
        if((ori_tmpfile = (FILE*(*)())dlsym(handle, "tmpfile")) == NULL) {
            return NULL;
        }
    }

    FILE* ret = ori_tmpfile();
    dprintf(getlogfd(), "[logger] tmpfile() = %p\n", ret);
    return ret;
}

static int (*ori_creat)(const char *, mode_t) = NULL;
int creat(const char *pathname, mode_t mode) {
    if(ori_creat == NULL) {
        void *handle = dlopen(LIBC_SO, RTLD_LAZY);
        if(handle == NULL) return -1;
        if((ori_creat = (int(*)(const char *, mode_t))dlsym(handle, "creat")) == NULL) {
            return -1;
        }
    }

    char real_pathname[1024];
    if(realpath(pathname, real_pathname) == NULL) {
        strcpy(real_pathname, pathname);
    }

    int ret = ori_creat(pathname, mode);
    dprintf(getlogfd(), "[logger] creat(\"%s\", %03o) = %d\n", real_pathname, mode, ret);
    return ret;
}

static int (*ori_open)(const char *, int, ...) = NULL;
int open(const char *pathname, int flags, ...) {
    if(ori_open == NULL) {
        void *handle = dlopen(LIBC_SO, RTLD_LAZY);
        if(handle == NULL) return -1;
        if((ori_open = (int(*)(const char *, int, ...))dlsym(handle, "open")) == NULL) {
            return -1;
        }
    }
    va_list ap;
    va_start(ap, flags);
    mode_t mode = va_arg(ap, mode_t);
    va_end(ap);


    char real_pathname[1024];
    if(realpath(pathname, real_pathname) == NULL) {
        strcpy(real_pathname, pathname);
    }

    int ret = ori_open(pathname, flags, mode);
    dprintf(getlogfd(), "[logger] open(\"%s\", %d, %03o) = %d\n", real_pathname, flags, mode, ret);
    return ret;
}

static ssize_t (*ori_read)(int, void *, size_t)= NULL;
ssize_t read(int fd, void *buf, size_t count) {
    if(ori_read == NULL) {
        void *handle = dlopen(LIBC_SO, RTLD_LAZY);
        if(handle == NULL) return -1;
        if((ori_read = (ssize_t(*)(int, void *, size_t))dlsym(handle, "read")) == NULL) {
            return -1;
        }
    }

    pid_t pid = getpid();
    char fdpath[1024];
    sprintf(fdpath, "/proc/%d/fd/%d", pid, fd);
    char real_fdpath[1024];
    memset(real_fdpath, 0, 1024);
    if(readlink(fdpath, real_fdpath, 1024) == -1) {
        strcpy(real_fdpath, fdpath);
    }

    char bufcpy[33];
    memset(bufcpy, 0, 33);
    memcpy(bufcpy, buf, 32);
    for (char *p = bufcpy; *p; p++) {
        if (isprint(*p) == 0) {
            *p = '.';
        }
    }

    size_t ret = ori_read(fd, buf, count);
    dprintf(getlogfd(), "[logger] read(\"%s\", \"%s\", %ld) = %ld\n", real_fdpath, bufcpy, count, ret);

    return ret;
}

static ssize_t (*ori_write)(int, const void *, size_t)= NULL;
ssize_t write(int fd, const void *buf, size_t count) {
    if(ori_write == NULL) {
        void *handle = dlopen(LIBC_SO, RTLD_LAZY);
        if(handle == NULL) return -1;
        if((ori_write = (ssize_t(*)(int, const void *, size_t))dlsym(handle, "write")) == NULL) {
            return -1;
        }
    }

    pid_t pid = getpid();
    char fdpath[1024];
    sprintf(fdpath, "/proc/%d/fd/%d", pid, fd);
    char real_fdpath[1024];
    memset(real_fdpath, 0, 1024);
    if(readlink(fdpath, real_fdpath, 1024) == -1) {
        strcpy(real_fdpath, fdpath);
    }

    char bufcpy[33];
    memset(bufcpy, 0, 33);
    memcpy(bufcpy, buf, 32);
    for (char *p = bufcpy; *p; p++) {
        if (isprint(*p) == 0) {
            *p = '.';
        }
    }

    size_t ret = ori_write(fd, buf, count);
    dprintf(getlogfd(), "[logger] write(\"%s\", \"%s\", %ld) = %ld\n", real_fdpath, bufcpy, count, ret);

    return ret;
}

static int (*ori_close)(int) = NULL;
int close(int fd) {
    if(ori_close == NULL) {
        void *handle = dlopen(LIBC_SO, RTLD_LAZY);
        if(handle == NULL) return -1;
        if((ori_close = (int(*)(int))dlsym(handle, "close")) == NULL) {
            return -1;
        }
    }

    pid_t pid = getpid();
    char fdpath[1024];
    sprintf(fdpath, "/proc/%d/fd/%d", pid, fd);
    char real_fdpath[1024];
    memset(real_fdpath, 0, 1024);
    if(readlink(fdpath, real_fdpath, 1024) == -1) {
        strcpy(real_fdpath, fdpath);
    }

    int ret = ori_close(fd);
    dprintf(getlogfd(), "[logger] close(\"%s\") = %d\n", real_fdpath, ret);
    return ret;
}
