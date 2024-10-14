#include "vmlinux.h"
#include "vmlinux-x86.h"

enum syscall_src_func
{
    SYSCALL_FUNC_UNKNOWN,
    SYSCALL_FUNC_WRITE,
    SYSCALL_FUNC_READ,
    SYSCALL_FUNC_SEND,
    SYSCALL_FUNC_RECV,
    SYSCALL_FUNC_SENDTO,
    SYSCALL_FUNC_RECVFROM,
    SYSCALL_FUNC_SENDMSG,
    SYSCALL_FUNC_RECVMSG,
    SYSCALL_FUNC_SENDMMSG,
    SYSCALL_FUNC_RECVMMSG,
    SYSCALL_FUNC_WRITEV,
    SYSCALL_FUNC_READV,
    SYSCALL_FUNC_SENDFILE
};

struct data_args_t
{
    // Represents the function from which this argument group originates.
    enum syscall_src_func source_fn;
    __u32 fd;
    // For send()/recv()/write()/read().
    // const char *buf;
    uintptr_t buf;

    // For sendmsg()/recvmsg()/writev()/readv().
    // const struct iovec *iov;
    uintptr_t iov;

    // void *sk;
    uintptr_t sk;
    size_t iovlen;

    union
    {
        // For sendmmsg()
        // unsigned int *msg_len;
        uintptr_t msg_len;
        // For clock_gettime()
        // struct timespec *timestamp_ptr;
        uintptr_t timestamp_ptr;
    };

    union
    {
        __u64 socket_id; // Use for socket close
        __u64 enter_ts;  // Timestamp for enter syscall function.
    };

    __u32 tcp_seq; // Used to record the entry of syscalls
    union
    {
        ssize_t bytes_count; // io event
        ssize_t data_seq;    // Use for socket close
    };
    // Scenario for using sendto() with a specified address
    __u16 port;
    __u8 addr[16];
}
__attribute__((packed));