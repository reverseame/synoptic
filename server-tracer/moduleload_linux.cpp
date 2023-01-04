#include "log.h"
#include "moduleload_linux.h"

#include <sys/types.h>
#include <sys/socket.h>

#include <set>
#include <string>
#include <iostream>

/* Checks if fd is a internet socket */
bool isNetworkSocket(int fd) {
    struct sockaddr saddr;

    socklen_t saddr_len = sizeof(saddr);

    /* It returns -1 if fd is not even a socket */
    if (getsockname(fd, (struct sockaddr *) &saddr, &saddr_len) != -1) {
        return (saddr.sa_family == AF_INET) || (saddr.sa_family == AF_INET6);
    }

    return false;
}

ssize_t newRecvFunction(AFUNPTR orgFuncPtr, CONTEXT *ctx, std::set<ADDRINT> &taintedAdddrs, int sockfd, void *buf, size_t len, int flags) {
    ssize_t ret;

    PIN_CallApplicationFunction(ctx, PIN_ThreadId(),
                                CALLINGSTD_DEFAULT, orgFuncPtr,
                                NULL,
                                PIN_PARG(ssize_t), &ret,
                                PIN_PARG(int), sockfd,
                                PIN_PARG(void*), buf,
                                PIN_PARG(size_t), len,
                                PIN_PARG(int), flags,
                                PIN_PARG_END());

    if (isNetworkSocket(sockfd)) {
        LOG_TAINT("action=recv file-descriptor=%d buffer-address=%p buffer-size=%ld content-size=%ld", sockfd, buf, len, ret);

        if (ret > 0) {
            LOG_RAW(" buffer-content=");
            for (int i = 0; i < ret; i++) {
                LOG_RAW("%02x", ((char* )buf)[i]);
            }
            LOG_RAW(" range-start=%p range-end=0x%08lx", buf, (UINT64) buf + ret - 1);
        }

        LOG_RAW("\n");

        /* Taint all recv data at byte level */
        for (int i = 0; i < ret; i++) {
            taintedAdddrs.insert((UINT64) buf + i);
        }
    }

    return ret;
}

ssize_t newRecvFromFunction(AFUNPTR orgFuncPtr, CONTEXT *ctx, std::set<ADDRINT> &taintedAdddrs, int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
    ssize_t ret;

    PIN_CallApplicationFunction(ctx, PIN_ThreadId(),
                                CALLINGSTD_DEFAULT, orgFuncPtr,
                                NULL,
                                PIN_PARG(ssize_t), &ret,
                                PIN_PARG(int), sockfd,
                                PIN_PARG(void*), buf,
                                PIN_PARG(size_t), len,
                                PIN_PARG(int), flags,
                                PIN_PARG(struct sockaddr*), src_addr,
                                PIN_PARG(socklen_t*), addrlen,
                                PIN_PARG_END());

    if (isNetworkSocket(sockfd)) {
        LOG_TAINT("action=recvfrom file-descriptor=%d buffer-address=%p buffer-size=%ld content-size=%ld", sockfd, buf, len, ret);

        if (ret > 0) {
            LOG_RAW(" buffer-content=");
            for (int i = 0; i < ret; i++) {
                LOG_RAW("%02x", ((char* )buf)[i]);
            }
            LOG_RAW(" range-start=%p range-end=0x%08lx", buf, (UINT64) buf + ret - 1);
        }

        LOG_RAW("\n");

        /* Taint all recv data at byte level */
        for (int i = 0; i < ret; i++) {
            taintedAdddrs.insert((UINT64) buf + i);
        }
    }

    return ret;
}

ssize_t newRecvMsgFunction(AFUNPTR orgFuncPtr, CONTEXT *ctx, std::set<ADDRINT> &taintedAdddrs, int sockfd, struct msghdr *msg, int flags) {
    ssize_t ret;

    PIN_CallApplicationFunction(ctx, PIN_ThreadId(),
                                CALLINGSTD_DEFAULT, orgFuncPtr,
                                NULL,
                                PIN_PARG(ssize_t), &ret,
                                PIN_PARG(int), sockfd,
                                PIN_PARG(struct msghdr*), msg,
                                PIN_PARG(int), flags,
                                PIN_PARG_END());

    //struct cmsghdr *cmsg;

    if (isNetworkSocket(sockfd)) {
        LOG_TAINT("action=recvmsg file-descriptor=%d content-size=%ld\n", sockfd, ret);
        /*for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL; cmsg = CMSG_NXTHDR(msg, cmsg)) {
            std::cout << "msg read" << std::endl;
        }*/
    }

    return ret;
}

ssize_t newSendFunction(AFUNPTR orgFuncPtr, CONTEXT *ctx, std::set<ADDRINT> &taintedAdddrs, bool(&taintedRegs)[REG_LAST], int sockfd, const void *buf, size_t len, int flags) {
    ssize_t ret;

    PIN_CallApplicationFunction(ctx, PIN_ThreadId(),
                                CALLINGSTD_DEFAULT, orgFuncPtr,
                                NULL,
                                PIN_PARG(ssize_t), &ret,
                                PIN_PARG(int), sockfd,
                                PIN_PARG(const void*), buf,
                                PIN_PARG(size_t), len,
                                PIN_PARG(int), flags,
                                PIN_PARG_END());

    if (isNetworkSocket(sockfd)) {
        LOG_TAINT("action=send file-descriptor=%d buffer-address=%p buffer-size=%ld content-size=%ld", sockfd, buf, len, ret);

        if (ret > 0) {
            LOG_RAW(" buffer-content=");
            for (int i = 0; i < ret; i++) {
                LOG_RAW("%02x", ((char* )buf)[i]);
            }
            LOG_RAW(" range-start=%p range-end=0x%08lx", buf, (UINT64) buf + ret - 1);
        }

        LOG_RAW("\n");

        /* Free all tainted data */
        taintedAdddrs.clear();
        for (int i = 0; i < REG_LAST; i++) {
            taintedRegs[i] = false;
        }
    }

    return ret;
}

ssize_t newSendToFunction(AFUNPTR orgFuncPtr, CONTEXT *ctx, std::set<ADDRINT> &taintedAdddrs, bool(&taintedRegs)[REG_LAST], int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
    ssize_t ret;

    PIN_CallApplicationFunction(ctx, PIN_ThreadId(),
                                CALLINGSTD_DEFAULT, orgFuncPtr,
                                NULL,
                                PIN_PARG(ssize_t), &ret,
                                PIN_PARG(int), sockfd,
                                PIN_PARG(const void*), buf,
                                PIN_PARG(size_t), len,
                                PIN_PARG(int), flags,
                                PIN_PARG(const struct sockaddr*), dest_addr,
                                PIN_PARG(socklen_t), addrlen,
                                PIN_PARG_END());

    if (isNetworkSocket(sockfd)) {
        LOG_TAINT("action=sendto file-descriptor=%d buffer-address=%p buffer-size=%ld content-size=%ld", sockfd, buf, len, ret);

        if (ret > 0) {
            LOG_RAW(" buffer-content=");
            for (int i = 0; i < ret; i++) {
                LOG_RAW("%02x", ((char* )buf)[i]);
            }
            LOG_RAW(" range-start=%p range-end=0x%08lx", buf, (UINT64) buf + ret - 1);
        }

        LOG_RAW("\n");

        /* Free all tainted data */
        taintedAdddrs.clear();
        for (int i = 0; i < REG_LAST; i++) {
            taintedRegs[i] = false;
        }
    }

    return ret;
}

ssize_t newSendMsgFunction(AFUNPTR orgFuncPtr, CONTEXT *ctx, std::set<ADDRINT> &taintedAdddrs, bool(&taintedRegs)[REG_LAST], int sockfd, const struct msghdr *msg, int flags) {
    ssize_t ret;

    PIN_CallApplicationFunction(ctx, PIN_ThreadId(),
                                CALLINGSTD_DEFAULT, orgFuncPtr,
                                NULL,
                                PIN_PARG(ssize_t), &ret,
                                PIN_PARG(int), sockfd,
                                PIN_PARG(const struct msghdr*), msg,
                                PIN_PARG(int), flags,
                                PIN_PARG_END());
    //struct cmsghdr *cmsg;

    if (isNetworkSocket(sockfd)) {
        LOG_TAINT("action=sendmsg file-descriptor=%d content-size=%ld\n", sockfd, ret);
        /*for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL; cmsg = CMSG_NXTHDR(msg, cmsg)) {
            std::cout << "msg read" << std::endl;
        }*/
        /* Free all tainted data */
        taintedAdddrs.clear();
        for (int i = 0; i < REG_LAST; i++) {
            taintedRegs[i] = false;
        }
    }

    return ret;
}

int newCloseFunction(AFUNPTR orgFuncPtr, CONTEXT *ctx, int fd) {
    int ret;

    if (isNetworkSocket(fd)) {
        LOG_INFO("action=close file-descriptor=%d\n", fd);
    }

    PIN_CallApplicationFunction(ctx, PIN_ThreadId(),
                                CALLINGSTD_DEFAULT, orgFuncPtr,
                                NULL,
                                PIN_PARG(int), &ret,
                                PIN_PARG(int), fd,
                                PIN_PARG_END());

    return ret;
}

int newAcceptFunction(AFUNPTR orgFuncPtr, CONTEXT *ctx, int sockfd, struct sockaddr *addr, socklen_t *addrLen) {
    int ret;

    PIN_CallApplicationFunction(ctx, PIN_ThreadId(),
                                CALLINGSTD_DEFAULT, orgFuncPtr,
                                NULL,
                                PIN_PARG(int), &ret,
                                PIN_PARG(int), sockfd,
                                PIN_PARG(struct sockaddr*), addr,
                                PIN_PARG(socklen_t*), addrLen,
                                PIN_PARG_END());

    if (isNetworkSocket(sockfd)) {
        LOG_INFO("action=accept file-descriptor=%d\n", ret);
    }

    return ret;
}

int newConnectFunction(AFUNPTR orgFuncPtr, CONTEXT *ctx, int sockfd, const struct sockaddr *addr, socklen_t addrLen) {
    int ret;

    PIN_CallApplicationFunction(ctx, PIN_ThreadId(),
                                CALLINGSTD_DEFAULT, orgFuncPtr,
                                NULL,
                                PIN_PARG(int), &ret,
                                PIN_PARG(int), sockfd,
                                PIN_PARG(const struct sockaddr*), addr,
                                PIN_PARG(socklen_t), addrLen,
                                PIN_PARG_END());

    if (isNetworkSocket(sockfd)) {
        LOG_INFO("action=connect file-descriptor=%d\n", sockfd);
    }
    

    return ret;
}

void replaceRecvFunction(IMG img, RTN rtn, std::set<ADDRINT> &taintedAdddrs) {
    PROTO proto_tcp_activity = PROTO_Allocate(PIN_PARG(ssize_t), CALLINGSTD_DEFAULT,
                                        NULL,
                                        PIN_PARG(int),      // sockfd
                                        PIN_PARG(void*),    // buf
                                        PIN_PARG(size_t),   // len
                                        PIN_PARG(int),      // flags
                                        PIN_PARG_END());

    RTN_ReplaceSignature(rtn, AFUNPTR(newRecvFunction),
                                IARG_PROTOTYPE, proto_tcp_activity,
                                IARG_ORIG_FUNCPTR,
                                IARG_CONTEXT,
                                IARG_PTR, &taintedAdddrs,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                                IARG_END);

    PROTO_Free(proto_tcp_activity);

    std::cout << "[*] server-tracer\t: INFO\t: recv replaced\t\t\t: " << IMG_Name(img) << std::endl;
}

void replaceRecvFromFunction(IMG img, RTN rtn, std::set<ADDRINT> &taintedAdddrs) {
    PROTO proto_tcp_activity = PROTO_Allocate(PIN_PARG(ssize_t), CALLINGSTD_DEFAULT,
                                        NULL,
                                        PIN_PARG(int),                  // sockfd
                                        PIN_PARG(void*),                // buf
                                        PIN_PARG(size_t),               // len
                                        PIN_PARG(int),                  // flags
                                        PIN_PARG(struct sockaddr*),     // src_addr
                                        PIN_PARG(socklen_t*),           // addrlen
                                        PIN_PARG_END());

    RTN_ReplaceSignature(rtn, AFUNPTR(newRecvFromFunction),
                                IARG_PROTOTYPE, proto_tcp_activity,
                                IARG_ORIG_FUNCPTR,
                                IARG_CONTEXT,
                                IARG_PTR, &taintedAdddrs,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
                                IARG_END);

    PROTO_Free(proto_tcp_activity);

    std::cout << "[*] server-tracer\t: INFO\t: recvfrom replaced\t\t\t: " << IMG_Name(img) << std::endl;
}

void replaceRecvMsgFunction(IMG img, RTN rtn, std::set<ADDRINT> &taintedAdddrs) {
    PROTO proto_tcp_activity = PROTO_Allocate(PIN_PARG(ssize_t), CALLINGSTD_DEFAULT,
                                        NULL,
                                        PIN_PARG(int),                  // sockfd
                                        PIN_PARG(struct msghdr*),       // msg
                                        PIN_PARG(int),                  // flags
                                        PIN_PARG_END());

    RTN_ReplaceSignature(rtn, AFUNPTR(newRecvMsgFunction),
                                IARG_PROTOTYPE, proto_tcp_activity,
                                IARG_ORIG_FUNCPTR,
                                IARG_CONTEXT,
                                IARG_PTR, &taintedAdddrs,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                IARG_END);

    PROTO_Free(proto_tcp_activity);

    std::cout << "[*] server-tracer\t: INFO\t: recvmsg replaced\t\t\t: " << IMG_Name(img) << std::endl;
}

void replaceSendFunction(IMG img, RTN rtn, std::set<ADDRINT> &taintedAdddrs, bool(&taintedRegs)[REG_LAST]) {
    PROTO proto_tcp_activity = PROTO_Allocate(PIN_PARG(ssize_t), CALLINGSTD_DEFAULT,
                                        NULL,
                                        PIN_PARG(int),          // sockfd
                                        PIN_PARG(const void*),  // buf
                                        PIN_PARG(size_t),       // len
                                        PIN_PARG(int),          // flags
                                        PIN_PARG_END());

    RTN_ReplaceSignature(rtn, AFUNPTR(newSendFunction),
                                IARG_PROTOTYPE, proto_tcp_activity,
                                IARG_ORIG_FUNCPTR,
                                IARG_CONTEXT,
                                IARG_PTR, &taintedAdddrs,
                                IARG_PTR, &taintedRegs,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                                IARG_END);

    PROTO_Free(proto_tcp_activity);

    std::cout << "[*] server-tracer\t: INFO\t: send replaced\t\t\t: " << IMG_Name(img) << std::endl;
}

void replaceSendToFunction(IMG img, RTN rtn, std::set<ADDRINT> &taintedAdddrs, bool(&taintedRegs)[REG_LAST]) {
    PROTO proto_tcp_activity = PROTO_Allocate(PIN_PARG(ssize_t), CALLINGSTD_DEFAULT,
                                        NULL,
                                        PIN_PARG(int),                      // sockfd
                                        PIN_PARG(const void*),              // buf
                                        PIN_PARG(size_t),                   // len
                                        PIN_PARG(int),                      // flags
                                        PIN_PARG(const struct sockaddr*),   // dest_addr
                                        PIN_PARG(socklen_t),                // addrlen
                                        PIN_PARG_END());

    RTN_ReplaceSignature(rtn, AFUNPTR(newSendToFunction),
                                IARG_PROTOTYPE, proto_tcp_activity,
                                IARG_ORIG_FUNCPTR,
                                IARG_CONTEXT,
                                IARG_PTR, &taintedAdddrs,
                                IARG_PTR, &taintedRegs,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
                                IARG_END);

    PROTO_Free(proto_tcp_activity);

    std::cout << "[*] server-tracer\t: INFO\t: sendto replaced\t\t\t: " << IMG_Name(img) << std::endl;
}

void replaceSendMsgFunction(IMG img, RTN rtn, std::set<ADDRINT> &taintedAdddrs, bool(&taintedRegs)[REG_LAST]) {
    PROTO proto_tcp_activity = PROTO_Allocate(PIN_PARG(ssize_t), CALLINGSTD_DEFAULT,
                                        NULL,
                                        PIN_PARG(int),                      // sockfd
                                        PIN_PARG(const struct msghdr*),     // msg
                                        PIN_PARG(int),                      // flags
                                        PIN_PARG_END());

    RTN_ReplaceSignature(rtn, AFUNPTR(newSendMsgFunction),
                                IARG_PROTOTYPE, proto_tcp_activity,
                                IARG_ORIG_FUNCPTR,
                                IARG_CONTEXT,
                                IARG_PTR, &taintedAdddrs,
                                IARG_PTR, &taintedRegs,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                IARG_END);

    PROTO_Free(proto_tcp_activity);

    std::cout << "[*] server-tracer\t: INFO\t: sendmsg replaced\t\t\t: " << IMG_Name(img) << std::endl;
}

void replaceCloseFunction(IMG img, RTN rtn) {
    PROTO proto_close = PROTO_Allocate(PIN_PARG(int), CALLINGSTD_DEFAULT,
                                        NULL,
                                        PIN_PARG(int),      // fd
                                        PIN_PARG_END());

    RTN_ReplaceSignature(rtn, AFUNPTR(newCloseFunction),
                                IARG_PROTOTYPE, proto_close,
                                IARG_ORIG_FUNCPTR,
                                IARG_CONTEXT,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                IARG_END);

    PROTO_Free(proto_close);

    std::cout << "[*] server-tracer\t: INFO\t: close replaced\t\t: " << IMG_Name(img) << std::endl;
}

void replaceAcceptFunction(IMG img, RTN rtn) {
    PROTO proto_accept = PROTO_Allocate(PIN_PARG(int), CALLINGSTD_DEFAULT,
                                        NULL,
                                        PIN_PARG(int),              // sockfd
                                        PIN_PARG(struct sockaddr*), // addr
                                        PIN_PARG(socklen_t*),       // addrlen
                                        PIN_PARG_END());

    RTN_ReplaceSignature(rtn, AFUNPTR(newAcceptFunction),
                                IARG_PROTOTYPE, proto_accept,
                                IARG_ORIG_FUNCPTR,
                                IARG_CONTEXT,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                IARG_END);

    PROTO_Free(proto_accept);

    std::cout << "[*] server-tracer\t: INFO\t: accept replaced\t\t: " << IMG_Name(img) << std::endl;
}

void replaceConnectFunction(IMG img, RTN rtn) {
    PROTO proto_connect = PROTO_Allocate(PIN_PARG(int), CALLINGSTD_DEFAULT,
                                        NULL,
                                        PIN_PARG(int),                      // sockfd
                                        PIN_PARG(const struct sockaddr*),   // addr
                                        PIN_PARG(socklen_t),                // addrlen
                                        PIN_PARG_END());

    RTN_ReplaceSignature(rtn, AFUNPTR(newConnectFunction),
                                IARG_PROTOTYPE, proto_connect,
                                IARG_ORIG_FUNCPTR,
                                IARG_CONTEXT,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                IARG_END);

    PROTO_Free(proto_connect);

    std::cout << "[*] server-tracer\t: INFO\t: connect replaced\t\t: " << IMG_Name(img) << std::endl;
}

void replaceSignatures(IMG img, std::set<ADDRINT> &taintedAdddrs, bool(&taintedRegs)[REG_LAST]) {
    RTN rtn;

    rtn = RTN_FindByName(img, "recv");
    if (RTN_Valid(rtn)) {
        replaceRecvFunction(img, rtn, taintedAdddrs);
    }

    rtn = RTN_FindByName(img, "recvfrom");
    if (RTN_Valid(rtn)) {
        replaceRecvFromFunction(img, rtn, taintedAdddrs);
    }

    rtn = RTN_FindByName(img, "recvmsg");
    if (RTN_Valid(rtn)) {
        replaceRecvMsgFunction(img, rtn, taintedAdddrs);
    }

    rtn = RTN_FindByName(img, "send");
    if (RTN_Valid(rtn)) {
        replaceSendFunction(img, rtn, taintedAdddrs, taintedRegs);
    }

    rtn = RTN_FindByName(img, "sendto");
    if (RTN_Valid(rtn)) {
        replaceSendToFunction(img, rtn, taintedAdddrs, taintedRegs);
    }

    rtn = RTN_FindByName(img, "sendmsg");
    if (RTN_Valid(rtn)) {
        replaceSendMsgFunction(img, rtn, taintedAdddrs, taintedRegs);
    }

    rtn = RTN_FindByName(img, "close");
    if (RTN_Valid(rtn)) {
        replaceCloseFunction(img, rtn);
    }

    rtn = RTN_FindByName(img, "accept");
    if (RTN_Valid(rtn)) {
        replaceAcceptFunction(img, rtn);
    }

    rtn = RTN_FindByName(img, "connect");
    if (RTN_Valid(rtn)) {
        replaceConnectFunction(img, rtn);
    }
}