#include "log.h"
#include "moduleload_linux.h"

#include <unistd.h>
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

int newSocketFunction(AFUNPTR orgFuncPtr, CONTEXT *ctx, std::string *imgName, int domain, int type, int protocol) {
    int ret;

    PIN_CallApplicationFunction(ctx, PIN_ThreadId(),
                                CALLINGSTD_DEFAULT, orgFuncPtr,
                                NULL,
                                PIN_PARG(int), &ret,
                                PIN_PARG(int), domain,
                                PIN_PARG(int), type,
                                PIN_PARG(int), protocol,
                                PIN_PARG_END());
    if (isNetworkSocket(ret)) {
        LOG_INFO("action=socket module=\"%s\" return=%d\n", imgName->c_str(), ret);
    }

    return ret;
}

int newAcceptFunction(AFUNPTR orgFuncPtr, CONTEXT *ctx, std::string *imgName, int sockfd, struct sockaddr *addr, socklen_t *addrLen) {
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
        LOG_INFO("action=accept module=\"%s\" return=%d\n", imgName->c_str(), ret);
    }

    return ret;
}

int newConnectFunction(AFUNPTR orgFuncPtr, CONTEXT *ctx, std::string *imgName, int sockfd, const struct sockaddr *addr, socklen_t addrLen) {
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
        LOG_INFO("action=connect module=\"%s\" file-descriptor=%d return=%d\n", imgName->c_str(), sockfd, ret);
    }
    

    return ret;
}

int newCloseFunction(AFUNPTR orgFuncPtr, CONTEXT *ctx, std::string *imgName, int fd) {
    int ret;
    bool network_socket = isNetworkSocket(fd);

    if (network_socket) {
        LOG_INFO("action=close module=\"%s\" file-descriptor=%d", imgName->c_str(), fd);
    }

    PIN_CallApplicationFunction(ctx, PIN_ThreadId(),
                                CALLINGSTD_DEFAULT, orgFuncPtr,
                                NULL,
                                PIN_PARG(int), &ret,
                                PIN_PARG(int), fd,
                                PIN_PARG_END());
    
    if (network_socket) {
        LOG_RAW(" return=%d\n", ret);
    }

    return ret;
}

int newDup2Function(AFUNPTR orgFuncPtr, CONTEXT *ctx, std::string *imgName, int oldfd, int newfd) {
    int ret;

    bool network_socket = isNetworkSocket(oldfd);

    if (network_socket) {
        LOG_INFO("action=dup2 module=\"%s\" file-descriptor=%d", imgName->c_str(), oldfd);
    }

    PIN_CallApplicationFunction(ctx, PIN_ThreadId(),
                                CALLINGSTD_DEFAULT, orgFuncPtr,
                                NULL,
                                PIN_PARG(int), &ret,
                                PIN_PARG(int), oldfd,
                                PIN_PARG(int), newfd,
                                PIN_PARG_END());
    
    if (network_socket) {
        LOG_RAW(" return=%d\n", ret);
    }

    return ret;
}

ssize_t newReadFunction(AFUNPTR orgFuncPtr, CONTEXT *ctx, std::set<ADDRINT> &taintedAdddrs, std::set<ADDRINT> &visitedAddrs, bool &thresholdTriggered, int &IOCounter, std::string *imgName, int fd, void *buf, size_t count) {
    ssize_t ret;

    PIN_CallApplicationFunction(ctx, PIN_ThreadId(),
                                CALLINGSTD_DEFAULT, orgFuncPtr,
                                NULL,
                                PIN_PARG(ssize_t), &ret,
                                PIN_PARG(int), fd,
                                PIN_PARG(void*), buf,
                                PIN_PARG(size_t), count,
                                PIN_PARG_END());

    if (isNetworkSocket(fd)) {
        IOCounter++;
        thresholdTriggered = false;

        LOG_TAINT("action=read module=\"%s\" file-descriptor=%d buffer-address=%p buffer-size=%ld return=%ld", imgName->c_str(), fd, buf, count, ret);

        if (ret > 0) {
            LOG_RAW(" buffer-content=");
            for (int i = 0; i < ret; i++) {
                LOG_RAW("%02x", ((char* )buf)[i]);
            }
            LOG_RAW(" range-start=%p range-end=0x%08lx", buf, (UINT64) buf + ret - 1);

            /* Taint all recv data at byte level */
            for (int i = 0; i < ret; i++) {
                taintedAdddrs.insert((UINT64) buf + i);
            }

            visitedAddrs.clear();
        }

        LOG_RAW("\n");
    }

    return ret;
}

ssize_t newRecvFunction(AFUNPTR orgFuncPtr, CONTEXT *ctx, std::set<ADDRINT> &taintedAdddrs, std::set<ADDRINT> &visitedAddrs, bool &thresholdTriggered, int &IOCounter, std::string *imgName, int sockfd, void *buf, size_t len, int flags) {
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
        IOCounter++;
        thresholdTriggered = false;

        LOG_TAINT("action=recv module=\"%s\" file-descriptor=%d buffer-address=%p buffer-size=%ld return=%ld", imgName->c_str(), sockfd, buf, len, ret);

        if (ret > 0) {
            LOG_RAW(" buffer-content=");
            for (int i = 0; i < ret; i++) {
                LOG_RAW("%02x", ((char* )buf)[i]);
            }
            LOG_RAW(" range-start=%p range-end=0x%08lx", buf, (UINT64) buf + ret - 1);

            /* Taint all recv data at byte level */
            for (int i = 0; i < ret; i++) {
                taintedAdddrs.insert((UINT64) buf + i);
            }

            visitedAddrs.clear();
        }

        LOG_RAW("\n");
    }

    return ret;
}

ssize_t newRecvFromFunction(AFUNPTR orgFuncPtr, CONTEXT *ctx, std::set<ADDRINT> &taintedAdddrs, std::set<ADDRINT> &visitedAddrs, bool &thresholdTriggered, int &IOCounter, std::string *imgName, int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
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
        IOCounter++;
        thresholdTriggered = false;

        LOG_TAINT("action=recvfrom module=\"%s\" file-descriptor=%d buffer-address=%p buffer-size=%ld return=%ld", imgName->c_str(), sockfd, buf, len, ret);

        if (ret > 0) {
            LOG_RAW(" buffer-content=");
            for (int i = 0; i < ret; i++) {
                LOG_RAW("%02x", ((char* )buf)[i]);
            }
            LOG_RAW(" range-start=%p range-end=0x%08lx", buf, (UINT64) buf + ret - 1);

            /* Taint all recv data at byte level */
            for (int i = 0; i < ret; i++) {
                taintedAdddrs.insert((UINT64) buf + i);
            }

            visitedAddrs.clear();
        }

        LOG_RAW("\n");
    }

    return ret;
}

ssize_t newRecvMsgFunction(AFUNPTR orgFuncPtr, CONTEXT *ctx, std::set<ADDRINT> &taintedAdddrs, std::set<ADDRINT> &visitedAddrs, bool &thresholdTriggered, int &IOCounter, std::string *imgName, int sockfd, struct msghdr *msg, int flags) {
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
        LOG_TAINT("action=recvmsg module=\"%s\" file-descriptor=%d return=%ld\n", imgName->c_str(), sockfd, ret);
        /*for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL; cmsg = CMSG_NXTHDR(msg, cmsg)) {
            std::cerr << "msg read" << std::endl;
        }*/
    }

    return ret;
}

ssize_t newWriteFunction(AFUNPTR orgFuncPtr, CONTEXT *ctx, std::set<ADDRINT> &taintedAdddrs, bool(&taintedRegs)[REG_LAST], std::string *imgName, int fd, const void *buf, size_t count) {
    ssize_t ret;

    PIN_CallApplicationFunction(ctx, PIN_ThreadId(),
                                CALLINGSTD_DEFAULT, orgFuncPtr,
                                NULL,
                                PIN_PARG(ssize_t), &ret,
                                PIN_PARG(int), fd,
                                PIN_PARG(const void*), buf,
                                PIN_PARG(size_t), count,
                                PIN_PARG_END());

    if (isNetworkSocket(fd)) {
        LOG_TAINT("action=write module=\"%s\" file-descriptor=%d buffer-address=%p buffer-size=%ld return=%ld", imgName->c_str(), fd, buf, count, ret);

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

ssize_t newSendFunction(AFUNPTR orgFuncPtr, CONTEXT *ctx, std::set<ADDRINT> &taintedAdddrs, bool(&taintedRegs)[REG_LAST], std::string *imgName, int sockfd, const void *buf, size_t len, int flags) {
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
        LOG_TAINT("action=send module=\"%s\" file-descriptor=%d buffer-address=%p buffer-size=%ld return=%ld", imgName->c_str(), sockfd, buf, len, ret);

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

ssize_t newSendToFunction(AFUNPTR orgFuncPtr, CONTEXT *ctx, std::set<ADDRINT> &taintedAdddrs, bool(&taintedRegs)[REG_LAST], std::string *imgName, int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
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
        LOG_TAINT("action=sendto module=\"%s\" file-descriptor=%d buffer-address=%p buffer-size=%ld return=%ld", imgName->c_str(), sockfd, buf, len, ret);

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

ssize_t newSendMsgFunction(AFUNPTR orgFuncPtr, CONTEXT *ctx, std::set<ADDRINT> &taintedAdddrs, bool(&taintedRegs)[REG_LAST], std::string *imgName, int sockfd, const struct msghdr *msg, int flags) {
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
        LOG_TAINT("action=sendmsg module=\"%s\" file-descriptor=%d return=%ld\n", imgName->c_str(), sockfd, ret);
        /*for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL; cmsg = CMSG_NXTHDR(msg, cmsg)) {
            std::cerr << "msg read" << std::endl;
        }*/
        /* Free all tainted data */
        taintedAdddrs.clear();
        for (int i = 0; i < REG_LAST; i++) {
            taintedRegs[i] = false;
        }
    }

    return ret;
}

void replaceSocketFunction(IMG img, RTN rtn) {
    PROTO proto_socket = PROTO_Allocate(PIN_PARG(int), CALLINGSTD_DEFAULT,
                                        NULL,
                                        PIN_PARG(int),      // domain
                                        PIN_PARG(int),      // type
                                        PIN_PARG(int),      // protocol
                                        PIN_PARG_END());

    RTN_ReplaceSignature(rtn, AFUNPTR(newSocketFunction),
                                IARG_PROTOTYPE, proto_socket,
                                IARG_ORIG_FUNCPTR,
                                IARG_CONTEXT,
                                IARG_PTR, new std::string(IMG_Name(img)),
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                IARG_END);

    PROTO_Free(proto_socket);
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
                                IARG_PTR, new std::string(IMG_Name(img)),
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                IARG_END);

    PROTO_Free(proto_accept);
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
                                IARG_PTR, new std::string(IMG_Name(img)),
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                IARG_END);

    PROTO_Free(proto_connect);
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
                                IARG_PTR, new std::string(IMG_Name(img)),
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                IARG_END);

    PROTO_Free(proto_close);
}

void replaceDup2Function(IMG img, RTN rtn) {
    PROTO proto_dup2 = PROTO_Allocate(PIN_PARG(int), CALLINGSTD_DEFAULT,
                                        NULL,
                                        PIN_PARG(int),      // oldfd
                                        PIN_PARG(int),      // newfd
                                        PIN_PARG_END());

    RTN_ReplaceSignature(rtn, AFUNPTR(newDup2Function),
                                IARG_PROTOTYPE, proto_dup2,
                                IARG_ORIG_FUNCPTR,
                                IARG_CONTEXT,
                                IARG_PTR, new std::string(IMG_Name(img)),
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                IARG_END);

    PROTO_Free(proto_dup2);
}

void replaceReadFunction(IMG img, RTN rtn, std::set<ADDRINT> &taintedAdddrs, std::set<ADDRINT> &visitedAddrs, bool &thresholdTriggered, int &IOCounter) {
    PROTO proto_tcp_activity = PROTO_Allocate(PIN_PARG(ssize_t), CALLINGSTD_DEFAULT,
                                        NULL,
                                        PIN_PARG(int),      // fd
                                        PIN_PARG(void*),    // buf
                                        PIN_PARG(size_t),   // count
                                        PIN_PARG_END());

    RTN_ReplaceSignature(rtn, AFUNPTR(newReadFunction),
                                IARG_PROTOTYPE, proto_tcp_activity,
                                IARG_ORIG_FUNCPTR,
                                IARG_CONTEXT,
                                IARG_PTR, &taintedAdddrs,
                                IARG_PTR, &visitedAddrs,
                                IARG_PTR, &thresholdTriggered,
                                IARG_PTR, &IOCounter,
                                IARG_PTR, new std::string(IMG_Name(img)),
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                IARG_END);

    PROTO_Free(proto_tcp_activity);
}

void replaceRecvFunction(IMG img, RTN rtn, std::set<ADDRINT> &taintedAdddrs, std::set<ADDRINT> &visitedAddrs, bool &thresholdTriggered, int &IOCounter) {
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
                                IARG_PTR, &visitedAddrs,
                                IARG_PTR, &thresholdTriggered,
                                IARG_PTR, &IOCounter,
                                IARG_PTR, new std::string(IMG_Name(img)),
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                                IARG_END);

    PROTO_Free(proto_tcp_activity);
}

void replaceRecvFromFunction(IMG img, RTN rtn, std::set<ADDRINT> &taintedAdddrs, std::set<ADDRINT> &visitedAddrs, bool &thresholdTriggered, int &IOCounter) {
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
                                IARG_PTR, &visitedAddrs,
                                IARG_PTR, &thresholdTriggered,
                                IARG_PTR, &IOCounter,
                                IARG_PTR, new std::string(IMG_Name(img)),
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
                                IARG_END);

    PROTO_Free(proto_tcp_activity);
}

void replaceRecvMsgFunction(IMG img, RTN rtn, std::set<ADDRINT> &taintedAdddrs, std::set<ADDRINT> &visitedAddrs, bool &thresholdTriggered, int &IOCounter) {
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
                                IARG_PTR, &visitedAddrs,
                                IARG_PTR, &thresholdTriggered,
                                IARG_PTR, &IOCounter,
                                IARG_PTR, new std::string(IMG_Name(img)),
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                IARG_END);

    PROTO_Free(proto_tcp_activity);
}

void replaceWriteFunction(IMG img, RTN rtn, std::set<ADDRINT> &taintedAdddrs, bool(&taintedRegs)[REG_LAST]) {
    PROTO proto_tcp_activity = PROTO_Allocate(PIN_PARG(ssize_t), CALLINGSTD_DEFAULT,
                                        NULL,
                                        PIN_PARG(int),          // fd
                                        PIN_PARG(const void*),  // buf
                                        PIN_PARG(size_t),       // count
                                        PIN_PARG_END());

    RTN_ReplaceSignature(rtn, AFUNPTR(newWriteFunction),
                                IARG_PROTOTYPE, proto_tcp_activity,
                                IARG_ORIG_FUNCPTR,
                                IARG_CONTEXT,
                                IARG_PTR, &taintedAdddrs,
                                IARG_PTR, &taintedRegs,
                                IARG_PTR, new std::string(IMG_Name(img)),
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                IARG_END);

    PROTO_Free(proto_tcp_activity);
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
                                IARG_PTR, new std::string(IMG_Name(img)),
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                                IARG_END);

    PROTO_Free(proto_tcp_activity);
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
                                IARG_PTR, new std::string(IMG_Name(img)),
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
                                IARG_END);

    PROTO_Free(proto_tcp_activity);
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
                                IARG_PTR, new std::string(IMG_Name(img)),
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                IARG_END);

    PROTO_Free(proto_tcp_activity);
}

void replaceSignatures(bool KnobDebug, IMG img, std::set<ADDRINT> &taintedAdddrs, bool(&taintedRegs)[REG_LAST], std::set<ADDRINT> &visitedAddrs, bool &thresholdTriggered, int &IOCounter) {
    RTN rtn;

    rtn = RTN_FindByName(img, "socket");
    if (RTN_Valid(rtn)) {
        replaceSocketFunction(img, rtn);
        if (KnobDebug) {
            PRINT_DEBUG("socket replaced\t\t: %s\n", IMG_Name(img).c_str());
        }
    }

    rtn = RTN_FindByName(img, "accept");
    if (RTN_Valid(rtn)) {
        replaceAcceptFunction(img, rtn);
        if (KnobDebug) {
            PRINT_DEBUG("accept replaced\t\t: %s\n", IMG_Name(img).c_str());
        }
    }

    rtn = RTN_FindByName(img, "connect");
    if (RTN_Valid(rtn)) {
        replaceConnectFunction(img, rtn);
        if (KnobDebug) {
            PRINT_DEBUG("connect replaced\t\t: %s\n", IMG_Name(img).c_str());
        }
    }

    rtn = RTN_FindByName(img, "close");
    if (RTN_Valid(rtn)) {
        replaceCloseFunction(img, rtn);
        if (KnobDebug) {
            PRINT_DEBUG("close replaced\t\t: %s\n", IMG_Name(img).c_str());
        }
    }

    rtn = RTN_FindByName(img, "dup2");
    if (RTN_Valid(rtn)) {
        replaceDup2Function(img, rtn);
        if (KnobDebug) {
            PRINT_DEBUG("dup2 replaced\t\t\t: %s\n", IMG_Name(img).c_str());
        }
    }

    rtn = RTN_FindByName(img, "read");
    if (RTN_Valid(rtn)) {
        replaceReadFunction(img, rtn, taintedAdddrs, visitedAddrs, thresholdTriggered, IOCounter);
        if (KnobDebug) {
            PRINT_DEBUG("read replaced\t\t\t: %s\n", IMG_Name(img).c_str());
        }
    }

    rtn = RTN_FindByName(img, "recv");
    if (RTN_Valid(rtn)) {
        replaceRecvFunction(img, rtn, taintedAdddrs, visitedAddrs, thresholdTriggered, IOCounter);
        if (KnobDebug) {
            PRINT_DEBUG("recv replaced\t\t\t: %s\n", IMG_Name(img).c_str());
        }
    }

    rtn = RTN_FindByName(img, "recvfrom");
    if (RTN_Valid(rtn)) {
        replaceRecvFromFunction(img, rtn, taintedAdddrs, visitedAddrs, thresholdTriggered, IOCounter);
        if (KnobDebug) {
            PRINT_DEBUG("recvfrom replaced\t\t: %s\n", IMG_Name(img).c_str());
        }
    }

    rtn = RTN_FindByName(img, "recvmsg");
    if (RTN_Valid(rtn)) {
        replaceRecvMsgFunction(img, rtn, taintedAdddrs, visitedAddrs, thresholdTriggered, IOCounter);
        if (KnobDebug) {
            PRINT_DEBUG("recvmsg replaced\t\t: %s\n", IMG_Name(img).c_str());
        }
    }

    rtn = RTN_FindByName(img, "write");
    if (RTN_Valid(rtn)) {
        replaceWriteFunction(img, rtn, taintedAdddrs, taintedRegs);
        if (KnobDebug) {
            PRINT_DEBUG("write replaced\t\t: %s\n", IMG_Name(img).c_str());
        }
    }

    rtn = RTN_FindByName(img, "send");
    if (RTN_Valid(rtn)) {
        replaceSendFunction(img, rtn, taintedAdddrs, taintedRegs);
        if (KnobDebug) {
            PRINT_DEBUG("send replaced\t\t\t: %s\n", IMG_Name(img).c_str());
        }
    }

    rtn = RTN_FindByName(img, "sendto");
    if (RTN_Valid(rtn)) {
        replaceSendToFunction(img, rtn, taintedAdddrs, taintedRegs);
        if (KnobDebug) {
            PRINT_DEBUG("sendto replaced\t\t: %s\n", IMG_Name(img).c_str());
        }
    }

    rtn = RTN_FindByName(img, "sendmsg");
    if (RTN_Valid(rtn)) {
        replaceSendMsgFunction(img, rtn, taintedAdddrs, taintedRegs);
        if (KnobDebug) {
            PRINT_DEBUG("sendmsg replaced\t\t: %s\n", IMG_Name(img).c_str());
        }
    }
}