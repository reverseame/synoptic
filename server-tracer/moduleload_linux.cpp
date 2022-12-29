#include "log.h"
#include "moduleload_linux.h"

#include <sys/stat.h>
#include <sys/socket.h>

#include <set>
#include <string>
#include <iostream>

int newConnectFunction(AFUNPTR orgFuncPtr, CONTEXT *ctx, int sockfd, struct sockaddr *addr, socklen_t addrLen) {
    int ret;

    PIN_CallApplicationFunction(ctx, PIN_ThreadId(),
                                CALLINGSTD_DEFAULT, orgFuncPtr,
                                NULL,
                                PIN_PARG(int), &ret,
                                PIN_PARG(int), sockfd,
                                PIN_PARG(struct sockaddr*), addr,
                                PIN_PARG(socklen_t), addrLen,
                                PIN_PARG_END());
    
    LOG_INFO("action=connect file-descriptor=%d\n", sockfd);

    return ret;
}

void replaceConnectFunction(IMG img, RTN rtn) {
    PROTO proto_connect = PROTO_Allocate(PIN_PARG(int), CALLINGSTD_DEFAULT,
                                        NULL,
                                        PIN_PARG(int),              // sockfd
                                        PIN_PARG(struct sockaddr*), // addr
                                        PIN_PARG(socklen_t),        // addrlen
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

    std::cout "[*] server-tracer\t: INFO\t: connect replaced\t: " << IMG_Name(img) << std::endl;
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
    
    LOG_INFO("action=accept file-descriptor=%d\n", ret);

    return ret;
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

    std::cout << "[*] server-tracer\t: INFO\t: accept replaced\t: " << IMG_Name(img) << std::endl;
}

int newCloseFunction(AFUNPTR orgFuncPtr, CONTEXT *ctx, int fd) {
    int ret;

    struct stat statbuf;
    if (fstat(fd, &statbuf) != -1) {
        /* Check if fd is a socket */
        if (S_ISSOCK(statbuf.st_mode)) {
            LOG_INFO("action=close file-descriptor=%d\n", fd);
        }
    }

    PIN_CallApplicationFunction(ctx, PIN_ThreadId(),
                                CALLINGSTD_DEFAULT, orgFuncPtr,
                                NULL,
                                PIN_PARG(int), &ret,
                                PIN_PARG(int), fd,
                                PIN_PARG_END());

    return ret;
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

    std::cout << "[*] server-tracer\t: INFO\t: close replaced\t: " << IMG_Name(img) << std::endl;
}

ssize_t newTCPActivityFunction(AFUNPTR orgFuncPtr, CONTEXT *ctx, const char *functionName, std::set<ADDRINT> &taintedAdddrs, bool(&taintedRegs)[REG_LAST], int sockfd, void *buf, size_t len, int flags) {
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

    LOG_TAINT("action=%s buffer-address=%p buffer-size=%ld content-size=%ld", functionName, buf, len, ret);

    if (ret > 0) {                                
        LOG_RAW(" buffer-content=");
        for (int i = 0; i < ret; i++) {
            LOG_RAW("%02x", ((char* )buf)[i]);
        }
        LOG_RAW(" range-start=%p range-end=0x%08lx", buf, (UINT64) buf + ret - 1);
    }

    LOG_RAW("\n");

    if (strcmp(functionName, "recv") == 0) {
        /* Taint all recv data at byte level */
        for (int i = 0; i < ret; i++) {
            taintedAdddrs.insert((UINT64) buf + i);
        }
    } else if (strcmp(functionName, "send") == 0) {
        /* Free all tainted data */
        taintedAdddrs.clear();
        for (int i = 0; i < REG_LAST; i++) {
            taintedRegs[i] = false;
        }
    }

    return ret;
}

void replaceTCPActivityFunction(IMG img, RTN rtn, const char *functionName, std::set<ADDRINT> &taintedAdddrs, bool(&taintedRegs)[REG_LAST]) {
    PROTO proto_tcp_activity = PROTO_Allocate(PIN_PARG(ssize_t), CALLINGSTD_DEFAULT,
                                        NULL,
                                        PIN_PARG(int),      // sockfd
                                        PIN_PARG(void*),    // buf
                                        PIN_PARG(size_t),   // len
                                        PIN_PARG(int),      // flags
                                        PIN_PARG_END());

    RTN_ReplaceSignature(rtn, AFUNPTR(newTCPActivityFunction),
                                IARG_PROTOTYPE, proto_tcp_activity,
                                IARG_ORIG_FUNCPTR,
                                IARG_CONTEXT,
                                IARG_PTR, functionName,
                                IARG_PTR, &taintedAdddrs,
                                IARG_PTR, &taintedRegs,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                                IARG_END);

    PROTO_Free(proto_tcp_activity);

    std::cout << "[*] server-tracer\t: INFO\t: " << functionName << "replaced\t\t\t: " << IMG_Name(img) << std::endl;
}

void replaceSignatures(IMG img, std::set<ADDRINT> &taintedAdddrs, bool(&taintedRegs)[REG_LAST]) {
    RTN rtn;

    rtn = RTN_FindByName(img, "recv");
    if (RTN_Valid(rtn)) {
        replaceTCPActivityFunction(img, rtn, taintedAdddrs, taintedRegs);
    }

    rtn = RTN_FindByName(img, "send");
    if (RTN_Valid(rtn)) {
        replaceTCPActivityFunction(img, rtn, taintedAdddrs, taintedRegs);
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