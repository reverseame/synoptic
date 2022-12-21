#include "log.h"
#include "util.h"
#include "moduleload_windows.h"
#include "windows_include.h"

#include <string>
#include <iostream>

WINDOWS::INT WSAAPI newConnectFunction(AFUNPTR orgFuncPtr, CONTEXT* ctx, WINDOWS::SOCKET s, const WINDOWS::sockaddr* name, WINDOWS::INT namelen) {
    WINDOWS::INT ret;

    PIN_CallApplicationFunction(ctx, PIN_ThreadId(),
        CALLINGSTD_DEFAULT, orgFuncPtr,
        NULL,
        PIN_PARG(WINDOWS::INT), &ret,
        PIN_PARG(WINDOWS::SOCKET), s,
        PIN_PARG(const WINDOWS::sockaddr*), name,
        PIN_PARG(WINDOWS::INT), namelen,
        PIN_PARG_END());

    LOG_INFO("thread=%u action=connect file-descriptor=%u\n", WINDOWS::GetCurrentThreadId(), s);

    return ret;
}

void replaceConnectFunction(IMG img, RTN rtn) {
    PROTO proto_connect = PROTO_Allocate(PIN_PARG(WINDOWS::INT), CALLINGSTD_DEFAULT,
        NULL,
        PIN_PARG(WINDOWS::SOCKET),          // s
        PIN_PARG(const WINDOWS::sockaddr*), // name
        PIN_PARG(WINDOWS::INT),             // namelen
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

    std::cout << "[*] server-tracer\t: INFO\t: connect replaced\t: " << IMG_Name(img) << std::endl;
}

WINDOWS::SOCKET WSAAPI newAcceptFunction(AFUNPTR orgFuncPtr, CONTEXT* ctx, WINDOWS::SOCKET s, WINDOWS::sockaddr* addr, int* addrlen) {
    WINDOWS::SOCKET ret;

    PIN_CallApplicationFunction(ctx, PIN_ThreadId(),
        CALLINGSTD_DEFAULT, orgFuncPtr,
        NULL,
        PIN_PARG(WINDOWS::SOCKET), &ret,
        PIN_PARG(WINDOWS::SOCKET), s,
        PIN_PARG(WINDOWS::sockaddr*), addr,
        PIN_PARG(int*), addrlen,
        PIN_PARG_END());

    LOG_INFO("thread=%u action=accept file-descriptor=%u\n", WINDOWS::GetCurrentThreadId(), s);

    return ret;
}

void replaceAcceptFunction(IMG img, RTN rtn) {
    PROTO proto_accept = PROTO_Allocate(PIN_PARG(WINDOWS::SOCKET), CALLINGSTD_DEFAULT,
        NULL,
        PIN_PARG(WINDOWS::SOCKET),      // s
        PIN_PARG(WINDOWS::sockaddr*),   // addr
        PIN_PARG(int*),                 // addrlen
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

int WSAAPI newCloseSocketFunction(AFUNPTR orgFuncPtr, CONTEXT* ctx, WINDOWS::SOCKET s) {
    int ret;

    PIN_CallApplicationFunction(ctx, PIN_ThreadId(),
        CALLINGSTD_DEFAULT, orgFuncPtr,
        NULL,
        PIN_PARG(int), &ret,
        PIN_PARG(WINDOWS::SOCKET), s,
        PIN_PARG_END());

    LOG_INFO("thread=%u action=close file-descriptor=%u\n", WINDOWS::GetCurrentThreadId(), s);

    return ret;
}

void replaceCloseSocketFunction(IMG img, RTN rtn) {
    PROTO proto_closesocket = PROTO_Allocate(PIN_PARG(int), CALLINGSTD_DEFAULT,
        NULL,
        PIN_PARG(WINDOWS::SOCKET),      // s
        PIN_PARG_END());

    RTN_ReplaceSignature(rtn, AFUNPTR(newCloseSocketFunction),
        IARG_PROTOTYPE, proto_closesocket,
        IARG_ORIG_FUNCPTR,
        IARG_CONTEXT,
        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
        IARG_END);

    PROTO_Free(proto_closesocket);

    std::cout << "[*] server-tracer\t: INFO\t: closesocket replaced\t: " << IMG_Name(img) << std::endl;
}

int WSAAPI newSend(AFUNPTR orgFuncPtr, CONTEXT* ctx, WINDOWS::SOCKET s, const char* buf, int len, int flags) {
    int ret;

    PIN_CallApplicationFunction(ctx, PIN_ThreadId(),
        CALLINGSTD_DEFAULT, orgFuncPtr,
        NULL,
        PIN_PARG(int), &ret,
        PIN_PARG(WINDOWS::SOCKET), s,
        PIN_PARG(const char*), buf,
        PIN_PARG(int), len,
        PIN_PARG(int), flags,
        PIN_PARG_END());

    LOG_TAINT("thread=%u action=send buffer-address=%p buffer-size=%d content-size=%d buffer-content=\n", WINDOWS::GetCurrentThreadId(), buf, len, ret);

    return ret;
}

void replaceSend(IMG img, RTN rtn) {
    PROTO proto_send = PROTO_Allocate(PIN_PARG(int), CALLINGSTD_DEFAULT,
        NULL,
        PIN_PARG(WINDOWS::SOCKET),  // s
        PIN_PARG(const char*),      // buf
        PIN_PARG(int),              // len
        PIN_PARG(int),              // flags
        PIN_PARG_END());

    RTN_ReplaceSignature(rtn, AFUNPTR(newSend),
        IARG_PROTOTYPE, proto_send,
        IARG_ORIG_FUNCPTR,
        IARG_CONTEXT,
        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
        IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
        IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
        IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
        IARG_END);

    PROTO_Free(proto_send);

    std::cout << "[*] server-tracer\t: INFO\t: send replaced\t\t: " << IMG_Name(img) << std::endl;
}

WINDOWS::INT WSAAPI newRecv(AFUNPTR orgFuncPtr, CONTEXT* ctx, WINDOWS::SOCKET s, WINDOWS::CHAR* buf, WINDOWS::INT len, WINDOWS::INT flags) {
    WINDOWS::INT ret;

    PIN_CallApplicationFunction(ctx, PIN_ThreadId(),
        CALLINGSTD_DEFAULT, orgFuncPtr,
        NULL,
        PIN_PARG(WINDOWS::INT), &ret,
        PIN_PARG(WINDOWS::SOCKET), s,
        PIN_PARG(WINDOWS::CHAR*), buf,
        PIN_PARG(WINDOWS::INT), len,
        PIN_PARG(WINDOWS::INT), flags,
        PIN_PARG_END());

    LOG_TAINT("thread=%u action=recv buffer-address=%p buffer-size=%d content-size=%d buffer-content=", WINDOWS::GetCurrentThreadId(), buf, len, ret);

    for (int i = 0; i < ret; i++) {
        LOG_RAW("%02x", ((char*)buf)[i]);
    }
    LOG_RAW(" range-start=%p range-end=%p\n", buf, (UINT64) buf + ret - 1);

    return ret;
}

void replaceRecv(IMG img, RTN rtn) {
    PROTO proto_recv = PROTO_Allocate(PIN_PARG(WINDOWS::INT), CALLINGSTD_DEFAULT,
        "recv",
        PIN_PARG(WINDOWS::SOCKET),  // s
        PIN_PARG(WINDOWS::CHAR*),   // buf
        PIN_PARG(WINDOWS::INT),     // len
        PIN_PARG(WINDOWS::INT),     // flags
        PIN_PARG_END());

    RTN_ReplaceSignature(rtn, AFUNPTR(newRecv),
        IARG_PROTOTYPE, proto_recv,
        IARG_ORIG_FUNCPTR,
        IARG_CONTEXT,
        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
        IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
        IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
        IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
        IARG_END);

    PROTO_Free(proto_recv);

    std::cout << "[*] server-tracer\t: INFO\t: recv replaced\t\t: " << IMG_Name(img) << std::endl;
}

VOID moduleLoad(IMG img, VOID* v) {
    RTN rtn;

    ADDRINT image_base = IMG_LowAddress(img);
    std::cout << "[*] server-tracer\t: INFO\t: Module loaded\t\t: " << IMG_Name(img) << " (" << hexaddr(image_base) << ")" << std::endl;

    /* Avoid to hook the main executable */
    if (IMG_IsMainExecutable(img)) {
        INFO("Main executable");
        return;
    }

    rtn = RTN_FindByName(img, "recv");
    if (RTN_Valid(rtn)) {
        replaceRecv(img, rtn);
    }

    rtn = RTN_FindByName(img, "send");
    if (RTN_Valid(rtn)) {
        replaceSend(img, rtn);
    }

    rtn = RTN_FindByName(img, "closesocket");
    if (RTN_Valid(rtn)) {
        replaceCloseSocketFunction(img, rtn);
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