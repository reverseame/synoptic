#include "log.h"
#include "moduleload_windows.h"
#include "windows_include.h"

#include <set>
#include <string>
#include <iostream>

WINDOWS::INT WSAAPI newConnectFunction(AFUNPTR orgFuncPtr, CONTEXT* ctx, WINDOWS::SOCKET s, const WINDOWS::sockaddr* name, WINDOWS::INT namelen) {
    WINDOWS::INT ret;

    PIN_CallApplicationFunction(ctx, PIN_ThreadId(),
        CALLINGSTD_STDCALL, orgFuncPtr,
        NULL,
        PIN_PARG(WINDOWS::INT), &ret,
        PIN_PARG(WINDOWS::SOCKET), s,
        PIN_PARG(const WINDOWS::sockaddr*), name,
        PIN_PARG(WINDOWS::INT), namelen,
        PIN_PARG_END());

    LOG_INFO("action=connect file-descriptor=%u\n", s);

    return ret;
}

void replaceConnectFunction(IMG img, RTN rtn) {
    PROTO proto_connect = PROTO_Allocate(PIN_PARG(WINDOWS::INT), CALLINGSTD_STDCALL,    // NOTE: CALLINGSTD_DEFAULT generates Run-Time Check Failure #0
        "connect",
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

    std::cerr << "[*] server-tracer\t: DEBUG\t: connect replaced\t\t: " << IMG_Name(img) << std::endl;
}

WINDOWS::SOCKET WSAAPI newAcceptFunction(AFUNPTR orgFuncPtr, CONTEXT* ctx, WINDOWS::SOCKET s, WINDOWS::sockaddr* addr, WINDOWS::INT* addrlen) {
    WINDOWS::SOCKET ret;

    PIN_CallApplicationFunction(ctx, PIN_ThreadId(),
        CALLINGSTD_STDCALL, orgFuncPtr,
        NULL,
        PIN_PARG(WINDOWS::SOCKET), &ret,
        PIN_PARG(WINDOWS::SOCKET), s,
        PIN_PARG(WINDOWS::sockaddr*), addr,
        PIN_PARG(WINDOWS::INT*), addrlen,
        PIN_PARG_END());

    LOG_INFO("action=accept file-descriptor=%u\n", s);

    return ret;
}

void replaceAcceptFunction(IMG img, RTN rtn) {
    PROTO proto_accept = PROTO_Allocate(PIN_PARG(WINDOWS::SOCKET), CALLINGSTD_STDCALL,
        "accept",
        PIN_PARG(WINDOWS::SOCKET),      // s
        PIN_PARG(WINDOWS::sockaddr*),   // addr
        PIN_PARG(WINDOWS::INT*),        // addrlen
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

    std::cerr << "[*] server-tracer\t: DEBUG\t: accept replaced\t\t: " << IMG_Name(img) << std::endl;
}

WINDOWS::INT WSAAPI newCloseSocketFunction(AFUNPTR orgFuncPtr, CONTEXT* ctx, WINDOWS::SOCKET s) {
    WINDOWS::INT ret;

    PIN_CallApplicationFunction(ctx, PIN_ThreadId(),
        CALLINGSTD_STDCALL, orgFuncPtr,
        NULL,
        PIN_PARG(WINDOWS::INT), &ret,
        PIN_PARG(WINDOWS::SOCKET), s,
        PIN_PARG_END());

    LOG_INFO("action=close file-descriptor=%u\n", s);

    return ret;
}

void replaceCloseSocketFunction(IMG img, RTN rtn) {
    PROTO proto_closesocket = PROTO_Allocate(PIN_PARG(WINDOWS::INT), CALLINGSTD_STDCALL,
        "closesocket",
        PIN_PARG(WINDOWS::SOCKET),  // s
        PIN_PARG_END());

    RTN_ReplaceSignature(rtn, AFUNPTR(newCloseSocketFunction),
        IARG_PROTOTYPE, proto_closesocket,
        IARG_ORIG_FUNCPTR,
        IARG_CONTEXT,
        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
        IARG_END);

    PROTO_Free(proto_closesocket);

    std::cerr << "[*] server-tracer\t: DEBUG\t: closesocket replaced\t\t: " << IMG_Name(img) << std::endl;
}

WINDOWS::INT WSAAPI newSend(AFUNPTR orgFuncPtr, CONTEXT* ctx, std::set<ADDRINT> &taintedAdddrs, bool(&taintedRegs)[REG_LAST], WINDOWS::SOCKET s, const WINDOWS::CHAR* buf, WINDOWS::INT len, WINDOWS::INT flags) {
    WINDOWS::INT ret;

    PIN_CallApplicationFunction(ctx, PIN_ThreadId(),
        CALLINGSTD_STDCALL, orgFuncPtr,
        NULL,
        PIN_PARG(WINDOWS::INT), &ret,
        PIN_PARG(WINDOWS::SOCKET), s,
        PIN_PARG(const WINDOWS::CHAR*), buf,
        PIN_PARG(WINDOWS::INT), len,
        PIN_PARG(WINDOWS::INT), flags,
        PIN_PARG_END());

    LOG_TAINT("action=send buffer-address=%p buffer-size=%d content-size=%d", buf, len, ret);

    if (ret > 0) {
        LOG_RAW(" buffer-content=");
        for (int i = 0; i < ret; i++) {
            LOG_RAW("%02x", ((char*)buf)[i]);
        }
        LOG_RAW(" range-start=%p range-end=%p", buf, (UINT64)buf + ret - 1);
    }

    LOG_RAW("\n");

    /* Free all tainted data */
    taintedAdddrs.clear();

    for (int i = 0; i < REG_LAST; i++) {
        taintedRegs[i] = false;
    }

    return ret;
}

void replaceSend(IMG img, RTN rtn, std::set<ADDRINT> &taintedAdddrs, bool(&taintedRegs)[REG_LAST]) {
    PROTO proto_send = PROTO_Allocate(PIN_PARG(WINDOWS::INT), CALLINGSTD_STDCALL,
        "send",
        PIN_PARG(WINDOWS::SOCKET),      // s
        PIN_PARG(const WINDOWS::CHAR*), // buf
        PIN_PARG(WINDOWS::INT),         // len
        PIN_PARG(WINDOWS::INT),         // flags
        PIN_PARG_END());

    RTN_ReplaceSignature(rtn, AFUNPTR(newSend),
        IARG_PROTOTYPE, proto_send,
        IARG_ORIG_FUNCPTR,
        IARG_CONTEXT,
        IARG_PTR, &taintedAdddrs,
        IARG_PTR, &taintedRegs,
        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
        IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
        IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
        IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
        IARG_END);

    PROTO_Free(proto_send);

    std::cerr << "[*] server-tracer\t: DEBUG\t: send replaced\t\t\t: " << IMG_Name(img) << std::endl;
}

WINDOWS::INT WSAAPI newRecv(AFUNPTR orgFuncPtr, CONTEXT* ctx, std::set<ADDRINT> &taintedAdddrs, WINDOWS::SOCKET s, WINDOWS::CHAR* buf, WINDOWS::INT len, WINDOWS::INT flags) {
    WINDOWS::INT ret;

    PIN_CallApplicationFunction(ctx, PIN_ThreadId(),
        CALLINGSTD_STDCALL, orgFuncPtr,
        NULL,
        PIN_PARG(WINDOWS::INT), &ret,
        PIN_PARG(WINDOWS::SOCKET), s,
        PIN_PARG(WINDOWS::CHAR*), buf,
        PIN_PARG(WINDOWS::INT), len,
        PIN_PARG(WINDOWS::INT), flags,
        PIN_PARG_END());

    LOG_TAINT("action=recv file-descriptor=%u buffer-address=%p buffer-size=%d content-size=%d", s, buf, len, ret);

    if (ret > 0) {
        LOG_RAW(" buffer-content=");
        for (int i = 0; i < ret; i++) {
            taintedAdddrs.insert((UINT64) buf + i);
            LOG_RAW("%02x", ((char*)buf)[i]);
        }
        LOG_RAW(" range-start=%p range-end=%p", buf, (UINT64) buf + ret - 1);
    }

    LOG_RAW("\n");

    return ret;
}

void replaceRecv(IMG img, RTN rtn, std::set<ADDRINT> &taintedAdddrs) {
    PROTO proto_recv = PROTO_Allocate(PIN_PARG(WINDOWS::INT), CALLINGSTD_STDCALL,
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
        IARG_PTR, &taintedAdddrs,
        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
        IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
        IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
        IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
        IARG_END);

    PROTO_Free(proto_recv);

    std::cerr << "[*] server-tracer\t: DEBUG\t: recv replaced\t\t\t: " << IMG_Name(img) << std::endl;
}

void replaceSignatures(bool KnobDebug, IMG img, std::set<ADDRINT> &taintedAdddrs, bool(&taintedRegs)[REG_LAST], std::set<ADDRINT> &visitedAddrs) {
    RTN rtn;

    rtn = RTN_FindByName(img, "recv");
    if (RTN_Valid(rtn)) {
        replaceRecv(img, rtn, taintedAdddrs);
    }

    rtn = RTN_FindByName(img, "send");
    if (RTN_Valid(rtn)) {
        replaceSend(img, rtn, taintedAdddrs, taintedRegs);
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