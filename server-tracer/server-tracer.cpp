/*
* Copyright (C) 2006-2021 Intel Corporation.
* SPDX-License-Identifier: MIT
*/

//  Replace an original function with a custom function defined in the tool using
//  probes.  The replacement function has a different signature from that of the
//  original replaced function.

#include "pin.H"
#include "stdio.h"
#include <sys/types.h>
#include <sys/socket.h>

FILE* trace;

ssize_t NewTCPActivity(AFUNPTR orgFuncptr, CONTEXT* ctx, const char* functionName, int sockfd, void *buf, size_t len, int flags) {
    ssize_t ret;

    PIN_CallApplicationFunction(ctx, PIN_ThreadId(),
                                CALLINGSTD_DEFAULT, orgFuncptr,
                                NULL,
                                PIN_PARG(ssize_t), &ret,
                                PIN_PARG(int), sockfd,
                                PIN_PARG(void*), buf,
                                PIN_PARG(size_t), len,
                                PIN_PARG(int), flags,
                                PIN_PARG_END());

    fprintf(trace, "%s (%ld/%ld): {\n\t", functionName, ret, len);

    for (int i = 0; i < ret; i++) {
        fprintf(trace, "%02x", ((char* )buf)[i]);
    }
    fprintf(trace, ",\n\t\"");
    for (int i = 0; i < ret; i++) {
        fprintf(trace, "%c", ((char* )buf)[i]);
    }
    fprintf(trace, "\"\n}\n");

    return ret;
}

VOID ReplaceTCPActivity(IMG img, RTN rtn, const char* functionName) {
    PROTO proto_tcp_activity = PROTO_Allocate(PIN_PARG(ssize_t), CALLINGSTD_DEFAULT,
                                        NULL,
                                        PIN_PARG(int),      // sockfd
                                        PIN_PARG(void*),    // buf
                                        PIN_PARG(size_t),   // len
                                        PIN_PARG(int),      // flags
                                        PIN_PARG_END());

    RTN_ReplaceSignature(rtn, AFUNPTR(NewTCPActivity),
                                IARG_PROTOTYPE, proto_tcp_activity,
                                IARG_ORIG_FUNCPTR,
                                IARG_CONTEXT,
                                IARG_PTR, functionName,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                                IARG_END);

    PROTO_Free(proto_tcp_activity);

    printf("[*] server-tracer: INFO: %s replaced\t: %s\n", functionName, IMG_Name(img).c_str());
}

VOID ImageLoad(IMG img, VOID* v) {
    RTN rtn;
    printf("[*] server-tracer: INFO: Module loaded\t: %s\n", IMG_Name(img).c_str());

    rtn = RTN_FindByName(img, "recv");
    if (RTN_Valid(rtn)) {
        ReplaceTCPActivity(img, rtn, "recv");
    }

    rtn = RTN_FindByName(img, "send");
    if (RTN_Valid(rtn)) {
        ReplaceTCPActivity(img, rtn, "send");
    }
}

VOID Fini(INT32 code, VOID* v) {
    puts("[*] server-tracer: INFO: Shutting down...");
    fclose(trace);
    puts("[*] server-tracer: INFO: Bye!");
}

int main(int argc, char* argv[]) {
    puts("[*] server-tracer: INFO: Initializating analysis...");
    /* Symbol processing */
    PIN_InitSymbols();

    PIN_Init(argc, argv);

    trace = fopen("trace.log", "a");
    puts("[*] server-tracer: INFO: Logging to trace.log");

    /* Replace calls on image load */
    IMG_AddInstrumentFunction(ImageLoad, 0);

    /* Function called on server exit */
    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram();

    return 0;
}
