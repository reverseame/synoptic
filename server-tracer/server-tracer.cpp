#include "pin.H"
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <list>

struct tainted_address {
    void *address;
    ssize_t size;
};

FILE* trace;                // Output file
int module_count = 0;       // Keep track of nº module loads
std::list<tainted_address> tainted_addresses;

/* This function is called before every instruction is executed */
void TraceInstruction() {
    /* Return inmediatly if there are no buffers of interest */
    if (tainted_addresses.empty()) {
        return;
    }
}

int NewAccept(AFUNPTR orgFuncptr, CONTEXT *ctx, int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    int ret;

    PIN_CallApplicationFunction(ctx, PIN_ThreadId(),
                                CALLINGSTD_DEFAULT, orgFuncptr,
                                NULL,
                                PIN_PARG(int), &ret,
                                PIN_PARG(int), sockfd,
                                PIN_PARG(struct sockaddr*), addr,
                                PIN_PARG(socklen_t*), addrlen,
                                PIN_PARG_END());
    
    fprintf(trace, "Thread: %d ; Function: accept ; File Descriptor: %d\n", gettid(), ret);

    return ret;
}

VOID ReplaceAccept(IMG img, RTN rtn) {
    PROTO proto_accept = PROTO_Allocate(PIN_PARG(int), CALLINGSTD_DEFAULT,
                                        NULL,
                                        PIN_PARG(int),              // sockfd
                                        PIN_PARG(struct sockaddr*), // addr
                                        PIN_PARG(socklen_t*),       // addrlen
                                        PIN_PARG_END());

    RTN_ReplaceSignature(rtn, AFUNPTR(NewAccept),
                                IARG_PROTOTYPE, proto_accept,
                                IARG_ORIG_FUNCPTR,
                                IARG_CONTEXT,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                IARG_END);

    PROTO_Free(proto_accept);

    printf("[*] server-tracer: INFO: accept replaced\t: %s\n", IMG_Name(img).c_str());
}

int NewClose(AFUNPTR orgFuncptr, CONTEXT *ctx, int fd) {
    int ret;

    struct stat statbuf;
    if (fstat(fd, &statbuf) != -1) {
        /* Check if fd is a socket */
        if (S_ISSOCK(statbuf.st_mode)) {
            fprintf(trace, "Thread: %d ; Function: close ; File Descriptor: %d\n", gettid(), fd);
        }
    }

    PIN_CallApplicationFunction(ctx, PIN_ThreadId(),
                                CALLINGSTD_DEFAULT, orgFuncptr,
                                NULL,
                                PIN_PARG(int), &ret,
                                PIN_PARG(int), fd,
                                PIN_PARG_END());

    return ret;
}

VOID ReplaceClose(IMG img, RTN rtn) {
    PROTO proto_close = PROTO_Allocate(PIN_PARG(int), CALLINGSTD_DEFAULT,
                                        NULL,
                                        PIN_PARG(int),      // fd
                                        PIN_PARG_END());

    RTN_ReplaceSignature(rtn, AFUNPTR(NewClose),
                                IARG_PROTOTYPE, proto_close,
                                IARG_ORIG_FUNCPTR,
                                IARG_CONTEXT,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                IARG_END);

    PROTO_Free(proto_close);

    printf("[*] server-tracer: INFO: close replaced\t\t: %s\n", IMG_Name(img).c_str());
}

ssize_t NewTCPActivity(AFUNPTR orgFuncptr, CONTEXT *ctx, const char *functionName, int sockfd, void *buf, size_t len, int flags) {
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

    fprintf(trace, "Thread: %d ; Function: %s ; Buffer Address: %p ; Buffer size: %ld ; Content size: %ld ; Buffer Content: ", gettid(), functionName, (void*) &buf, len, ret);

    for (int i = 0; i < ret; i++) {
        fprintf(trace, "%02x", ((char* )buf)[i]);
    }
    fprintf(trace, "\n");

    if (strcmp("recv", functionName) == 0) {
        tainted_address tainted;
        tainted.address = &buf;
        tainted.size = ret;
        tainted_addresses.push_back(tainted);
        fprintf(trace, "Thread: %d ; Tainted ; Function: %s ; Buffer Address: %p ; Buffer size: %ld\n", gettid(), functionName, tainted.address, tainted.size);
    } else if (strcmp("send", functionName) == 0) {
        /* We only want to keep track of server model */
        tainted_addresses.clear();
    }

    return ret;
}

VOID ReplaceTCPActivity(IMG img, RTN rtn, const char *functionName) {
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

    printf("[*] server-tracer: INFO: %s replaced\t\t: %s\n", functionName, IMG_Name(img).c_str());
}

VOID ImageLoad(IMG img, VOID *v) {
    RTN rtn;
    printf("[*] server-tracer: INFO: Module loaded\t\t: %s\n", IMG_Name(img).c_str());

    /* Avoid to hook first module loaded a.k.a main executable */
    if (module_count == 0) {
        printf("[*] server-tracer: INFO: Main module not hooked\t: %s\n", IMG_Name(img).c_str());
        module_count++;
        return;
    }

    rtn = RTN_FindByName(img, "recv");
    if (RTN_Valid(rtn)) {
        ReplaceTCPActivity(img, rtn, "recv");
    }

    rtn = RTN_FindByName(img, "send");
    if (RTN_Valid(rtn)) {
        ReplaceTCPActivity(img, rtn, "send");
    }

    rtn = RTN_FindByName(img, "close");
    if (RTN_Valid(rtn)) {
        ReplaceClose(img, rtn);
    }

    rtn = RTN_FindByName(img, "accept");
    if (RTN_Valid(rtn)) {
        ReplaceAccept(img, rtn);
    }
}

VOID Instruction(INS ins, VOID *v) {
    /* Insert a call before every instruction */
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)TraceInstruction, IARG_END);
}

VOID Fini(INT32 code, VOID *v) {
    puts("[*] server-tracer: INFO: Shutting down...");
    fprintf(trace, "-----END TRACE-----\n");
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
    fprintf(trace, "-----BEGIN TRACE-----\n");

    /* Replace calls on image load */
    IMG_AddInstrumentFunction(ImageLoad, 0);

    /* Instrument instructions */
    INS_AddInstrumentFunction(Instruction, 0);

    /* Function called on server exit */
    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram();

    return 0;
}
