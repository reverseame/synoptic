#include "pin.H"
#include <set>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>

/* Output file */
FILE* trace;
/* Keep track of tainted addresses by thread */
std::set<ADDRINT> taintedAdddrs;

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
    
    fprintf(trace, "level=info thread=%d action=connect file-descriptor=%d\n", gettid(), sockfd);

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

    printf("[*] server-tracer\t: INFO\t: connect replaced\t: %s\n", IMG_Name(img).c_str());
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
    
    fprintf(trace, "level=info thread=%d action=accept file-descriptor=%d\n", gettid(), ret);

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

    printf("[*] server-tracer\t: INFO\t: accept replaced\t: %s\n", IMG_Name(img).c_str());
}

int newCloseFunction(AFUNPTR orgFuncPtr, CONTEXT *ctx, int fd) {
    int ret;

    struct stat statbuf;
    if (fstat(fd, &statbuf) != -1) {
        /* Check if fd is a socket */
        if (S_ISSOCK(statbuf.st_mode)) {
            fprintf(trace, "level=info thread=%d action=close file-descriptor=%d\n", gettid(), fd);
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

    printf("[*] server-tracer\t: INFO\t: close replaced\t: %s\n", IMG_Name(img).c_str());
}

ssize_t newTCPActivityFunction(AFUNPTR orgFuncPtr, CONTEXT *ctx, const char *functionName, int sockfd, void *buf, size_t len, int flags) {
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

    pid_t tid = gettid();

    fprintf(trace, "level=taint thread=%d action=%s buffer-address=%p buffer-size=%ld content-size=%ld buffer-content=", tid, functionName, *&buf, len, ret);
    for (int i = 0; i < ret; i++) {
        fprintf(trace, "%02x", ((char* )buf)[i]);
    }
    fprintf(trace, " range-start=%p range-end=0x%08lx\n", *&buf, (UINT64) *&buf+ret-1);

    if (strcmp(functionName, "recv") == 0) {
        /* Taint all recv data at byte level */
        for (int i = 0; i < ret ; i++) {
            taintedAdddrs.insert((UINT64) *&buf + i);
        }
    } else if (strcmp(functionName, "send") == 0) {
        taintedAdddrs.clear();
        fflush(trace);
    }

    return ret;
}

void replaceTCPActivityFunction(IMG img, RTN rtn, const char *functionName) {
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
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                                IARG_END);

    PROTO_Free(proto_tcp_activity);

    printf("[*] server-tracer\t: INFO\t: %s replaced\t\t: %s\n", functionName, IMG_Name(img).c_str());
}

void moduleLoad(IMG img, VOID *v) {
    RTN rtn;

    ADDRINT image_base = IMG_LowAddress(img);
    printf("[*] server-tracer\t: INFO\t: Module loaded\t\t: %s (0x%08lx)\n", IMG_Name(img).c_str(), image_base);

    /* Avoid to hook the main executable */
    if (IMG_IsMainExecutable(img)) {
        fprintf(trace, "level=info thread=%d action=relocate image-base=0x%08lx\n", gettid(), image_base);
        return;
    }

    rtn = RTN_FindByName(img, "recv");
    if (RTN_Valid(rtn)) {
        replaceTCPActivityFunction(img, rtn, "recv");
    }

    rtn = RTN_FindByName(img, "send");
    if (RTN_Valid(rtn)) {
        replaceTCPActivityFunction(img, rtn, "send");
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

void traceCall(ADDRINT insAddr, std::string insDis, char* routine, char* callType, ADDRINT targetAddr) {
    std::string target = RTN_FindNameByAddress(targetAddr);

    if (target.empty()) {
        target = "unknown";
    }

    fprintf(trace, "level=info thread=%d routine=\"%s\" ins-addr=0x%08lx ins-dis=\"%s\" action=%s target=\"%s\"\n", gettid(), routine, insAddr, insDis.c_str(), callType, target.c_str());
}

void traceMemoryRead(ADDRINT insAddr, std::string insDis, char* routine, ADDRINT memoryAddr) {
    if (std::find(taintedAdddrs.begin(), taintedAdddrs.end(), memoryAddr) != taintedAdddrs.end()) {
        fprintf(trace, "level=taint thread=%d routine=\"%s\" ins-addr=0x%08lx ins-dis=\"%s\" action=memory-read memory-addr=0x%08lx\n", gettid(), routine, insAddr, insDis.c_str(), memoryAddr);
    } else {
        fprintf(trace, "level=info thread=%d routine=\"%s\" ins-addr=0x%08lx ins-dis=\"%s\"\n", gettid(), routine, insAddr, insDis.c_str());
    }
}

void traceMemoryWrite(ADDRINT insAddr, std::string insDis, char* routine, ADDRINT memoryAddr) {
    if (std::find(taintedAdddrs.begin(), taintedAdddrs.end(), memoryAddr) != taintedAdddrs.end()) {
        fprintf(trace, "level=taint thread=%d routine=\"%s\" ins-addr=0x%08lx ins-dis=\"%s\" action=memory-write memory-addr=0x%08lx\n", gettid(), routine, insAddr, insDis.c_str(), memoryAddr);
    } else {
        fprintf(trace, "level=info thread=%d routine=\"%s\" ins-addr=0x%08lx ins-dis=\"%s\"\n", gettid(), routine, insAddr, insDis.c_str());
    }
}

void instructionExec(INS ins, void *v) {
    /* Return inmediatly if there are no buffers of interest */
    if (taintedAdddrs.empty()) {
        return;
    }

    const char* routine = "unknown";
    if (RTN_Valid(INS_Rtn(ins))) {
        routine = RTN_Name(INS_Rtn(ins)).c_str();
    }

    IMG img = IMG_FindByAddress(INS_Address(ins));

    /* Just analyze the main executable */
    if (IMG_Valid(img) && IMG_IsMainExecutable(img)) {
        if (INS_IsCall(ins)) {
            if (INS_IsDirectControlFlow(ins)) {
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)traceCall,
                    IARG_INST_PTR,
                    IARG_PTR, new std::string(INS_Disassemble(ins)),
                    IARG_PTR, routine,
                    IARG_PTR, "direct-call",
                    IARG_BRANCH_TARGET_ADDR,
                    IARG_END);
                return;
            } else if (INS_IsIndirectControlFlow(ins)) {
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)traceCall,
                    IARG_INST_PTR,
                    IARG_PTR, new std::string(INS_Disassemble(ins)),
                    IARG_PTR, routine,
                    IARG_PTR, "indirect-call",
                    IARG_BRANCH_TARGET_ADDR,
                    IARG_END);
                return;
            }
        } else if (INS_IsMemoryRead(ins)) {
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)traceMemoryRead,
                IARG_INST_PTR,
                IARG_PTR, new std::string(INS_Disassemble(ins)),
                IARG_PTR, routine,
                IARG_MEMORYREAD_EA,
                IARG_END);
            return;
        } else if (INS_IsMemoryWrite(ins)) {
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)traceMemoryWrite,
                IARG_INST_PTR,
                IARG_PTR, new std::string(INS_Disassemble(ins)),
                IARG_PTR, routine,
                IARG_MEMORYWRITE_EA,
                IARG_END);
            return;
        }

        fprintf(trace, "level=info thread=%d routine=\"%s\" ins-addr=0x%08lx ins-dis=\"%s\"\n", gettid(), routine, INS_Address(ins), INS_Disassemble(ins).c_str());
    }
}

void fini(INT32 code, void *v) {
    fprintf(trace, "-----END TRACE-----\n");
    fclose(trace);
    puts("[*] server-tracer\t: INFO\t: Analysis finished");
}

int main(int argc, char* argv[]) {
    puts("[*] server-tracer\t: INFO\t: Analysis started");
    /* Symbol processing */
    PIN_InitSymbols();

    PIN_Init(argc,argv);

    trace = fopen("trace.log", "a");
    puts("[*] server-tracer\t: INFO\t: Log file\t\t: trace.log");
    fprintf(trace, "-----BEGIN TRACE-----\n");

    PIN_SetSyntaxIntel();

    /* Replace calls on module load */
    IMG_AddInstrumentFunction(moduleLoad, 0);

    /* Instrument instructions */
    INS_AddInstrumentFunction(instructionExec, 0);

    /* Function called on server exit */
    PIN_AddFiniFunction(fini, 0);

    PIN_StartProgram();

    return 0;
}
