#include "pin.H"
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <list>

FILE* trace;        // Output file

/* Keep tainted address by thread */
std::map<pid_t,std::list<UINT64>> threadTaintedAddresses;

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
        std::list<UINT64> taintedAdderess;
        pid_t tid = gettid();
        for (int i = 0; i < ret ; i++) {
            taintedAdderess.push_back((UINT64) *&buf + i);
        }
        threadTaintedAddresses.insert(std::make_pair(tid, taintedAdderess));
        fprintf(trace, "Thread: %d ; Function: %s ; [Tainted]  %p-0x%08lx\n", tid, functionName, *&buf, (UINT64) *&buf+ret-1);
    } else if (strcmp("send", functionName) == 0) {
        /* We only want to keep track of server model */
        threadTaintedAddresses.erase(gettid());
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
    if (IMG_IsMainExecutable(img)) {
        printf("[*] server-tracer: INFO: Main module not hooked\t: %s\n", IMG_Name(img).c_str());
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

void TraceMem(const char* mode, UINT64 insAddr, UINT64 memOp, char* routine, std::string insDis) {
    if (threadTaintedAddresses.empty()) {
        return;
    }

    pid_t pid = gettid();
    std::list<UINT64> taintedAdderess = threadTaintedAddresses.find(pid)->second;
    std::list<UINT64>::iterator i;

    for (i=taintedAdderess.begin(); i!=taintedAdderess.end(); i++) {
        if (*i == memOp) {
            fprintf(trace, "Thread: %d ; Routine: %s ; [%p %s] ; @%p: %s\n", pid, routine, (void*)memOp, mode, (void*)insAddr, insDis.c_str());
            return;
        }
    }

    fprintf(trace, "Thread: %d ; Routine: %s ; @%p: %s\n", gettid(), routine, (void*) insAddr, insDis.c_str());
}

void Instruction(INS ins, void *v) {
    /* Return inmediatly if there are no buffers of interest */
    if (threadTaintedAddresses.empty()) {
        return;
    }

    const char* routine = "unknown";
    if(RTN_Valid(INS_Rtn(ins))) {
        routine = RTN_Name(INS_Rtn(ins)).c_str();
    }
    IMG img = IMG_FindByAddress(INS_Address(ins));

    /* Just analyze the main executable */
    if (IMG_Valid(img) && IMG_IsMainExecutable(img)) {
        if (INS_IsCall(ins)) {
            if (INS_IsDirectControlFlow(ins)) {
                ADDRINT target = INS_DirectControlFlowTargetAddress(ins);
                fprintf(trace, "Thread: %d ; Routine: %s ; Call: %s; @%p: %s\n", gettid(), routine, RTN_FindNameByAddress(target).c_str(), (void*) INS_Address(ins), INS_Disassemble(ins).c_str());
            } else {
                /* Target address is provided through memory or through a register */
                fprintf(trace, "Thread: %d ; Routine: %s ; Indirect call ; @%p: %s\n", gettid(), routine, (void*) INS_Address(ins), INS_Disassemble(ins).c_str());
            }
        } else if (INS_IsMemoryRead(ins) || INS_IsMemoryWrite(ins)) {
            std::string insDis = INS_Disassemble(ins);
            UINT32 memOperands = INS_MemoryOperandCount(ins);
            for (UINT32 memOp = 0; memOp < memOperands; memOp++) {
                if (INS_MemoryOperandIsRead(ins, memOp)) {
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)TraceMem,
                        IARG_PTR, "read",
                        IARG_INST_PTR,
                        IARG_MEMORYOP_EA, memOp,
                        IARG_PTR, routine,
                        IARG_PTR, new std::string(insDis),
                        IARG_END);
                }
                /* for example, movsb instruction reads and writes to memomy */
                if (INS_MemoryOperandIsWritten(ins, memOp)) {
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)TraceMem,
                        IARG_PTR, "written",
                        IARG_INST_PTR,
                        IARG_MEMORYOP_EA, memOp,
                        IARG_PTR, routine,
                        IARG_PTR, new std::string(insDis),
                        IARG_END);
                }
            }
        } else {
            fprintf(trace, "Thread: %d ; Routine: %s ; @%p: %s\n", gettid(), routine, (void*) INS_Address(ins), INS_Disassemble(ins).c_str());
        }
    }
}

void Fini(INT32 code, void *v) {
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

    PIN_SetSyntaxIntel();

    /* Replace calls on image load */
    IMG_AddInstrumentFunction(ImageLoad, 0);

    /* Instrument instructions */
    INS_AddInstrumentFunction(Instruction, 0);

    /* Function called on server exit */
    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram();

    return 0;
}
