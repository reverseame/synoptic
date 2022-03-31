#include "pin.H"
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <list>

/* Output file */
FILE* trace;
/* Keep track of tainted addresses by thread */
std::map<pid_t,std::list<UINT64>> threadTaintedAddresses;
/* Keep track of tainted registers by thread */
std::map<pid_t,std::list<REG>> threadTaintedRegs;

bool checkAlreadyRegTainted(REG reg) {
    if (threadTaintedRegs.empty()) {
        return false;
    }

    std::list<REG>::iterator i;
    std::list<REG> taintedRegs = threadTaintedRegs.find(gettid())->second;

    for(i = taintedRegs.begin(); i != taintedRegs.end(); i++){
        if (*i == reg){
            return true;
        }
    }
    return false;
}

bool taintReg(REG reg) {
    pid_t tid = gettid();

    if (checkAlreadyRegTainted(reg) == true) {
        fprintf(trace, "Thread: %d ; [Taint] ; %s is already tainted\n", tid, REG_StringShort(reg).c_str());
        return false;
    }

    std::list<REG> taintedRegs = threadTaintedRegs.find(tid)->second;

    switch(reg){
        case REG_RAX:  taintedRegs.push_front(REG_RAX);
        case REG_EAX:  taintedRegs.push_front(REG_EAX); 
        case REG_AX:   taintedRegs.push_front(REG_AX); 
        case REG_AH:   taintedRegs.push_front(REG_AH); 
        case REG_AL:   taintedRegs.push_front(REG_AL); 
            break;

        case REG_RBX:  taintedRegs.push_front(REG_RBX);
        case REG_EBX:  taintedRegs.push_front(REG_EBX);
        case REG_BX:   taintedRegs.push_front(REG_BX);
        case REG_BH:   taintedRegs.push_front(REG_BH);
        case REG_BL:   taintedRegs.push_front(REG_BL);
            break;

        case REG_RCX:  taintedRegs.push_front(REG_RCX); 
        case REG_ECX:  taintedRegs.push_front(REG_ECX);
        case REG_CX:   taintedRegs.push_front(REG_CX);
        case REG_CH:   taintedRegs.push_front(REG_CH);
        case REG_CL:   taintedRegs.push_front(REG_CL);
            break;

        case REG_RDX:  taintedRegs.push_front(REG_RDX); 
        case REG_EDX:  taintedRegs.push_front(REG_EDX); 
        case REG_DX:   taintedRegs.push_front(REG_DX); 
        case REG_DH:   taintedRegs.push_front(REG_DH); 
        case REG_DL:   taintedRegs.push_front(REG_DL); 
            break;

        case REG_RDI:  taintedRegs.push_front(REG_RDI); 
        case REG_EDI:  taintedRegs.push_front(REG_EDI); 
        case REG_DI:   taintedRegs.push_front(REG_DI); 
        case REG_DIL:  taintedRegs.push_front(REG_DIL); 
            break;

        case REG_RSI:  taintedRegs.push_front(REG_RSI); 
        case REG_ESI:  taintedRegs.push_front(REG_ESI); 
        case REG_SI:   taintedRegs.push_front(REG_SI); 
        case REG_SIL:  taintedRegs.push_front(REG_SIL); 
            break;

        default:
            fprintf(trace, "Thread: %d ; [Taint] ; %s can't be tainted\n", tid, REG_StringShort(reg).c_str());
            return false;
    }

    fprintf(trace, "Thread: %d ; [Taint] ; %s is now tainted\n", tid, REG_StringShort(reg).c_str());
    return true;
}

bool removeRegTainted(REG reg) {
    pid_t tid = gettid();
    std::list<REG> taintedRegs = threadTaintedRegs.find(tid)->second;
    switch(reg){
        case REG_RAX:  taintedRegs.remove(REG_RAX);
        case REG_EAX:  taintedRegs.remove(REG_EAX);
        case REG_AX:   taintedRegs.remove(REG_AX);
        case REG_AH:   taintedRegs.remove(REG_AH);
        case REG_AL:   taintedRegs.remove(REG_AL);
            break;

        case REG_RBX:  taintedRegs.remove(REG_RBX);
        case REG_EBX:  taintedRegs.remove(REG_EBX);
        case REG_BX:   taintedRegs.remove(REG_BX);
        case REG_BH:   taintedRegs.remove(REG_BH);
        case REG_BL:   taintedRegs.remove(REG_BL);
            break;

        case REG_RCX:  taintedRegs.remove(REG_RCX); 
        case REG_ECX:  taintedRegs.remove(REG_ECX);
        case REG_CX:   taintedRegs.remove(REG_CX);
        case REG_CH:   taintedRegs.remove(REG_CH);
        case REG_CL:   taintedRegs.remove(REG_CL);
            break;

        case REG_RDX:  taintedRegs.remove(REG_RDX); 
        case REG_EDX:  taintedRegs.remove(REG_EDX); 
        case REG_DX:   taintedRegs.remove(REG_DX); 
        case REG_DH:   taintedRegs.remove(REG_DH); 
        case REG_DL:   taintedRegs.remove(REG_DL); 
            break;

        case REG_RDI:  taintedRegs.remove(REG_RDI); 
        case REG_EDI:  taintedRegs.remove(REG_EDI); 
        case REG_DI:   taintedRegs.remove(REG_DI); 
        case REG_DIL:  taintedRegs.remove(REG_DIL); 
            break;

        case REG_RSI:  taintedRegs.remove(REG_RSI); 
        case REG_ESI:  taintedRegs.remove(REG_ESI); 
        case REG_SI:   taintedRegs.remove(REG_SI); 
        case REG_SIL:  taintedRegs.remove(REG_SIL); 
            break;

        default:
            return false;
    }
    fprintf(trace, "Thread: %d ; [Taint] ; %s is now freed\n", tid, REG_StringShort(reg).c_str());
    return true;
}

void removeMemTainted(UINT64 addr) {
    pid_t tid = gettid();
    std::list<UINT64> taintedAddresses = threadTaintedAddresses.find(tid)->second;
    taintedAddresses.remove(addr);
    fprintf(trace, "Thread: %d ; [Taint] ; %p is now freed\n", tid, (void*)addr);
}

void addMemTainted(UINT64 addr) {
    pid_t tid = gettid();
    std::list<UINT64> taintedAddresses = threadTaintedAddresses.find(tid)->second;
    taintedAddresses.push_back(addr);
    fprintf(trace, "Thread: %d ; [Taint] ; %p is now tainted\n", tid, (void*)addr);
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

void ReplaceAccept(IMG img, RTN rtn) {
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

void ReplaceClose(IMG img, RTN rtn) {
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
        std::list<UINT64> taintedAddresses;
        std::list<REG> taintedRegs;
        pid_t tid = gettid();

        for (int i = 0; i < ret ; i++) {
            taintedAddresses.push_back((UINT64) *&buf + i);
        }

        threadTaintedAddresses.insert(std::make_pair(tid, taintedAddresses));
        threadTaintedRegs.insert(std::make_pair(tid, taintedRegs));
        fprintf(trace, "Thread: %d ; Function: %s ; [Taint] ; Range: %p-0x%08lx\n", tid, functionName, *&buf, (UINT64) *&buf+ret-1);
    } else if (strcmp("send", functionName) == 0) {
        /* We only want to keep track of server model */
        threadTaintedAddresses.erase(gettid());
        threadTaintedRegs.erase(gettid());
        fprintf(trace, "Thread: %d ; [Taint] ; All tainted information deleted\n", gettid());
    }

    return ret;
}

void ReplaceTCPActivity(IMG img, RTN rtn, const char *functionName) {
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

void ImageLoad(IMG img, VOID *v) {
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
    pid_t tid = gettid();
    std::list<UINT64> taintedAdderess = threadTaintedAddresses.find(tid)->second;
    std::list<UINT64>::iterator i;

    for (i=taintedAdderess.begin(); i!=taintedAdderess.end(); i++) {
        if (*i == memOp) {
            fprintf(trace, "Thread: %d ; Routine: %s ; [%p %s] ; @%p: %s\n", tid, routine, (void*)memOp, mode, (void*)insAddr, insDis.c_str());
            return;
        }
    }

    fprintf(trace, "Thread: %d ; Routine: %s ; @%p: %s\n", tid, routine, (void*) insAddr, insDis.c_str());
}

void ReadMem(INS ins, UINT64 memOp, char* routine, REG reg_r) {
    pid_t tid = gettid();
    std::list<UINT64> taintedAdderess = threadTaintedAddresses.find(tid)->second;
    std::list<UINT64>::iterator i;

    for(i = taintedAdderess.begin(); i != taintedAdderess.end(); i++) {
        if (*i == memOp) {
            fprintf(trace, "Thread: %d ; Routine: %s ; [Taint] ; [%p read] ; @%p: %s\n", tid, routine, (void*)memOp, (void*)INS_Address(ins), INS_Disassemble(ins).c_str());
            taintReg(reg_r);
            return;
        }
    }
    /* if mem != tained and reg == taint => free the reg */
    if (checkAlreadyRegTainted(reg_r)) {
        fprintf(trace, "Thread: %d ; Routine: %s ; [Taint] ; [%p read] ; @%p: %s\n", tid, routine, (void*)memOp, (void*)INS_Address(ins), INS_Disassemble(ins).c_str());
        removeRegTainted(reg_r);
    }
}

void WriteMem(INS ins, UINT64 memOp, char* routine, REG reg_r) {
    if (threadTaintedAddresses.empty()) {
        return;
    }
    pid_t tid = gettid();
    std::list<UINT64> taintedAdderess = threadTaintedAddresses.find(tid)->second;
    std::list<UINT64>::iterator i;

    for(i = taintedAdderess.begin(); i != taintedAdderess.end(); i++) {
        if (*i == memOp) {
            fprintf(trace, "Thread: %d ; Routine: %s ; [Taint] ; [%p written] ; @%p: %s\n", tid, routine, (void*)memOp, (void*)INS_Address(ins), INS_Disassemble(ins).c_str());
            if (!REG_valid(reg_r) || !checkAlreadyRegTainted(reg_r)) {
                removeMemTainted(memOp);
            }
            return;
        }
    }
    if (checkAlreadyRegTainted(reg_r)) {
        fprintf(trace, "Thread: %d ; Routine: %s ; [Taint] ; [%p written] ; @%p: %s\n", tid, routine, (void*)memOp, (void*)INS_Address(ins), INS_Disassemble(ins).c_str());
        addMemTainted(memOp);
    }
}

void spreadRegTaint(INS ins, char* routine, REG reg_r, REG reg_w) {
    pid_t tid = gettid();

    if (REG_valid(reg_w)) {
        if (checkAlreadyRegTainted(reg_w) && (!REG_valid(reg_r) || !checkAlreadyRegTainted(reg_r))) {
            fprintf(trace, "Thread: %d ; Routine: %s ; [Taint] ; Spread ; @%p: %s\n", tid, routine, (void*) INS_Address(ins), INS_Disassemble(ins).c_str());
            fprintf(trace, "Thread: %d ; Routine: %s ; [Taint] ; Output: %s ; Input: %s", tid, routine, REG_StringShort(reg_w).c_str(), (REG_valid(reg_r) ? REG_StringShort(reg_r).c_str() : "constant"));
            removeRegTainted(reg_w);
        } else if (!checkAlreadyRegTainted(reg_w) && checkAlreadyRegTainted(reg_r)) {
            fprintf(trace, "Thread: %d ; Routine: %s ; [Taint] ; Spread ; @%p: %s\n", tid, routine, (void*) INS_Address(ins), INS_Disassemble(ins).c_str());
            fprintf(trace, "Thread: %d ; Routine: %s ; [Taint] ; Output: %s ; Input: %s", tid, routine, REG_StringShort(reg_w).c_str(), REG_StringShort(reg_r).c_str());
            taintReg(reg_w);
        }
    }
}

VOID followData(INS ins, char* routine, REG reg) {
    if (!REG_valid(reg)) {
        return;
    }

    if (checkAlreadyRegTainted(reg)){
        fprintf(trace, "Thread: %d ; Routine: %s ; Follow data ; Indirect call ; @%p: %s\n", gettid(), routine, (void*) INS_Address(ins), INS_Disassemble(ins).c_str());
    }
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
            if (INS_OperandCount(ins) == 2 && INS_MemoryOperandIsRead(ins, 0) && INS_OperandIsReg(ins, 0)) {
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)ReadMem,
                    IARG_PTR, ins,
                    IARG_MEMORYOP_EA, 0,
                    IARG_PTR, routine,
                    IARG_UINT32, INS_OperandReg(ins, 0),
                    IARG_END);
            } else if (INS_OperandCount(ins) == 2 && INS_MemoryOperandIsWritten(ins, 0)){
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)WriteMem,
                    IARG_PTR, ins,
                    IARG_MEMORYOP_EA, 0,
                    IARG_PTR, routine,
                    IARG_UINT32, INS_OperandReg(ins, 1),
                    IARG_END);
            } else if (INS_OperandCount(ins) == 2 && INS_OperandIsReg(ins, 0)){
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)spreadRegTaint,
                    IARG_PTR, ins,
                    IARG_PTR, routine,
                    IARG_UINT32, INS_RegR(ins, 0),
                    IARG_UINT32, INS_RegW(ins, 0),
                    IARG_END);
            } else {
                fprintf(trace, "Thread: %d ; Routine: %s ; @%p: %s (Memory operand count: %d)\n", gettid(), routine, (void*) INS_Address(ins), INS_Disassemble(ins).c_str(), INS_MemoryOperandCount(ins));
            }
            if (INS_OperandCount(ins) > 1 && INS_OperandIsReg(ins, 0)){
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)followData,
                    IARG_PTR, ins,
                    IARG_PTR, routine,
                    IARG_UINT32, INS_RegR(ins, 0),
                    IARG_END);
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
