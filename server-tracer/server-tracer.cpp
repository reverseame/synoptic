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
std::map<pid_t,std::list<UINT64>> thread_tainted_addresses;
/* Keep track of tainted registers by thread */
std::map<pid_t,std::list<REG>> thread_tainted_regs;
/* Keep track of session info by thread */
std::map<pid_t,std::list<UINT64>> thread_session_changes;

bool checkAlreadyRegTainted(REG reg) {
    if (thread_tainted_regs.empty()) {
        return false;
    }

    std::list<REG>::iterator i;
    std::list<REG> tainted_regs = thread_tainted_regs.find(gettid())->second;

    for(i = tainted_regs.begin(); i != tainted_regs.end(); i++){
        if (*i == reg){
            return true;
        }
    }
    return false;
}

bool taintReg(REG reg) {
    if (thread_tainted_regs.empty()) {
        return false;
    }

    pid_t tid = gettid();

    if (checkAlreadyRegTainted(reg)) {
        fprintf(trace, "level=taint thread=%d action=reg message=\"%s is already tainted\"\n", tid, REG_StringShort(reg).c_str());
        return false;
    }

    std::list<REG> tainted_regs = thread_tainted_regs.find(tid)->second;

    switch(reg) {
        case REG_RAX:  tainted_regs.push_front(REG_RAX);
        case REG_EAX:  tainted_regs.push_front(REG_EAX); 
        case REG_AX:   tainted_regs.push_front(REG_AX); 
        case REG_AH:   tainted_regs.push_front(REG_AH); 
        case REG_AL:   tainted_regs.push_front(REG_AL); 
            break;

        case REG_RBX:  tainted_regs.push_front(REG_RBX);
        case REG_EBX:  tainted_regs.push_front(REG_EBX);
        case REG_BX:   tainted_regs.push_front(REG_BX);
        case REG_BH:   tainted_regs.push_front(REG_BH);
        case REG_BL:   tainted_regs.push_front(REG_BL);
            break;

        case REG_RCX:  tainted_regs.push_front(REG_RCX); 
        case REG_ECX:  tainted_regs.push_front(REG_ECX);
        case REG_CX:   tainted_regs.push_front(REG_CX);
        case REG_CH:   tainted_regs.push_front(REG_CH);
        case REG_CL:   tainted_regs.push_front(REG_CL);
            break;

        case REG_RDX:  tainted_regs.push_front(REG_RDX); 
        case REG_EDX:  tainted_regs.push_front(REG_EDX); 
        case REG_DX:   tainted_regs.push_front(REG_DX); 
        case REG_DH:   tainted_regs.push_front(REG_DH); 
        case REG_DL:   tainted_regs.push_front(REG_DL); 
            break;

        case REG_RSI:  tainted_regs.push_front(REG_RSI); 
        case REG_ESI:  tainted_regs.push_front(REG_ESI); 
        case REG_SI:   tainted_regs.push_front(REG_SI); 
        case REG_SIL:  tainted_regs.push_front(REG_SIL); 
            break;

        case REG_RDI:  tainted_regs.push_front(REG_RDI); 
        case REG_EDI:  tainted_regs.push_front(REG_EDI); 
        case REG_DI:   tainted_regs.push_front(REG_DI); 
        case REG_DIL:  tainted_regs.push_front(REG_DIL); 
            break;

        case REG_RBP:  tainted_regs.push_front(REG_RBP); 
        case REG_EBP:  tainted_regs.push_front(REG_EBP); 
        case REG_BP:   tainted_regs.push_front(REG_BP); 
        case REG_BPL:  tainted_regs.push_front(REG_BPL); 
            break;

        case REG_RSP:  tainted_regs.push_front(REG_RSP); 
        case REG_ESP:  tainted_regs.push_front(REG_ESP); 
        case REG_SP:   tainted_regs.push_front(REG_SP); 
        case REG_SPL:  tainted_regs.push_front(REG_SPL); 
            break;

        case REG_R8:   tainted_regs.push_front(REG_R8); 
        case REG_R8D:  tainted_regs.push_front(REG_R8D); 
        case REG_R8W:  tainted_regs.push_front(REG_R8W); 
        case REG_R8B:  tainted_regs.push_front(REG_R8B); 
            break;

        case REG_R9:   tainted_regs.push_front(REG_R9); 
        case REG_R9D:  tainted_regs.push_front(REG_R9D); 
        case REG_R9W:  tainted_regs.push_front(REG_R9W); 
        case REG_R9B:  tainted_regs.push_front(REG_R9B); 
            break;

        case REG_R10:   tainted_regs.push_front(REG_R10); 
        case REG_R10D:  tainted_regs.push_front(REG_R10D); 
        case REG_R10W:  tainted_regs.push_front(REG_R10W); 
        case REG_R10B:  tainted_regs.push_front(REG_R10B); 
            break;

        case REG_R11:   tainted_regs.push_front(REG_R11); 
        case REG_R11D:  tainted_regs.push_front(REG_R11D); 
        case REG_R11W:  tainted_regs.push_front(REG_R11W); 
        case REG_R11B:  tainted_regs.push_front(REG_R11B); 
            break;

        case REG_R12:   tainted_regs.push_front(REG_R12); 
        case REG_R12D:  tainted_regs.push_front(REG_R12D); 
        case REG_R12W:  tainted_regs.push_front(REG_R12W); 
        case REG_R12B:  tainted_regs.push_front(REG_R12B); 
            break;

        case REG_R13:  tainted_regs.push_front(REG_R13); 
        case REG_R13D: tainted_regs.push_front(REG_R13D); 
        case REG_R13W: tainted_regs.push_front(REG_R13W); 
        case REG_R13B: tainted_regs.push_front(REG_R13B); 
            break;

        case REG_R14:   tainted_regs.push_front(REG_R14); 
        case REG_R14D:  tainted_regs.push_front(REG_R14D); 
        case REG_R14W:  tainted_regs.push_front(REG_R14W); 
        case REG_R14B:  tainted_regs.push_front(REG_R14B); 
            break;

        case REG_R15:   tainted_regs.push_front(REG_R15); 
        case REG_R15D:  tainted_regs.push_front(REG_R15D); 
        case REG_R15W:  tainted_regs.push_front(REG_R15W); 
        case REG_R15B:  tainted_regs.push_front(REG_R15B); 
            break;

        default:
            fprintf(trace, "level=taint thread=%d message=\"%s can't be tainted\"\n", tid, REG_StringShort(reg).c_str());
            return false;
    }

    thread_tainted_regs[tid] = tainted_regs;
    fprintf(trace, "level=taint thread=%d action=reg message=\"%s is now tainted\"\n", tid, REG_StringShort(reg).c_str());
    return true;
}

bool removeRegTainted(REG reg) {
    if (thread_tainted_regs.empty()) {
        return false;
    }

    pid_t tid = gettid();
    std::list<REG> tainted_regs = thread_tainted_regs.find(tid)->second;
    switch(reg) {
        case REG_RAX:  tainted_regs.remove(REG_RAX);
        case REG_EAX:  tainted_regs.remove(REG_EAX);
        case REG_AX:   tainted_regs.remove(REG_AX);
        case REG_AH:   tainted_regs.remove(REG_AH);
        case REG_AL:   tainted_regs.remove(REG_AL);
            break;

        case REG_RBX:  tainted_regs.remove(REG_RBX);
        case REG_EBX:  tainted_regs.remove(REG_EBX);
        case REG_BX:   tainted_regs.remove(REG_BX);
        case REG_BH:   tainted_regs.remove(REG_BH);
        case REG_BL:   tainted_regs.remove(REG_BL);
            break;

        case REG_RCX:  tainted_regs.remove(REG_RCX); 
        case REG_ECX:  tainted_regs.remove(REG_ECX);
        case REG_CX:   tainted_regs.remove(REG_CX);
        case REG_CH:   tainted_regs.remove(REG_CH);
        case REG_CL:   tainted_regs.remove(REG_CL);
            break;

        case REG_RDX:  tainted_regs.remove(REG_RDX); 
        case REG_EDX:  tainted_regs.remove(REG_EDX); 
        case REG_DX:   tainted_regs.remove(REG_DX); 
        case REG_DH:   tainted_regs.remove(REG_DH); 
        case REG_DL:   tainted_regs.remove(REG_DL); 
            break;

        case REG_RSI:  tainted_regs.remove(REG_RSI); 
        case REG_ESI:  tainted_regs.remove(REG_ESI); 
        case REG_SI:   tainted_regs.remove(REG_SI); 
        case REG_SIL:  tainted_regs.remove(REG_SIL); 
            break;

        case REG_RDI:  tainted_regs.remove(REG_RDI); 
        case REG_EDI:  tainted_regs.remove(REG_EDI); 
        case REG_DI:   tainted_regs.remove(REG_DI); 
        case REG_DIL:  tainted_regs.remove(REG_DIL); 
            break;

        case REG_RBP:  tainted_regs.remove(REG_RBP); 
        case REG_EBP:  tainted_regs.remove(REG_EBP); 
        case REG_BP:   tainted_regs.remove(REG_BP); 
        case REG_BPL:  tainted_regs.remove(REG_BPL); 
            break;

        case REG_RSP:  tainted_regs.remove(REG_RSP); 
        case REG_ESP:  tainted_regs.remove(REG_ESP); 
        case REG_SP:   tainted_regs.remove(REG_SP); 
        case REG_SPL:  tainted_regs.remove(REG_SPL); 
            break;

        case REG_R8:   tainted_regs.remove(REG_R8); 
        case REG_R8D:  tainted_regs.remove(REG_R8D); 
        case REG_R8W:  tainted_regs.remove(REG_R8W); 
        case REG_R8B:  tainted_regs.remove(REG_R8B); 
            break;

        case REG_R9:   tainted_regs.remove(REG_R9); 
        case REG_R9D:  tainted_regs.remove(REG_R9D); 
        case REG_R9W:  tainted_regs.remove(REG_R9W); 
        case REG_R9B:  tainted_regs.remove(REG_R9B); 
            break;

        case REG_R10:   tainted_regs.remove(REG_R10); 
        case REG_R10D:  tainted_regs.remove(REG_R10D); 
        case REG_R10W:  tainted_regs.remove(REG_R10W); 
        case REG_R10B:  tainted_regs.remove(REG_R10B); 
            break;

        case REG_R11:   tainted_regs.remove(REG_R11); 
        case REG_R11D:  tainted_regs.remove(REG_R11D); 
        case REG_R11W:  tainted_regs.remove(REG_R11W); 
        case REG_R11B:  tainted_regs.remove(REG_R11B); 
            break;

        case REG_R12:   tainted_regs.remove(REG_R12); 
        case REG_R12D:  tainted_regs.remove(REG_R12D); 
        case REG_R12W:  tainted_regs.remove(REG_R12W); 
        case REG_R12B:  tainted_regs.remove(REG_R12B); 
            break;

        case REG_R13:  tainted_regs.remove(REG_R13); 
        case REG_R13D: tainted_regs.remove(REG_R13D); 
        case REG_R13W: tainted_regs.remove(REG_R13W); 
        case REG_R13B: tainted_regs.remove(REG_R13B); 
            break;

        case REG_R14:   tainted_regs.remove(REG_R14); 
        case REG_R14D:  tainted_regs.remove(REG_R14D); 
        case REG_R14W:  tainted_regs.remove(REG_R14W); 
        case REG_R14B:  tainted_regs.remove(REG_R14B); 
            break;

        case REG_R15:   tainted_regs.remove(REG_R15); 
        case REG_R15D:  tainted_regs.remove(REG_R15D); 
        case REG_R15W:  tainted_regs.remove(REG_R15W); 
        case REG_R15B:  tainted_regs.remove(REG_R15B); 
            break;

        default:
            return false;
    }

    thread_tainted_regs[tid] = tainted_regs;
    fprintf(trace, "level=taint thread=%d action=reg message=\"%s is now freed\"\n", tid, REG_StringShort(reg).c_str());
    return true;
}

void removeMemTainted(UINT64 addr) {
    if (thread_tainted_addresses.empty()) {
        return;
    }

    pid_t tid = gettid();
    std::list<UINT64> tainted_addresses = thread_tainted_addresses.find(tid)->second;
    tainted_addresses.remove(addr);
    thread_tainted_addresses[tid] = tainted_addresses;
    fprintf(trace, "level=taint thread=%d action=mem message=\"%p is now freed\"\n", tid, (void*)addr);
}

void addMemTainted(UINT64 addr) {
    if (thread_tainted_addresses.empty()) {
        return;
    }

    pid_t tid = gettid();
    std::list<UINT64> tainted_addresses = thread_tainted_addresses.find(tid)->second;
    tainted_addresses.push_back(addr);
    thread_tainted_addresses[tid] = tainted_addresses;
    fprintf(trace, "level=taint thread=%d action=mem message=\"%p is now tainted\"\n", tid, (void*)addr);
}

int newAccept(AFUNPTR orgFuncPtr, CONTEXT *ctx, int sockfd, struct sockaddr *addr, socklen_t *addrLen) {
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

void replaceAccept(IMG img, RTN rtn) {
    PROTO proto_accept = PROTO_Allocate(PIN_PARG(int), CALLINGSTD_DEFAULT,
                                        NULL,
                                        PIN_PARG(int),              // sockfd
                                        PIN_PARG(struct sockaddr*), // addr
                                        PIN_PARG(socklen_t*),       // addrlen
                                        PIN_PARG_END());

    RTN_ReplaceSignature(rtn, AFUNPTR(newAccept),
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

int newClose(AFUNPTR orgFuncPtr, CONTEXT *ctx, int fd) {
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

void replaceClose(IMG img, RTN rtn) {
    PROTO proto_close = PROTO_Allocate(PIN_PARG(int), CALLINGSTD_DEFAULT,
                                        NULL,
                                        PIN_PARG(int),      // fd
                                        PIN_PARG_END());

    RTN_ReplaceSignature(rtn, AFUNPTR(newClose),
                                IARG_PROTOTYPE, proto_close,
                                IARG_ORIG_FUNCPTR,
                                IARG_CONTEXT,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                IARG_END);

    PROTO_Free(proto_close);

    printf("[*] server-tracer: INFO: close replaced\t\t: %s\n", IMG_Name(img).c_str());
}

ssize_t newTCPActivity(AFUNPTR orgFuncPtr, CONTEXT *ctx, const char *functionName, int sockfd, void *buf, size_t len, int flags) {
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

    if (strcmp("recv", functionName) == 0) {
        std::list<UINT64> tainted_addresses;
        std::list<REG> tainted_regs;
        pid_t tid = gettid();

        for (int i = 0; i < ret ; i++) {
            tainted_addresses.push_back((UINT64) *&buf + i);
        }

        thread_tainted_addresses.insert(std::make_pair(tid, tainted_addresses));
        thread_tainted_regs.insert(std::make_pair(tid, tainted_regs));
        fprintf(trace, "level=taint thread=%d action=%s buffer-address=%p buffer-size=%ld content-size=%ld buffer-content=", gettid(), functionName, (void*) *&buf, len, ret);
        for (int i = 0; i < ret; i++) {
            fprintf(trace, "%02x", ((char* )buf)[i]);
        }
        fprintf(trace, " range-start=%p range-end=0x%08lx\n", *&buf, (UINT64) *&buf+ret-1);
    } else if (strcmp("send", functionName) == 0) {
        /* We only want to keep track of server model */
        thread_tainted_addresses.erase(gettid());
        thread_tainted_regs.erase(gettid());
        fprintf(trace, "level=taint thread=%d action=%s buffer-address=%p buffer-size=%ld content-size=%ld buffer-content=", gettid(), functionName, (void*) *&buf, len, ret);
        for (int i = 0; i < ret; i++) {
            fprintf(trace, "%02x", ((char* )buf)[i]);
        }
        fprintf(trace, " message=\"All tainted information deleted\"\n");
        /* Flush all information */
        fflush(trace);
    }

    return ret;
}

void replaceTCPActivity(IMG img, RTN rtn, const char *functionName) {
    PROTO proto_tcp_activity = PROTO_Allocate(PIN_PARG(ssize_t), CALLINGSTD_DEFAULT,
                                        NULL,
                                        PIN_PARG(int),      // sockfd
                                        PIN_PARG(void*),    // buf
                                        PIN_PARG(size_t),   // len
                                        PIN_PARG(int),      // flags
                                        PIN_PARG_END());

    RTN_ReplaceSignature(rtn, AFUNPTR(newTCPActivity),
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

void imageLoad(IMG img, VOID *v) {
    RTN rtn;
    printf("[*] server-tracer: INFO: Module loaded\t\t: %s\n", IMG_Name(img).c_str());

    /* Avoid to hook first module loaded a.k.a main executable */
    if (IMG_IsMainExecutable(img)) {
        ADDRINT image_base = IMG_LowAddress(img);
        printf("[*] server-tracer: INFO: Main module mapped to %p\n", (void*)image_base);
        fprintf(trace, "level=info action=relocate image-base=%p\n", (void*)image_base);
        printf("[*] server-tracer: INFO: Main module not hooked\t: %s\n", IMG_Name(img).c_str());
        return;
    }

    rtn = RTN_FindByName(img, "recv");
    if (RTN_Valid(rtn)) {
        replaceTCPActivity(img, rtn, "recv");
    }

    rtn = RTN_FindByName(img, "send");
    if (RTN_Valid(rtn)) {
        replaceTCPActivity(img, rtn, "send");
    }

    rtn = RTN_FindByName(img, "close");
    if (RTN_Valid(rtn)) {
        replaceClose(img, rtn);
    }

    rtn = RTN_FindByName(img, "accept");
    if (RTN_Valid(rtn)) {
        replaceAccept(img, rtn);
    }
}

void printInsHexBytes(UINT64 insAdd, USIZE insSize) {
    /*
    * Intel® 64 and IA-32 Architectures Software Developer’s Manual Volume 2A: Instruction Set Reference, A-L
    * The maximum length of an Intel 64 and IA-32 instruction remains 15 bytes
    */
    void* buf[15];
    PIN_SafeCopy(buf, (void*) insAdd, insSize);

    for (uint i = 0; i < insSize; i++) {
        fprintf(trace, "%02x", ((unsigned char*) buf)[i]);
    }
}

void traceMem(UINT64 insAdd, std::string insDis, USIZE insSize, UINT64 memOp, char* routine, char* mode) {
    if (thread_tainted_addresses.empty()) {
        return;
    }
    pid_t tid = gettid();
    std::list<UINT64> tainted_adderess = thread_tainted_addresses.find(tid)->second;
    std::list<UINT64>::iterator i;

    for (i=tainted_adderess.begin(); i!=tainted_adderess.end(); i++) {
        if (*i == memOp) {
            fprintf(trace, "level=taint thread=%d routine=%s action=%s mem-addr=%p ins-addr=%p ins-dis=\"%s\" ins-bytes=", tid, routine, mode, (void*)memOp, (void*)insAdd, insDis.c_str());
            printInsHexBytes(insAdd, insSize);
            fprintf(trace, "\n");
            return;
        }
    }

    fprintf(trace, "level=info thread=%d routine=%s action=log ins-addr=%p ins-dis=\"%s\"\n", tid, routine, (void*)insAdd, insDis.c_str());
}

void readMem(UINT64 insAdd, std::string insDis, USIZE insSize, UINT64 memOp, char* routine, REG reg_r) {
    pid_t tid = gettid();
    std::list<UINT64> tainted_adderess = thread_tainted_addresses.find(tid)->second;
    std::list<UINT64>::iterator i;

    for(i = tainted_adderess.begin(); i != tainted_adderess.end(); i++) {
        if (*i == memOp) {
            fprintf(trace, "level=taint thread=%d routine=%s action=mem-read mem-addr=%p ins-addr=%p ins-dis=\"%s\" ins-bytes=", tid, routine, (void*)memOp, (void*)insAdd, insDis.c_str());
            printInsHexBytes(insAdd, insSize);
            fprintf(trace, "\n");
            taintReg(reg_r);
            return;
        }
    }
    /* if mem != tained and reg == taint => free the reg */
    if (checkAlreadyRegTainted(reg_r)) {
        fprintf(trace, "level=taint thread=%d routine=%s action=mem-read mem-addr=%p ins-addr=%p ins-dis=\"%s\" ins-bytes=", tid, routine, (void*)memOp, (void*)insAdd, insDis.c_str());
        printInsHexBytes(insAdd, insSize);
        fprintf(trace, "\n");
        removeRegTainted(reg_r);
    }
}

void writeMem(UINT64 insAdd, std::string insDis, USIZE insSize, UINT64 memOp, char* routine, REG reg_r) {
    if (thread_tainted_addresses.empty()) {
        return;
    }
    pid_t tid = gettid();
    std::list<UINT64> tainted_adderess = thread_tainted_addresses.find(tid)->second;
    std::list<UINT64>::iterator i;

    for(i = tainted_adderess.begin(); i != tainted_adderess.end(); i++) {
        if (*i == memOp) {
            fprintf(trace, "level=taint thread=%d routine=%s action=mem-write mem-addr=%p ins-addr=%p ins-dis=\"%s\" ins-bytes=", tid, routine, (void*)memOp, (void*)insAdd, insDis.c_str());
            printInsHexBytes(insAdd, insSize);
            fprintf(trace, "\n");
            if (!REG_valid(reg_r) || !checkAlreadyRegTainted(reg_r)) {
                removeMemTainted(memOp);
            }
            return;
        }
    }
    if (checkAlreadyRegTainted(reg_r)) {
        fprintf(trace, "level=taint thread=%d routine=%s action=mem-write mem-addr=%p ins-addr=%p ins-dis=\"%s\" ins-bytes=", tid, routine, (void*)memOp, (void*)insAdd, insDis.c_str());
        printInsHexBytes(insAdd, insSize);
        fprintf(trace, "\n");
        addMemTainted(memOp);
    }
}

void spreadRegTaint(UINT64 insAdd, std::string insDis, char* routine, REG reg_r, REG reg_w) {
    pid_t tid = gettid();

    if (REG_valid(reg_w)) {
        if (checkAlreadyRegTainted(reg_w) && (!REG_valid(reg_r) || !checkAlreadyRegTainted(reg_r))) {
            fprintf(trace, "level=taint thread=%d routine=%s action=spread ins-addr=%p ins-dis=\"%s\"\n", tid, routine, (void*)insAdd, insDis.c_str());
            fprintf(trace, "level=taint thread=%d routine=%s actino=spread output=%s input=%s", tid, routine, REG_StringShort(reg_w).c_str(), (REG_valid(reg_r) ? REG_StringShort(reg_r).c_str() : "constant"));
            removeRegTainted(reg_w);
        } else if (!checkAlreadyRegTainted(reg_w) && checkAlreadyRegTainted(reg_r)) {
            fprintf(trace, "level=taint thread=%d routine=%s action=spread ins-addr=%p ins-dis=\"%s\"\n", tid, routine, (void*)insAdd, insDis.c_str());
            fprintf(trace, "level=taint thread=%d routine=%s action=spread output=%s input=%s", tid, routine, REG_StringShort(reg_w).c_str(), REG_StringShort(reg_r).c_str());
            taintReg(reg_w);
        }
    }
}

VOID followData(UINT64 insAdd, std::string insDis, char* routine, REG reg) {
    if (!REG_valid(reg)) {
        return;
    }

    if (checkAlreadyRegTainted(reg)){
        fprintf(trace, "level=taint thread=%d routine=%s action=follow-data ins-addr=%p ins-dis=\"%s\"\n", gettid(), routine, (void*) insAdd, insDis.c_str());
    }
}

void instruction(INS ins, void *v) {
    /* Return inmediatly if there are no buffers of interest */
    if (thread_tainted_addresses.empty()) {
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
                fprintf(trace, "level=info thread=%d routine=%s action=call target=%s ins-addr=%p ins-dis=\"%s\"\n", gettid(), routine, RTN_FindNameByAddress(target).c_str(), (void*) INS_Address(ins), INS_Disassemble(ins).c_str());
            } else {
                /* Target address is provided through memory or through a register */
                fprintf(trace, "level=info thread=%d routine=%s action=indirect-call ins-addr=%p ins-dis=\"%s\"\n", gettid(), routine, (void*) INS_Address(ins), INS_Disassemble(ins).c_str());
            }
        } else if (INS_IsMemoryRead(ins) || INS_IsMemoryWrite(ins)) {
            if (INS_OperandCount(ins) == 2 && INS_MemoryOperandIsRead(ins, 0) && INS_OperandIsReg(ins, 0)) {
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)readMem,
                    IARG_INST_PTR,
                    IARG_PTR, new std::string(INS_Disassemble(ins)),
                    IARG_MEMORYOP_EA, 0,
                    IARG_PTR, routine,
                    IARG_UINT32, INS_OperandReg(ins, 0),
                    IARG_END);
            } else if (INS_OperandCount(ins) == 2 && INS_MemoryOperandIsWritten(ins, 0)) {
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)writeMem,
                    IARG_INST_PTR,
                    IARG_PTR, new std::string(INS_Disassemble(ins)),
                    IARG_MEMORYOP_EA, 0,
                    IARG_PTR, routine,
                    IARG_UINT32, INS_OperandReg(ins, 1),
                    IARG_END);
            } else if (INS_OperandCount(ins) == 2 && INS_OperandIsReg(ins, 0)) {
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)spreadRegTaint,
                    IARG_INST_PTR,
                    IARG_PTR, new std::string(INS_Disassemble(ins)),
                    IARG_PTR, routine,
                    IARG_UINT32, INS_RegR(ins, 0),
                    IARG_UINT32, INS_RegW(ins, 0),
                    IARG_END);
            } else if (INS_MemoryOperandCount(ins) > 0) {
                UINT32 mem_operands = INS_MemoryOperandCount(ins);
                for (UINT32 mem_op = 0; mem_op < mem_operands; mem_op++) {
                    if (INS_MemoryOperandIsRead(ins, mem_op)) {
                        INS_InsertCall(
                            ins, IPOINT_BEFORE, (AFUNPTR)traceMem,
                            IARG_INST_PTR,
                            IARG_PTR, new std::string(INS_Disassemble(ins)),
                            IARG_ADDRINT, INS_Size(ins),
                            IARG_MEMORYOP_EA, mem_op,
                            IARG_PTR, routine,
                            IARG_PTR, "mem-read",
                            IARG_END);
                    }
                    /* Check for both reads and writes to memory (for example, movsb) */
                    if (INS_MemoryOperandIsWritten(ins, mem_op)) {
                        INS_InsertCall(
                            ins, IPOINT_BEFORE, (AFUNPTR)traceMem,
                            IARG_INST_PTR,
                            IARG_PTR, new std::string(INS_Disassemble(ins)),
                            IARG_PTR, ins,
                            IARG_MEMORYOP_EA, mem_op,
                            IARG_PTR, routine,
                            IARG_PTR, "mem-write",
                            IARG_END);
                    }
                }
            }

            if (INS_OperandCount(ins) > 1 && INS_OperandIsReg(ins, 0)){
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)followData,
                    IARG_INST_PTR,
                    IARG_PTR, new std::string(INS_Disassemble(ins)),
                    IARG_PTR, routine,
                    IARG_UINT32, INS_RegR(ins, 0),
                    IARG_END);
            }
        } else {
            fprintf(trace, "level=info thread=%d routine=%s action=log ins-addr=%p ins-dis=\"%s\"\n", gettid(), routine, (void*) INS_Address(ins), INS_Disassemble(ins).c_str());
        }
    }
}

void fini(INT32 code, void *v) {
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
    IMG_AddInstrumentFunction(imageLoad, 0);

    /* Instrument instructions */
    INS_AddInstrumentFunction(instruction, 0);

    /* Function called on server exit */
    PIN_AddFiniFunction(fini, 0);

    PIN_StartProgram();

    return 0;
}
