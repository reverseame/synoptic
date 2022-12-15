#include "pin.H"
#include <set>
#include <stdio.h>
#include <winsock2.h>
#include <processthreadsapi.h>

/* Output file */
FILE* trace;
/* Keep track of tainted addresses */
std::set<ADDRINT> taintedAdddrs;
/* Keep track of tainted registers */
bool taintedRegs[REG_LAST];

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

int newCloseSocketFunction(AFUNPTR orgFuncPtr, CONTEXT *ctx, int fd) {
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

void replaceCloseSocketFunction(IMG img, RTN rtn) {
    PROTO proto_close = PROTO_Allocate(PIN_PARG(int), CALLINGSTD_DEFAULT,
                                        NULL,
                                        PIN_PARG(int),      // fd
                                        PIN_PARG_END());

    RTN_ReplaceSignature(rtn, AFUNPTR(newCloseSocketFunction),
                                IARG_PROTOTYPE, proto_close,
                                IARG_ORIG_FUNCPTR,
                                IARG_CONTEXT,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                IARG_END);

    PROTO_Free(proto_close);

    printf("[*] server-tracer\t: INFO\t: close replaced\t: %s\n", IMG_Name(img).c_str());
}

int WSAAPI newTCPActivityFunction(AFUNPTR orgFuncPtr, CONTEXT *ctx, const char *functionName, SOCKET s, char *buf, int len, int flags) {
    int ret;

    PIN_CallApplicationFunction(ctx, PIN_ThreadId(),
                                CALLINGSTD_DEFAULT, orgFuncPtr,
                                NULL,
                                PIN_PARG(int), &ret,
                                PIN_PARG(SOCKET), s,
                                PIN_PARG(char*), buf,
                                PIN_PARG(int), len,
                                PIN_PARG(int), flags,
                                PIN_PARG_END());

    DWORD tid = GetCurrentThreadId();

    fprintf(trace, "level=taint thread=%d action=%s buffer-address=%p buffer-size=%ld content-size=%ld buffer-content=", tid, functionName, *&buf, len, ret);
    for (int i = 0; i < ret; i++) {
        fprintf(trace, "%02x", ((char* )buf)[i]);
    }
    fprintf(trace, " range-start=%p range-end=0x%08lx\n", *&buf, (UINT64) *&buf+ret-1);

    if (strcmp(functionName, "recv") == 0) {
        /* Taint all recv data at byte level */
        for (int i = 0; i < ret; i++) {
            taintedAdddrs.insert((UINT64) *&buf + i);
        }
    } else if (strcmp(functionName, "send") == 0) {
        /* Free all tainted data */
        taintedAdddrs.clear();
        for (int i = 0; i < REG_LAST; i++) {
            taintedRegs[i] = false;
        }
        fflush(trace);
    }

    return ret;
}

void replaceTCPActivityFunction(IMG img, RTN rtn, const char *functionName) {
    PROTO proto_tcp_activity = PROTO_Allocate(PIN_PARG(ssize_t), CALLINGSTD_DEFAULT,
                                        NULL,
                                        PIN_PARG(SOCKET),   // s
                                        PIN_PARG(char*),    // buf
                                        PIN_PARG(int),      // len
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

    /*rtn = RTN_FindByName(img, "send");
    if (RTN_Valid(rtn)) {
        replaceTCPActivityFunction(img, rtn, "send");
    }

    rtn = RTN_FindByName(img, "close");
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
    }*/
}

void traceIns(ADDRINT insAddr, std::string insDis, char* routine) {
    fprintf(trace, "level=info thread=%d routine=\"%s\" ins-addr=0x%08lx ins-dis=\"%s\"\n", gettid(), routine, insAddr, insDis.c_str());
}

/* Register copied to memory */
void regToAddr(ADDRINT insAddr, std::string insDis, char* routine, ADDRINT reg_r, ADDRINT mem_w) {
    if (taintedRegs[reg_r]) {
        fprintf(trace, "level=taint thread=%d routine=\"%s\" ins-addr=0x%08lx ins-dis=\"%s\" action=taint-addr origin=reg addr=0x%08lx reg=%s\n", gettid(), routine, insAddr, insDis.c_str(), mem_w, REG_StringShort((REG)reg_r).c_str());
        taintedAdddrs.insert(mem_w);
    } else {
        /* reg not tainted --> mem not tainted */
        /* if mem is already not tainted nothing to do */
        if (taintedAdddrs.count(mem_w)) {
            fprintf(trace, "level=taint thread=%d routine=\"%s\" ins-addr=0x%08lx ins-dis=\"%s\" action=free-addr origin=reg addr=0x%08lx reg=%s\n", gettid(), routine, insAddr, insDis.c_str(), mem_w, REG_StringShort((REG)reg_r).c_str());
            taintedAdddrs.erase(taintedAdddrs.find(mem_w));
        } else {
            traceIns(insAddr, insDis, routine);
        }
    }
}

/* Memory copied to register */
void addrToReg(ADDRINT insAddr, std::string insDis, char* routine, ADDRINT mem_r, ADDRINT reg_w) {
    if (taintedAdddrs.count(mem_r)) {
        fprintf(trace, "level=taint thread=%d routine=\"%s\" ins-addr=0x%08lx ins-dis=\"%s\" action=taint-reg origin=addr reg=%s addr=0x%08lx\n", gettid(), routine, insAddr, insDis.c_str(), REG_StringShort((REG)reg_w).c_str(), mem_r);
        taintedRegs[reg_w] = true;
    } else {
        /* mem is clean -> reg is cleaned */
        fprintf(trace, "level=taint thread=%d routine=\"%s\" ins-addr=0x%08lx ins-dis=\"%s\" action=free-reg origin=addr reg=%s addr=0x%08lx\n", gettid(), routine, insAddr, insDis.c_str(), REG_StringShort((REG)reg_w).c_str(), mem_r);
        taintedRegs[reg_w] = false;
    }
}

/* Reg copied to another reg */
void regToReg(ADDRINT insAddr, std::string insDis, char* routine, ADDRINT reg_r, ADDRINT reg_w) {
    if (taintedRegs[reg_r]) {
        fprintf(trace, "level=taint thread=%d routine=\"%s\" ins-addr=0x%08lx ins-dis=\"%s\" action=taint-reg origin=reg reg-taint=%s reg-origin=%s\n", gettid(), routine, insAddr, insDis.c_str(), REG_StringShort((REG)reg_w).c_str(), REG_StringShort((REG)reg_r).c_str());
        taintedRegs[reg_w] = true;
    } else if (taintedRegs[reg_w]) {
        fprintf(trace, "level=taint thread=%d routine=\"%s\" ins-addr=0x%08lx ins-dis=\"%s\" action=free-reg origin=reg reg-free=%s reg-origin=%s\n", gettid(), routine, insAddr, insDis.c_str(), REG_StringShort((REG)reg_w).c_str(), REG_StringShort((REG)reg_r).c_str());
        taintedRegs[reg_w] = false;
    } else {
        traceIns(insAddr, insDis, routine);
    }
}

/* Immediate copied to a register */
void immToReg(ADDRINT insAddr, std::string insDis, char* routine, ADDRINT reg_w) {
    if (taintedRegs[reg_w]) {
        fprintf(trace, "level=taint thread=%d routine=\"%s\" ins-addr=0x%08lx ins-dis=\"%s\" action=free-reg reg=%s\n", gettid(), routine, insAddr, insDis.c_str(), REG_StringShort((REG)reg_w).c_str());
        taintedRegs[reg_w] = false;
    } else {
        traceIns(insAddr, insDis, routine);
    }
}

/* Immediate copied to memory address */
void immToAddr(ADDRINT insAddr, std::string insDis, char* routine, ADDRINT mem_w) {
    /* if mem is not tainted nothing to do */
    if (taintedAdddrs.count(mem_w)) {
        fprintf(trace, "level=taint thread=%d routine=\"%s\" ins-addr=0x%08lx ins-dis=\"%s\" action=free-addr addr=0x%08lx\n", gettid(), routine, insAddr, insDis.c_str(), mem_w);
        taintedAdddrs.erase(taintedAdddrs.find(mem_w));
    } else {
        traceIns(insAddr, insDis, routine);
    }
}

/* returns register */
REG getReg(INS ins) {
    for (unsigned int i = 0; i < INS_OperandCount(ins); i++) {
        if (INS_OperandIsReg(ins, i)) {
            return REG_FullRegName(INS_OperandReg(ins, i));
        }
    }
    
    return REG_INVALID();
}

/* returns immediate */
ADDRINT getImm(INS ins) {
    for (unsigned int i = 0; i < INS_OperandCount(ins); i++) {
        if (INS_OperandIsImmediate(ins, i)) {
            return INS_OperandImmediate(ins, i);
        }
    }
    
    return -1;
}

/* meant to be called only from instrumentation routines */
bool hasImm(INS ins) {
    for (unsigned int i = 0; i < INS_OperandCount(ins); i++) {
        if (INS_OperandIsImmediate(ins, i)) {
            return true;
        }
    }
    return false;
}

/* returns the full name of the first register operand written */
REG getWriteReg(INS ins) {
    for (unsigned int i = 0; i < INS_OperandCount(ins); i++) {
        if (INS_OperandIsReg(ins, i) && INS_OperandWritten(ins, i)) {
            return REG_FullRegName(INS_OperandReg(ins, i));
        }
    }
    
    return REG_INVALID();
}

/* returns the full name of the first register operand read */
REG getReadReg(INS ins) {
    for (unsigned int i = 0; i < INS_OperandCount(ins); i++) {
        if (INS_OperandIsReg(ins, i) && INS_OperandRead(ins, i)) {
            return REG_FullRegName(INS_OperandReg(ins, i));
        }
    }
    
    return REG_INVALID();
}

/* returns the full name of the first register operand read */
REG getMemoryReg(INS ins) {
    for (unsigned int i = 0; i < INS_OperandCount(ins); i++) {
        if (INS_OperandIsMemory(ins, i)) {
            REG reg = INS_OperandMemoryBaseReg(ins, i);
            if (reg != REG_INVALID()) {
                return REG_FullRegName(reg);
            }
        }
    }
    
    return REG_INVALID();
}

/* Print in/direct call instruction with  */
void traceCall(ADDRINT insAddr, std::string insDis, char* routine, char* callType, ADDRINT targetAddr) {
    std::string target = RTN_FindNameByAddress(targetAddr);

    if (target.empty()) {
        target = "unknown";
    }

    fprintf(trace, "level=info thread=%d routine=\"%s\" ins-addr=0x%08lx ins-dis=\"%s\" action=%s target=\"%s\"\n", gettid(), routine, insAddr, insDis.c_str(), callType, target.c_str());
}

/* Analyzes mov instructions */
void propagateTaint(INS ins, const char* routine) {
    if (hasImm(ins)) {
        /* [addr] <- imm */
        if (INS_IsMemoryWrite(ins)) {
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)immToAddr,
                IARG_INST_PTR,
                IARG_PTR, new std::string(INS_Disassemble(ins)),
                IARG_PTR, routine,
                IARG_MEMORYOP_EA, 0,
                IARG_END);
        } else {
            /* reg <- imm */
            REG reg = getWriteReg(ins);
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)immToReg,
                IARG_INST_PTR,
                IARG_PTR, new std::string(INS_Disassemble(ins)),
                IARG_PTR, routine,
                IARG_ADDRINT, (ADDRINT)reg,
                IARG_END);
        }
    } else if (INS_IsMemoryRead(ins)) {
        /* reg <- [addr] */
        REG reg = getWriteReg(ins);
        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)addrToReg,
            IARG_INST_PTR,
            IARG_PTR, new std::string(INS_Disassemble(ins)),
            IARG_PTR, routine,
            IARG_MEMORYOP_EA, 0,
            IARG_ADDRINT, (ADDRINT)reg,
            IARG_END);
    } else if (INS_IsMemoryWrite(ins)) {
        /* [addr] <- reg */
        REG reg = getReadReg(ins);
        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)regToAddr,
            IARG_INST_PTR,
            IARG_PTR, new std::string(INS_Disassemble(ins)),
            IARG_PTR, routine,
            IARG_ADDRINT, (ADDRINT)reg,
            IARG_MEMORYOP_EA, 0,
            IARG_END);
    } else if (INS_RegR(ins, 0) != REG_INVALID()) {
        /* reg <- reg */
        REG reg_r = getReadReg(ins);
        REG reg_w = getWriteReg(ins);
        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)regToReg,
            IARG_INST_PTR,
            IARG_PTR, new std::string(INS_Disassemble(ins)),
            IARG_PTR, routine,
            IARG_ADDRINT, (ADDRINT)reg_r,
            IARG_ADDRINT, (ADDRINT)reg_w,
            IARG_END);
    } else {
        fprintf(stderr, "[*] server-tracer\t: ERROR\t: Unable to propagate taint info: %s\n", INS_Disassemble(ins).c_str());
    }
}

void analyzeCall(INS ins, const char* routine) {
    /* call addr */
    if (INS_IsDirectControlFlow(ins)) {
        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)traceCall,
            IARG_INST_PTR,
            IARG_PTR, new std::string(INS_Disassemble(ins)),
            IARG_PTR, routine,
            IARG_PTR, "direct-call",
            IARG_BRANCH_TARGET_ADDR,
            IARG_END);
    } else if (INS_IsIndirectControlFlow(ins)) {
        /* call [reg] */
        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)traceCall,
            IARG_INST_PTR,
            IARG_PTR, new std::string(INS_Disassemble(ins)),
            IARG_PTR, routine,
            IARG_PTR, "indirect-call",
            IARG_BRANCH_TARGET_ADDR,
            IARG_END);
    } else {
        fprintf(stderr, "[*] server-tracer\t: ERROR\t: Unknown call: %s\n", INS_Disassemble(ins).c_str());
    }
}

/* Immediate compared to memory address */
void compareImmToAddr(ADDRINT insAddr, std::string insDis, char* routine, ADDRINT mem_r, REG reg_r, ADDRINT imm) {
    if (taintedAdddrs.count(mem_r)) {
        fprintf(trace, "level=taint thread=%d routine=\"%s\" ins-addr=0x%08lx ins-dis=\"%s\" action=compare origin=imm-addr addr=0x%08lx reg=%s imm=0x%016lx\n", gettid(), routine, insAddr, insDis.c_str(), mem_r, REG_StringShort(reg_r).c_str(), imm);
    } else {
        traceIns(insAddr, insDis, routine);
    }
}

/* Immediate compared to register */
void compareImmToReg(ADDRINT insAddr, std::string insDis, char* routine, REG reg, ADDRINT imm) {
    if (taintedRegs[reg]) {
        fprintf(trace, "level=taint thread=%d routine=\"%s\" ins-addr=0x%08lx ins-dis=\"%s\" action=compare origin=imm-reg reg=%s imm=0x%016lx\n", gettid(), routine, insAddr, insDis.c_str(), REG_StringShort(reg).c_str(), imm);
    } else {
        traceIns(insAddr, insDis, routine);
    }
}

/* Register compared to register */
void compareRegToReg(ADDRINT insAddr, std::string insDis, char* routine, REG reg1, REG reg2) {
    if (taintedRegs[reg1] || taintedRegs[reg2]) {
        fprintf(trace, "level=taint thread=%d routine=\"%s\" ins-addr=0x%08lx ins-dis=\"%s\" action=compare origin=reg-reg reg1=%s reg2=%s\n", gettid(), routine, insAddr, insDis.c_str(), REG_StringShort(reg1).c_str(), REG_StringShort(reg2).c_str());
    } else {
        traceIns(insAddr, insDis, routine);
    }
}

void analyzeComparison(INS ins, const char* routine) {
    if (hasImm(ins)) {
        /* [addr] == imm */
        if (INS_IsMemoryRead(ins)) {
            REG reg = getMemoryReg(ins);
            ADDRINT imm = getImm(ins);
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)compareImmToAddr,
                IARG_INST_PTR,
                IARG_PTR, new std::string(INS_Disassemble(ins)),
                IARG_PTR, routine, 
                IARG_MEMORYOP_EA, 0,
                IARG_PTR, reg,
                IARG_PTR, imm,
                IARG_END);
        } else {
            /* reg == imm */
            REG reg = getReg(ins);
            ADDRINT imm = getImm(ins);
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)compareImmToReg,
                IARG_INST_PTR,
                IARG_PTR, new std::string(INS_Disassemble(ins)),
                IARG_PTR, routine, 
                IARG_PTR, reg,
                IARG_PTR, imm,
                IARG_END);
        }
    } else if (INS_OperandIsReg(ins, 0) && INS_OperandIsReg(ins, 1)) {
        /* reg == reg */
        REG reg1 = REG_FullRegName(INS_OperandReg(ins, 0));
        REG reg2 = REG_FullRegName(INS_OperandReg(ins, 1));
        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)compareRegToReg,
            IARG_INST_PTR,
            IARG_PTR, new std::string(INS_Disassemble(ins)),
            IARG_PTR, routine, 
            IARG_PTR, reg1,
            IARG_PTR, reg2,
            IARG_END);
    } else {
        fprintf(trace, "level=info thread=%d routine=\"%s\" ins-addr=0x%08lx ins-dis=\"%s\"\n", gettid(), routine, INS_Address(ins), INS_Disassemble(ins).c_str());
    }
}

/*!
* This function checks for each instruction if it does a mov that can potentially
* transfer taint and if true adds the approriate analysis routine to check
* and propogate taint at run-time if needed
* This function is called every time a new trace is encountered.
*/
VOID instrumentTrace(TRACE trace, VOID *v) {
    /* Return inmediatly if there are no buffers of interest */
    if (taintedAdddrs.empty()) {
        return;
    }

    /* Just analyze the main executable */
    IMG img = IMG_FindByAddress(TRACE_Address(trace));
    if (!IMG_Valid(img) || !IMG_IsMainExecutable(img)) {
        return;
    }

    const char* routine = "unknown";
    if (RTN_Valid(TRACE_Rtn(trace))) {
        routine = RTN_Name(TRACE_Rtn(trace)).c_str();
    }

    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
            if ((INS_Opcode(ins) >= XED_ICLASS_MOV) && (INS_Opcode(ins) <= XED_ICLASS_MOVZX)) {
                propagateTaint(ins, routine);
            } else if (INS_IsCall(ins)) {
                analyzeCall(ins, routine);
            } else if ((INS_Opcode(ins) == XED_ICLASS_CMP) || (INS_Opcode(ins) == XED_ICLASS_TEST)) {
                analyzeComparison(ins, routine);
            /*} else if(INS_MaxNumWRegs(ins)) {
                analyzeWrite(ins, routine);*/
            } else {
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)traceIns,
                    IARG_INST_PTR,
                    IARG_PTR, new std::string(INS_Disassemble(ins)),
                    IARG_PTR, routine,
                    IARG_END);
            }
        }
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

    PIN_Init(argc, argv);

    trace = fopen("trace.log", "a");
    puts("[*] server-tracer\t: INFO\t: Log file\t\t: trace.log");
    fprintf(trace, "-----BEGIN TRACE-----\n");

    PIN_SetSyntaxIntel();

    /* Replace calls on module load */
    IMG_AddInstrumentFunction(moduleLoad, 0);

    /* Instrument traces */
    /*TRACE_AddInstrumentFunction(instrumentTrace, 0);*/

    /* Function called on server exit */
    PIN_AddFiniFunction(fini, 0);

    PIN_StartProgram();

    return 0;
}
