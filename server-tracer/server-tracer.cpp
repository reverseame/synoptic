#include "pin.H"
#include <list>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>

// Output file
FILE* trace;
// Keep track of tainted addresses by thread
std::map<pid_t,std::list<UINT64>> taint_addrs_by_thread;
// Keep track of tainted registers by thread
std::map<pid_t,std::list<REG>> taint_regs_by_thread;

void fini(INT32 code, void *v) {
    puts("[*] server-tracer: INFO: Shutting down...");
    fprintf(trace, "-----END TRACE-----\n");
    fclose(trace);
    puts("[*] server-tracer: INFO: Bye!");
}

bool isMemTaint(ADDRINT addr) {
    pid_t tid = gettid();
    std::map<pid_t,std::list<UINT64>>::iterator pos = taint_addrs_by_thread.find(tid);
    if (pos == taint_addrs_by_thread.end()) {
        return false;
    }

    std::list<UINT64> taint_addrs = pos->second;
    std::list<UINT64>::iterator i;

    for(i = taint_addrs.begin(); i != taint_addrs.end(); i++) {
        if (*i == addr) {
            return true;
        }
    }

    return false;
}

void taintMem(UINT64 addr) {
    pid_t tid = gettid();
    std::map<pid_t,std::list<UINT64>>::iterator pos = taint_addrs_by_thread.find(tid);
    if (pos == taint_addrs_by_thread.end()) {
        return;
    }

    if (!isMemTaint(addr)) {
        std::list<UINT64> taint_addrs = pos->second;
        taint_addrs.push_back(addr);
        taint_addrs_by_thread[tid] = taint_addrs;
    }
}

void freeTaintMem(ADDRINT addr) {
    pid_t tid = gettid();
    std::map<pid_t,std::list<UINT64>>::iterator pos = taint_addrs_by_thread.find(tid);
    if (pos == taint_addrs_by_thread.end()) {
        return;
    }

    std::list<UINT64> taint_addrs = pos->second;
    taint_addrs.remove(addr);
    taint_addrs_by_thread[tid] = taint_addrs;
}

REG getParentReg(REG reg) {
    REG parentReg;

    switch(reg) {
        case REG_RAX: case REG_EAX: case REG_AX: case REG_AH: case REG_AL:
            parentReg = REG_RAX;
            break;

        case REG_RBX: case REG_EBX: case REG_BX: case REG_BH: case REG_BL:
            parentReg = REG_RBX;
            break;

        case REG_RCX: case REG_ECX: case REG_CX: case REG_CH: case REG_CL:
            parentReg = REG_RCX;
            break;

        case REG_RDX: case REG_EDX: case REG_DX: case REG_DH: case REG_DL:
            parentReg = REG_RDX;
            break;

        case REG_RSI: case REG_ESI: case REG_SI: case REG_SIL:
            parentReg = REG_RSI;
            break;

        case REG_RDI: case REG_EDI: case REG_DI: case REG_DIL:
            parentReg = REG_RDI;
            break;

        case REG_R8: case REG_R8D: case REG_R8W: case REG_R8B:
            parentReg = REG_R8;
            break;

        case REG_R9: case REG_R9D: case REG_R9W: case REG_R9B:
            parentReg = REG_R9;
            break;

        case REG_R10: case REG_R10D: case REG_R10W: case REG_R10B:
            parentReg = REG_R10;
            break;

        case REG_R11: case REG_R11D: case REG_R11W: case REG_R11B:
            parentReg = REG_R11;
            break;

        case REG_R12: case REG_R12D: case REG_R12W: case REG_R12B:
            parentReg = REG_R12;
            break;

        case REG_R13: case REG_R13D: case REG_R13W: case REG_R13B:
            parentReg = REG_R13;
            break;

        case REG_R14: case REG_R14D: case REG_R14W: case REG_R14B:
            parentReg = REG_R14;
            break;

        case REG_R15: case REG_R15D: case REG_R15W: case REG_R15B:
            parentReg = REG_R15;
            break;

        default:
            parentReg = REG_INVALID();
    }

    return parentReg;
}

bool isRegTaint(REG reg) {
    std::map<pid_t,std::list<REG>>::iterator pos = taint_regs_by_thread.find(gettid());

    if (pos == taint_regs_by_thread.end()) {
        return false;
    }

    std::list<REG> taint_regs = pos->second;
    std::list<REG>::iterator i;
    REG parentReg = getParentReg(reg);
    if (parentReg == REG_INVALID()) {
        return false;
    }

    for(i = taint_regs.begin(); i != taint_regs.end(); i++){
        if (*i == parentReg) {
            return true;
        }
    }

    return false;
}

bool freeTaintReg(REG reg) {
    pid_t tid = gettid();
    std::map<pid_t,std::list<REG>>::iterator pos = taint_regs_by_thread.find(tid);
    if (pos == taint_regs_by_thread.end()) {
        return false;
    }

    std::list<REG> taint_regs = pos->second;

    REG parentReg = getParentReg(reg);
    if (parentReg == REG_INVALID()) {
        return false;
    }

    taint_regs.remove(parentReg);
    taint_regs_by_thread[tid] = taint_regs;

    return true;
}

bool taintReg(REG reg) {
    pid_t tid = gettid();

    std::map<pid_t,std::list<REG>>::iterator pos = taint_regs_by_thread.find(tid);

    if (pos == taint_regs_by_thread.end()) {
        return false;
    }

    if (isRegTaint(reg)) {
        return false;
    }

    REG parentReg = getParentReg(reg);
    if (parentReg == REG_INVALID()) {
        return false;
    }

    std::list<REG> taint_regs = pos->second;
    taint_regs.push_front(parentReg);
    taint_regs_by_thread[tid] = taint_regs;

    return true;
}

int operandCount(INS ins) {
    // Ignores all implicit related operands. For example, "ret" has 0 operands
    // instead of 4 as returned by INS_OperandCount()
    int count = 0;

    for (UINT32 op = 0; op < INS_OperandCount(ins); op++) {
        if (INS_OperandIsImplicit(ins, op)) {
            return count;
        }
        count++;
    }

    return count;
}

void traceIns(UINT64 insAddr, std::string insDis, const char *routine) {
    fprintf(trace, "level=info thread=%d routine=\"%s\" ins-addr=0x%08lx ins-dis=\"%s\" traceIns\n", gettid(), routine, insAddr, insDis.c_str());
}

void branchIns(UINT64 insAddr, std::string insDis, const char *routine, bool branchTaken) {
    //fprintf(trace, "level=info thread=%d routine=\"%s\" ins-addr=0x%08lx ins-dis=\"%s\" action=branch taken=%d\n", gettid(), routine, insAddr, insDis.c_str(), branchTaken);
    fprintf(trace, "level=info thread=%d routine=\"%s\" ins-addr=0x%08lx ins-dis=\"%s\"\n", gettid(), routine, insAddr, insDis.c_str());
}

void compareRegToReg(UINT64 insAddr, std::string insDis, const char *routine, REG reg1, ADDRINT regValue1, REG reg2, ADDRINT regValue2) {
    if (isRegTaint(reg1) || isRegTaint(reg2)) {
        fprintf(trace, "level=taint thread=%d routine=\"%s\" ins-addr=0x%08lx ins-dis=\"%s\" action=cmp-reg-reg reg1=%s reg1-value=0x%08lx reg2=%s reg2-value=0x%08lx\n", gettid(), routine, insAddr, insDis.c_str(), REG_StringShort(reg1).c_str(), regValue1, REG_StringShort(reg2).c_str(), regValue2);
    } else {
        fprintf(trace, "level=info thread=%d routine=\"%s\" ins-addr=0x%08lx ins-dis=\"%s\"\n", gettid(), routine, insAddr, insDis.c_str());
    }
}

void compareImmToReg(UINT64 insAddr, std::string insDis, const char *routine, REG reg, ADDRINT regValue, UINT64 imm) {
    if (isRegTaint(reg)) {
        fprintf(trace, "level=taint thread=%d routine=\"%s\" ins-addr=0x%08lx ins-dis=\"%s\" action=cmp-reg reg=%s reg-value=0x%08lx value=0x%08lx\n", gettid(), routine, insAddr, insDis.c_str(), REG_StringShort(reg).c_str(), regValue, imm);
    } else {
        fprintf(trace, "level=info thread=%d routine=\"%s\" ins-addr=0x%08lx ins-dis=\"%s\"\n", gettid(), routine, insAddr, insDis.c_str());
    }
}

void popIns(UINT64 insAddr, std::string insDis, const char *routine, REG reg) {
    if (isRegTaint(reg)) {
        freeTaintReg(reg);
        fprintf(trace, "level=debug thread=%d routine=\"%s\" ins-addr=0x%08lx ins-dis=\"%s\" action=reg-free output=%s\n", gettid(), routine, insAddr, insDis.c_str(), REG_StringShort(reg).c_str());
    } else {
        fprintf(trace, "level=info thread=%d routine=\"%s\" ins-addr=0x%08lx ins-dis=\"%s\"\n", gettid(), routine, insAddr, insDis.c_str());
    }
}

void spreadRegTaint(UINT64 insAddr, std::string insDis, const char *routine, REG regW, REG regR) {
    // Check only if a register is overwritten
    if (REG_valid(regW)) {
        // Taint written register if write comes from other taint register
        if (REG_valid(regR) && isRegTaint(regR)) {
            bool taint = taintReg(regW);
            if (taint) {
                fprintf(trace, "level=debug thread=%d routine=\"%s\" ins-addr=0x%08lx ins-dis=\"%s\" action=reg-taint output=%s input=%s\n", gettid(), routine, insAddr, insDis.c_str(), REG_StringShort(regW).c_str(), REG_StringShort(regR).c_str());
                return;
            }
        // Free taint written register if write doesn't come from a valid register (e.g: immediate) or source
        // register is not taint
        } else if (isRegTaint(regW)) {
            freeTaintReg(regW);
            fprintf(trace, "level=debug thread=%d routine=\"%s\" ins-addr=0x%08lx ins-dis=\"%s\" action=reg-free output=%s input=%s\n", gettid(), routine, insAddr, insDis.c_str(), REG_StringShort(regW).c_str(), REG_valid(regR) ? REG_StringShort(regR).c_str() : "imm");
            return;
        }
    }
    // Log ins otherwirse
    fprintf(trace, "level=info thread=%d routine=\"%s\" ins-addr=0x%08lx ins-dis=\"%s\"\n", gettid(), routine, insAddr, insDis.c_str());
}

void leaIns(UINT64 insAddr, std::string insDis, const char *routine, ADDRINT memAddr, REG reg) {
    if (isMemTaint(memAddr)) {
        fprintf(trace, "level=taint thread=%d routine=\"%s\" ins-addr=0x%08lx ins-dis=\"%s\" action=lea mem-addr=0x%08lx", gettid(), routine, insAddr, insDis.c_str(), memAddr);
        taintReg(reg);
        fprintf(trace, " reg=%s\n", REG_StringShort(reg).c_str());
    } else {
        fprintf(trace, "level=info thread=%d routine=\"%s\" ins-addr=0x%08lx ins-dis=\"%s\"\n", gettid(), routine, insAddr, insDis.c_str());
    }
}

void writeRegToMem(UINT64 insAddr, std::string insDis, const char *routine, UINT64 memAddr, REG reg, ADDRINT regValue) {
    if (isRegTaint(reg)) {
        fprintf(trace, "level=taint thread=%d routine=\"%s\" ins-addr=0x%08lx ins-dis=\"%s\" action=mem-write mem-addr=0x%08lx reg=%s reg-value=0x%08lx\n", gettid(), routine, insAddr, insDis.c_str(), memAddr, REG_StringShort(reg).c_str(), regValue);
        taintMem(memAddr);
    } else if (isMemTaint(memAddr)) {
        fprintf(trace, "level=taint thread=%d routine=\"%s\" ins-addr=0x%08lx ins-dis=\"%s\" action=mem-free mem-addr=0x%08lx reg=%s reg-value=0x%08lx\n", gettid(), routine, insAddr, insDis.c_str(), memAddr, REG_StringShort(reg).c_str(), regValue);
        freeTaintMem(memAddr);
    } else {
        fprintf(trace, "level=info thread=%d routine=\"%s\" ins-addr=0x%08lx ins-dis=\"%s\"\n", gettid(), routine, insAddr, insDis.c_str());
    }
}

void writeImmToMem(UINT64 insAddr, std::string insDis, const char *routine, UINT64 memAddr, UINT64 imm) {
    if (isMemTaint(memAddr)) {
        fprintf(trace, "level=taint thread=%d routine=\"%s\" ins-addr=0x%08lx ins-dis=\"%s\" action=mem-free mem-addr=0x%08lx value=0x%08lx\n", gettid(), routine, insAddr, insDis.c_str(), memAddr, imm);
        freeTaintMem(memAddr);
    } else {
        fprintf(trace, "level=info thread=%d routine=\"%s\" ins-addr=0x%08lx ins-dis=\"%s\"\n", gettid(), routine, insAddr, insDis.c_str());
    }
}

void readMemToReg(UINT64 insAddr, std::string insDis, const char *routine, UINT64 memAddr, REG reg, REG memReg) {
    if (isMemTaint(memAddr)) {
        fprintf(trace, "level=taint thread=%d routine=\"%s\" ins-addr=0x%08lx ins-dis=\"%s\" action=mem-read mem-addr=0x%08lx", gettid(), routine, insAddr, insDis.c_str(), memAddr);
        taintReg(reg);
        fprintf(trace, " reg=%s", REG_StringShort(reg).c_str());
        if (REG_valid(memReg)) {
            taintReg(memReg);
            fprintf(trace, " reg=%s", REG_StringShort(memReg).c_str());
        }
        fprintf(trace, "\n");
    } else {
        fprintf(trace, "level=info thread=%d routine=\"%s\" ins-addr=0x%08lx ins-dis=\"%s\"\n", gettid(), routine, insAddr, insDis.c_str());
    }
}

void compareImmToMem(UINT64 insAddr, std::string insDis, const char *routine, UINT64 memAddr, UINT64 imm) {
    if (isMemTaint(memAddr)) {
        fprintf(trace, "level=taint thread=%d routine=\"%s\" ins-addr=0x%08lx ins-dis=\"%s\" action=cmp-mem mem-addr=0x%08lx value=0x%08lx\n", gettid(), routine, insAddr, insDis.c_str(), memAddr, imm);
    } else {
        fprintf(trace, "level=info thread=%d routine=\"%s\" ins-addr=0x%08lx ins-dis=\"%s\"\n", gettid(), routine, insAddr, insDis.c_str());
    }
}

void traceCall(UINT64 insAddr, std::string insDis, char* routine, ADDRINT targetAddr) {
    std::string target = RTN_FindNameByAddress(targetAddr);

    if (target.empty()) {
        target = "unknown";
    }

    fprintf(trace, "level=info thread=%d routine=\"%s\" ins-addr=0x%08lx ins-dis=\"%s\" action=call target=\"%s\"\n", gettid(), routine, insAddr, insDis.c_str(), target.c_str());
}

void instructionExec(INS ins, void *v) {
    // Return inmediatly if there are no buffers of interest
    if (taint_addrs_by_thread.empty()) {
        return;
    }

    const char* routine = "unknown";
    if (RTN_Valid(INS_Rtn(ins))) {
        routine = RTN_Name(INS_Rtn(ins)).c_str();
    }

    IMG img = IMG_FindByAddress(INS_Address(ins));

    // Just analyze the main executable
    if (IMG_Valid(img) && IMG_IsMainExecutable(img)) {
        if (INS_IsCall(ins)) {
            if (INS_IsControlFlow(ins)) {
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)traceCall,
                    IARG_INST_PTR,
                    IARG_PTR, new std::string(INS_Disassemble(ins)),
                    IARG_PTR, routine,
                    IARG_BRANCH_TARGET_ADDR,
                    IARG_END);
                return;
            }
        } else {
            int opCount = operandCount(ins);
            if (opCount == 2) {
                if ((INS_Opcode(ins) == XED_ICLASS_CMP) && INS_IsMemoryRead(ins) && INS_OperandIsMemory(ins, 0) && INS_OperandIsImmediate(ins, 1)) {
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)compareImmToMem,
                        IARG_INST_PTR,
                        IARG_PTR, new std::string(INS_Disassemble(ins)),
                        IARG_PTR, routine,
                        IARG_MEMORYOP_EA, 0,
                        IARG_UINT64, INS_OperandImmediate(ins, 1),
                        IARG_END);
                    return;
                } else if (INS_IsMemoryRead(ins) && INS_OperandIsReg(ins, 0) && INS_OperandIsMemory(ins, 1)) {
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)readMemToReg,
                        IARG_INST_PTR,
                        IARG_PTR, new std::string(INS_Disassemble(ins)),
                        IARG_PTR, routine,
                        IARG_MEMORYOP_EA, 0,
                        IARG_UINT32, INS_OperandReg(ins, 0),
                        IARG_UINT32, INS_OperandMemoryBaseReg(ins, 1),
                        IARG_END);
                    return;
                } else if (INS_OperandIsReg(ins, 0) && INS_OperandIsAddressGenerator(ins, 1)) {
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)leaIns,
                        IARG_INST_PTR,
                        IARG_PTR, new std::string(INS_Disassemble(ins)),
                        IARG_PTR, routine,
                        IARG_EXPLICIT_MEMORY_EA,
                        IARG_UINT32, INS_OperandReg(ins, 0),
                        IARG_END);
                    return;
                } else if (INS_IsMemoryWrite(ins) && INS_OperandIsMemory(ins, 0) && INS_OperandIsImmediate(ins, 1)) {
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)writeImmToMem,
                        IARG_INST_PTR,
                        IARG_PTR, new std::string(INS_Disassemble(ins)),
                        IARG_PTR, routine,
                        IARG_MEMORYOP_EA, 0,
                        IARG_UINT64, INS_OperandImmediate(ins, 1),
                        IARG_END);
                    return;
                } else if (INS_IsMemoryWrite(ins) && INS_OperandIsMemory(ins, 0) && INS_OperandIsReg(ins, 1) && !REG_is_xmm_ymm_zmm(INS_OperandReg(ins, 1))) {
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)writeRegToMem,
                        IARG_INST_PTR,
                        IARG_PTR, new std::string(INS_Disassemble(ins)),
                        IARG_PTR, routine,
                        IARG_MEMORYOP_EA, 0,
                        IARG_UINT32, INS_OperandReg(ins, 1),
                        IARG_REG_VALUE, INS_OperandReg(ins, 1),
                        IARG_END);
                    return;
                } else if (((INS_Opcode(ins) == XED_ICLASS_CMP) || (INS_Opcode(ins) == XED_ICLASS_TEST)) && INS_OperandIsReg(ins, 0) && INS_OperandIsImmediate(ins, 1)) {
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)compareImmToReg,
                        IARG_INST_PTR,
                        IARG_PTR, new std::string(INS_Disassemble(ins)),
                        IARG_PTR, routine,
                        IARG_UINT32, INS_OperandReg(ins, 0),
                        IARG_REG_VALUE, INS_OperandReg(ins, 0),
                        IARG_UINT64, INS_OperandImmediate(ins, 1),
                        IARG_END);
                    return;
                } else if (((INS_Opcode(ins) == XED_ICLASS_CMP) || (INS_Opcode(ins) == XED_ICLASS_TEST)) && INS_OperandIsReg(ins, 0) && INS_OperandIsReg(ins, 1)) {
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)compareRegToReg,
                        IARG_INST_PTR,
                        IARG_PTR, new std::string(INS_Disassemble(ins)),
                        IARG_PTR, routine,
                        IARG_UINT32, INS_OperandReg(ins, 0),
                        IARG_REG_VALUE, INS_OperandReg(ins, 0),
                        IARG_UINT32, INS_OperandReg(ins, 1),
                        IARG_REG_VALUE, INS_OperandReg(ins, 1),
                        IARG_END);
                    return;
                } else if (INS_OperandIsReg(ins, 0) && INS_OperandWritten(ins, 0) && INS_OperandIsReg(ins, 1) && INS_OperandRead(ins, 1)) {
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)spreadRegTaint,
                        IARG_INST_PTR,
                        IARG_PTR, new std::string(INS_Disassemble(ins)),
                        IARG_PTR, routine,
                        IARG_UINT32, INS_OperandReg(ins, 0),
                        IARG_UINT32, INS_OperandReg(ins, 1),
                        IARG_END);
                    return;
                } else if (INS_OperandIsReg(ins, 0)) {
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)spreadRegTaint,
                        IARG_INST_PTR,
                        IARG_PTR, new std::string(INS_Disassemble(ins)),
                        IARG_PTR, routine,
                        IARG_UINT32, INS_RegW(ins, 0),
                        IARG_UINT32, INS_RegR(ins, 0),
                        IARG_END);
                    return;
                }
            } else if (opCount == 1) {
                if (INS_IsBranch(ins)) {
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)branchIns,
                        IARG_INST_PTR,
                        IARG_PTR, new std::string(INS_Disassemble(ins)),
                        IARG_PTR, routine,
                        IARG_BRANCH_TAKEN,
                        IARG_END);
                    return;
                } else if ((INS_Opcode(ins) == XED_ICLASS_POP) && INS_OperandIsReg(ins, 0) && INS_OperandWritten(ins, 0)) {
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)popIns,
                        IARG_INST_PTR,
                        IARG_PTR, new std::string(INS_Disassemble(ins)),
                        IARG_PTR, routine,
                        IARG_UINT32, INS_OperandIsReg(ins, 0),
                        IARG_END);
                    return;
                }
            }
        }
        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)traceIns,
            IARG_INST_PTR,
            IARG_PTR, new std::string(INS_Disassemble(ins)),
            IARG_PTR, routine,
            IARG_END);
    }
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

    printf("[*] server-tracer: INFO: accept replaced\t: %s\n", IMG_Name(img).c_str());
}

int newCloseFunction(AFUNPTR orgFuncPtr, CONTEXT *ctx, int fd) {
    int ret;

    struct stat statbuf;
    if (fstat(fd, &statbuf) != -1) {
        // Check if fd is a socket
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

    printf("[*] server-tracer: INFO: close replaced\t\t: %s\n", IMG_Name(img).c_str());
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
        std::list<UINT64> taint_addr;
        std::list<REG> taint_regs;

        // Taint all recv data at byte level
        for (int i = 0; i < ret ; i++) {
            taint_addr.push_back((UINT64) *&buf + i);
        }

        taint_addrs_by_thread.insert(std::make_pair(tid, taint_addr));
        taint_regs_by_thread.insert(std::make_pair(tid, taint_regs));
    } else if (strcmp(functionName, "send")) {
        // We only want to keep track of server model
        taint_addrs_by_thread.erase(tid);
        taint_regs_by_thread.erase(tid);
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

    printf("[*] server-tracer: INFO: %s replaced\t\t: %s\n", functionName, IMG_Name(img).c_str());
}

void moduleLoad(IMG img, VOID *v) {
    RTN rtn;

    ADDRINT image_base = IMG_LowAddress(img);
    printf("[*] server-tracer: INFO: Module loaded\t\t: 0x%08lx: %s\n", image_base, IMG_Name(img).c_str());

    // Avoid to hook the main executable
    if (IMG_IsMainExecutable(img)) {
        fprintf(trace, "level=info thread=%d action=relocate image-base=0x%08lx\n", gettid(), image_base);
        printf("[*] server-tracer: INFO: Main module not hooked\t: %s\n", IMG_Name(img).c_str());
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
}

int main(int argc, char* argv[]) {
    puts("[*] server-tracer: INFO: Initializating analysis...");
    // Symbol processing
    PIN_InitSymbols();

    PIN_Init(argc, argv);

    trace = fopen("trace.log", "a");
    puts("[*] server-tracer: INFO: Logging to trace.log");
    fprintf(trace, "-----BEGIN TRACE-----\n");

    PIN_SetSyntaxIntel();

    // Replace calls on module load
    IMG_AddInstrumentFunction(moduleLoad, 0);

    // Instrument instructions
    INS_AddInstrumentFunction(instructionExec, 0);

    // Function called on server exit
    PIN_AddFiniFunction(fini, 0);

    PIN_StartProgram();

    return 0;
}
