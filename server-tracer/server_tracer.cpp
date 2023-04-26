#include "pin.H"

#include <set>
#include <iostream>

#include "log.h"
#include "utilities.h"

#if linux
#include "moduleload_linux.h"
#elif _WIN32 || _WIN64
#include "moduleload_windows.h"
#endif

/* Number of I/O iteractions */
int IOCounter = 0;

/*
* Rely on spatial location to minimize runtime overhead. Usually,
* message parsing is done just after receiving data over the network
*/
#define SPATIAL_THRESHOLD 1000
bool thresholdTriggered = false;

/* Keep track of visited addresses during tracing */
std::set<ADDRINT> visitedAddrs;

/* Main executable limit addresses */
ADDRINT MAIN_MODULE_LOW_ADDRESS = 0;
ADDRINT MAIN_MODULE_HIGH_ADDRESS = 0;

/* Command line options */
KNOB<bool> KnobDebug(KNOB_MODE_WRITEONCE, "pintool", "debug", "0", "Enable debug messages");
KNOB<std::string> KnobLogDir(KNOB_MODE_WRITEONCE, "pintool", "dirlog", ".", "Absolute path of log directory (default to current directory)");

/* Keep track of tainted addresses */
std::set<ADDRINT> taintedAdddrs;
/* Keep track of tainted registers */
bool taintedRegs[REG_LAST];

void fini(INT32 code, VOID *v) {
    LOG_INFO("action=process-end return=%x\n", code);
    CLOSE_LOG();
    if (KnobDebug) {
        PRINT_DEBUG("Analysis finished\t: Checkout \"%s\" folder\n", KnobLogDir.Value().c_str());
    }
}

bool followChild(CHILD_PROCESS cProcess, VOID *val) {
    if (KnobDebug) {
        PRINT_DEBUG("New child process spawned\n");
    }
    LOG_INFO("action=new-child\n");
    /* Flush log file before injecting into new process */
    FLUSH_LOG();
    /* true value to inject PIN into child process */
    return true;
}

void followForkBefore(THREADID threadid, const CONTEXT *ctxt, VOID *v) {
    /* Flush log file before fork */
    FLUSH_LOG();
}

void followForkInParent(THREADID threadid, const CONTEXT *ctxt, VOID *v) {
    LOG_INFO("action=process-forked\n");
}

void followForkInChild(THREADID threadid, const CONTEXT *ctxt, VOID *v) {
    /* Change to corresponding log file */
    std::string filename = getFilePath(KnobLogDir.Value(), getProcessId() + ".log");

    if (KnobDebug) {
        PRINT_DEBUG("New process forked\n");
        PRINT_DEBUG("log file\t\t\t: %s\n", filename.c_str());
    }
    OPEN_LOG(filename.c_str());

    LOG_INFO("action=new-process-forked\n");
}

bool addrIsTraceable(ADDRINT insAddr) {
    /*
    * Just analyze main module. Pin IMG_IsMainExecutable() with TRACE_Address()
    * fails to resolve main executable after glibc local symbols
    */
    if (insAddr > MAIN_MODULE_HIGH_ADDRESS || insAddr < MAIN_MODULE_LOW_ADDRESS) {
        return false;
    }

    if (visitedAddrs.size() >= SPATIAL_THRESHOLD) {
        return false;
    }

    visitedAddrs.insert(insAddr);

    return true;
}

void logInsOpcodes(ADDRINT insAddr, USIZE insSize) {
    /*
    * Intel® 64 and IA-32 Architectures Software Developer’s Manual Volume 2A: Instruction Set Reference, A-L
    * The maximum length of an Intel 64 and IA-32 instruction remains 15 bytes
    */
    void* buf[15];
    int ret = PIN_SafeCopy(buf, (void*) insAddr, insSize);
    
    if ((ret > 0) && (ret == ((int)insSize))) {
        for (int i = 0; i < ret; i++) {
            LOG_RAW("%02x", ((unsigned char*) buf)[i]);
        }
    } else {
        LOG_RAW("\"unable to get opcodes\"");
    }
}

void logIns(ADDRINT insAddr, USIZE insSize, std::string *insDis, const char *routine, ADDRINT routineAddr) {
    LOG_INFO("io-counter=%d action=log-ins routine=\"%s\" routine-addr=%s ins-addr=%s ins-dis=\"%s\" ins-opcodes=", IOCounter, routine, hexaddr(routineAddr).c_str(), hexaddr(insAddr).c_str(), insDis->c_str());
    logInsOpcodes(insAddr, insSize);
    LOG_RAW("\n");
}

void traceIns(ADDRINT insAddr, USIZE insSize, std::string *insDis, const char *routine, ADDRINT routineAddr) {
    if (!addrIsTraceable(insAddr)) {
        return;
    }

    logIns(insAddr, insSize, insDis, routine, routineAddr);
}

/* Register copied to memory */
void regToAddr(ADDRINT insAddr, USIZE insSize, std::string *insDis, char *routine, ADDRINT routineAddr, REG regAddr, ADDRINT addr, REG reg) {
    if (!addrIsTraceable(insAddr)) {
        return;
    }

    if (taintedRegs[reg]) {
        LOG_TAINT("io-counter=%d action=taint-addr routine=\"%s\" routine-addr=%s ins-addr=%s ins-dis=\"%s\" ins-opcodes=", IOCounter, routine, hexaddr(routineAddr).c_str(), hexaddr(insAddr).c_str(), insDis->c_str());
        logInsOpcodes(insAddr, insSize);
        LOG_RAW(" origin=reg addr=%s reg-addr=%s reg=%s\n", hexaddr(addr).c_str(), REG_StringShort(regAddr).c_str(), REG_StringShort(reg).c_str());
        taintedAdddrs.insert(addr);
    } else {
        /* reg not tainted --> mem not tainted */
        /* if mem is already not tainted, nothing to do */
        if (taintedAdddrs.count(addr)) {
            LOG_TAINT("io-counter=%d action=free-addr routine=\"%s\" routine-addr=%s ins-addr=%s ins-dis=\"%s\" ins-opcodes=", IOCounter, routine, hexaddr(routineAddr).c_str(), hexaddr(insAddr).c_str(), insDis->c_str());
            logInsOpcodes(insAddr, insSize);
            LOG_RAW(" origin=reg addr=%s reg-addr=%s reg=%s\n", hexaddr(addr).c_str(), REG_StringShort(regAddr).c_str(), REG_StringShort(reg).c_str());
            taintedAdddrs.erase(taintedAdddrs.find(addr));
        } else {
            logIns(insAddr, insSize, insDis, routine, routineAddr);
        }
    }
}

/* Memory copied to register */
void addrToReg(ADDRINT insAddr, USIZE insSize, std::string *insDis, char *routine, ADDRINT routineAddr, ADDRINT mem_r, REG reg_w) {
    if (!addrIsTraceable(insAddr)) {
        return;
    }

    if (taintedAdddrs.count(mem_r)) {
        LOG_TAINT("io-counter=%d action=taint-reg routine=\"%s\" routine-addr=%s ins-addr=%s ins-dis=\"%s\" ins-opcodes=", IOCounter, routine, hexaddr(routineAddr).c_str(), hexaddr(insAddr).c_str(), insDis->c_str());
        logInsOpcodes(insAddr, insSize);
        LOG_RAW(" origin=addr reg=%s addr=%s\n", REG_StringShort(reg_w).c_str(), hexaddr(mem_r).c_str());
        taintedRegs[reg_w] = true;
    } else if (taintedRegs[reg_w]) {
        /* mem is clean -> reg is cleaned */
        LOG_TAINT("io-counter=%d action=free-reg routine=\"%s\" routine-addr=%s ins-addr=%s ins-dis=\"%s\" ins-opcodes=", IOCounter , routine, hexaddr(routineAddr).c_str(), hexaddr(insAddr).c_str(), insDis->c_str());
        logInsOpcodes(insAddr, insSize);
        LOG_RAW(" origin=addr reg=%s addr=%s\n", REG_StringShort(reg_w).c_str(), hexaddr(mem_r).c_str());
        taintedRegs[reg_w] = false;
    } else {
        logIns(insAddr, insSize, insDis, routine, routineAddr);
    }
}

/* Reg copied to another reg */
void regToReg(ADDRINT insAddr, USIZE insSize, std::string *insDis, char *routine, ADDRINT routineAddr, REG reg_r, REG reg_w) {
    if (!addrIsTraceable(insAddr)) {
        return;
    }

    if (taintedRegs[reg_r]) {
        LOG_TAINT("io-counter=%d action=taint-reg routine=\"%s\" routine-addr=%s ins-addr=%s ins-dis=\"%s\" ins-opcodes=", IOCounter, routine, hexaddr(routineAddr).c_str(), hexaddr(insAddr).c_str(), insDis->c_str());
        logInsOpcodes(insAddr, insSize);
        LOG_RAW(" origin=reg reg-taint=%s reg-origin=%s\n", REG_StringShort(reg_w).c_str(), REG_StringShort(reg_r).c_str());
        taintedRegs[reg_w] = true;
    } else if (taintedRegs[reg_w]) {
        LOG_TAINT("io-counter=%d action=free-reg routine=\"%s\" routine-addr=%s ins-addr=%s ins-dis=\"%s\" ins-opcodes=", IOCounter, routine, hexaddr(routineAddr).c_str(), hexaddr(insAddr).c_str(), insDis->c_str());
        logInsOpcodes(insAddr, insSize);
        LOG_RAW(" origin=reg reg-free=%s reg-origin=%s\n", REG_StringShort(reg_w).c_str(), REG_StringShort(reg_r).c_str());
        taintedRegs[reg_w] = false;
    } else {
        logIns(insAddr, insSize, insDis, routine, routineAddr);
    }
}

/* Immediate copied to a register */
void immToReg(ADDRINT insAddr, USIZE insSize, std::string *insDis, char *routine, ADDRINT routineAddr, REG reg_w) {
    if (!addrIsTraceable(insAddr)) {
        return;
    }

    if (taintedRegs[reg_w]) {
        LOG_TAINT("io-counter=%d action=free-reg routine=\"%s\" routine-addr=%s ins-addr=%s ins-dis=\"%s\" ins-opcodes=", IOCounter, routine, hexaddr(routineAddr).c_str(), hexaddr(insAddr).c_str(), insDis->c_str());
        logInsOpcodes(insAddr, insSize);
        LOG_RAW(" reg=%s\n", REG_StringShort(reg_w).c_str());
        taintedRegs[reg_w] = false;
    } else {
        logIns(insAddr, insSize, insDis, routine, routineAddr);
    }
}

/* Immediate copied to memory address */
void immToAddr(ADDRINT insAddr, USIZE insSize, std::string *insDis, char *routine, ADDRINT routineAddr, ADDRINT mem_w) {
    if (!addrIsTraceable(insAddr)) {
        return;
    }

    /* if mem is not tainted nothing to do */
    if (taintedAdddrs.count(mem_w)) {
        LOG_TAINT("io-counter=%d action=free-addr routine=\"%s\" routine-addr=%s ins-addr=%s ins-dis=\"%s\" ins-opcodes=", IOCounter,routine, hexaddr(routineAddr).c_str(), hexaddr(insAddr).c_str(), insDis->c_str());
        logInsOpcodes(insAddr, insSize);
        LOG_RAW(" addr=%s\n", hexaddr(mem_w).c_str());
        taintedAdddrs.erase(taintedAdddrs.find(mem_w));
    } else {
        logIns(insAddr, insSize, insDis, routine, routineAddr);
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
void traceCall(ADDRINT insAddr, USIZE insSize, std::string *insDis, char *routine, ADDRINT routineAddr, char *callType, ADDRINT targetAddr) {
    if (!addrIsTraceable(insAddr)) {
        return;
    }

    std::string target = RTN_FindNameByAddress(targetAddr);

    if (target.empty()) {
        target = "unknown";
    }

    LOG_INFO("io-counter=%d action=%s routine=\"%s\" routine-addr=%s ins-addr=%s ins-dis=\"%s\" ins-opcodes=", IOCounter, callType, routine, hexaddr(routineAddr).c_str(), hexaddr(insAddr).c_str(), insDis->c_str());
    logInsOpcodes(insAddr, insSize);
    LOG_RAW(" target-addr=%s target=\"%s\"\n", hexaddr(targetAddr).c_str(), target.c_str());
}

/* Analyzes mov instructions */
void propagateTaint(INS ins, const char *routine, ADDRINT routineAddr) {
    if (hasImm(ins)) {
        /* [addr] <- imm */
        if (INS_IsMemoryWrite(ins)) {
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)immToAddr,
                IARG_INST_PTR,
                IARG_UINT32, INS_Size(ins),
                IARG_PTR, new std::string(INS_Disassemble(ins)),
                IARG_PTR, routine,
                IARG_ADDRINT, routineAddr,
                IARG_MEMORYOP_EA, 0,
                IARG_END);
        } else {
            /* reg <- imm */
            REG reg = getWriteReg(ins);
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)immToReg,
                IARG_INST_PTR,
                IARG_UINT32, INS_Size(ins),
                IARG_PTR, new std::string(INS_Disassemble(ins)),
                IARG_PTR, routine,
                IARG_ADDRINT, routineAddr,
                IARG_PTR, reg,
                IARG_END);
        }
    } else if (INS_IsMemoryRead(ins)) {
        /* reg <- [addr] */
        REG reg = getWriteReg(ins);
        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)addrToReg,
            IARG_INST_PTR,
            IARG_UINT32, INS_Size(ins),
            IARG_PTR, new std::string(INS_Disassemble(ins)),
            IARG_PTR, routine,
            IARG_ADDRINT, routineAddr,
            IARG_MEMORYOP_EA, 0,
            IARG_PTR, reg,
            IARG_END);
    } else if (INS_IsMemoryWrite(ins)) {
        /* [addr] <- reg */
        REG regAddr = getMemoryReg(ins);
        REG reg = getReg(ins);
        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)regToAddr,
            IARG_INST_PTR,
            IARG_UINT32, INS_Size(ins),
            IARG_PTR, new std::string(INS_Disassemble(ins)),
            IARG_PTR, routine,
            IARG_ADDRINT, routineAddr,
            IARG_PTR, regAddr,
            IARG_MEMORYOP_EA, 0,
            IARG_PTR, reg,
            IARG_END);
    } else if (INS_RegR(ins, 0) != REG_INVALID()) {
        /* reg <- reg */
        REG reg_r = getReadReg(ins);
        REG reg_w = getWriteReg(ins);
        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)regToReg,
            IARG_INST_PTR,
            IARG_UINT32, INS_Size(ins),
            IARG_PTR, new std::string(INS_Disassemble(ins)),
            IARG_PTR, routine,
            IARG_ADDRINT, routineAddr,
            IARG_PTR, reg_r,
            IARG_PTR, reg_w,
            IARG_END);
    } else {
        PRINT_WARNING("Unable to propagate taint info: %s\n", INS_Disassemble(ins).c_str());
    }
}

void analyzeCall(INS ins, const char *routine, ADDRINT routineAddr) {
    /* call addr */
    if (INS_IsDirectControlFlow(ins)) {
        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)traceCall,
            IARG_INST_PTR,
            IARG_UINT32, INS_Size(ins),
            IARG_PTR, new std::string(INS_Disassemble(ins)),
            IARG_PTR, routine,
            IARG_ADDRINT, routineAddr,
            IARG_PTR, "direct-call",
            IARG_BRANCH_TARGET_ADDR,
            IARG_END);
    } else if (INS_IsIndirectControlFlow(ins)) {
        /* call [reg] */
        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)traceCall,
            IARG_INST_PTR,
            IARG_UINT32, INS_Size(ins),
            IARG_PTR, new std::string(INS_Disassemble(ins)),
            IARG_PTR, routine,
            IARG_ADDRINT, routineAddr,
            IARG_PTR, "indirect-call",
            IARG_BRANCH_TARGET_ADDR,
            IARG_END);
    } else {
        PRINT_WARNING("Unknown call: %s\n", INS_Disassemble(ins).c_str());
    }
}

/* Immediate compared to memory address */
void compareImmToAddr(ADDRINT insAddr, USIZE insSize, std::string *insDis, char *routine, ADDRINT routineAddr, ADDRINT mem_r, REG reg_r, ADDRINT imm) {
    if (!addrIsTraceable(insAddr)) {
        return;
    }

    if (taintedAdddrs.count(mem_r)) {
        LOG_TAINT("io-counter=%d action=compare routine=\"%s\" routine-addr=%s ins-addr=%s ins-dis=\"%s\" ins-opcodes=", IOCounter, routine, hexaddr(routineAddr).c_str(), hexaddr(insAddr).c_str(), insDis->c_str());
        logInsOpcodes(insAddr, insSize);
        LOG_RAW(" origin=imm-addr addr=%s reg=%s imm=%s\n", hexaddr(mem_r).c_str(), REG_StringShort(reg_r).c_str(), hexaddr(imm).c_str());
    } else {
        logIns(insAddr, insSize, insDis, routine, routineAddr);
    }
}

/* Immediate compared to register */
void compareImmToReg(ADDRINT insAddr, USIZE insSize, std::string *insDis, char *routine, ADDRINT routineAddr, REG reg, ADDRINT regValue, ADDRINT imm) {
    if (!addrIsTraceable(insAddr)) {
        return;
    }

    if (taintedRegs[reg]) {
        LOG_TAINT("io-counter=%d action=compare routine=\"%s\" routine-addr=%s ins-addr=%s ins-dis=\"%s\" ins-opcodes=", IOCounter, routine, hexaddr(routineAddr).c_str(), hexaddr(insAddr).c_str(), insDis->c_str());
        logInsOpcodes(insAddr, insSize);
        LOG_RAW(" origin=imm-reg reg=%s reg-value=%s imm=%s\n", REG_StringShort(reg).c_str(), hexaddr(regValue).c_str(), hexaddr(imm).c_str());
    } else {
        logIns(insAddr, insSize, insDis, routine, routineAddr);
    }
}

/* Register compared to register */
void compareRegToReg(ADDRINT insAddr, USIZE insSize, std::string *insDis, char *routine, ADDRINT routineAddr, REG reg1, REG reg2) {
    if (!addrIsTraceable(insAddr)) {
        return;
    }

    if (taintedRegs[reg1] || taintedRegs[reg2]) {
        LOG_TAINT("io-counter=%d action=compare outine=\"%s\" routine-addr=%s ins-addr=%s ins-dis=\"%s\" ins-opcodes=", IOCounter, routine, hexaddr(routineAddr).c_str(), hexaddr(insAddr).c_str(), insDis->c_str());
        logInsOpcodes(insAddr, insSize);
        LOG_RAW(" origin=reg-reg reg1=%s reg2=%s\n", REG_StringShort(reg1).c_str(), REG_StringShort(reg2).c_str());
    } else {
        logIns(insAddr, insSize, insDis, routine, routineAddr);
    }
}

void analyzeComparison(INS ins, const char *routine, ADDRINT routineAddr) {
    if (hasImm(ins)) {
        /* [addr] == imm */
        if (INS_IsMemoryRead(ins)) {
            REG reg = getMemoryReg(ins);
            ADDRINT imm = getImm(ins);
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)compareImmToAddr,
                IARG_INST_PTR,
                IARG_UINT32, INS_Size(ins),
                IARG_PTR, new std::string(INS_Disassemble(ins)),
                IARG_PTR, routine,
                IARG_ADDRINT, routineAddr,
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
                IARG_UINT32, INS_Size(ins),
                IARG_PTR, new std::string(INS_Disassemble(ins)),
                IARG_PTR, routine,
                IARG_ADDRINT, routineAddr,
                IARG_PTR, reg,
                IARG_REG_VALUE, reg,
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
            IARG_UINT32, INS_Size(ins),
            IARG_PTR, new std::string(INS_Disassemble(ins)),
            IARG_PTR, routine,
            IARG_ADDRINT, routineAddr,
            IARG_PTR, reg1,
            IARG_PTR, reg2,
            IARG_END);
    } else {
        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)traceIns,
            IARG_INST_PTR,
            IARG_UINT32, INS_Size(ins),
            IARG_PTR, new std::string(INS_Disassemble(ins)),
            IARG_PTR, routine,
            IARG_ADDRINT, routineAddr,
            IARG_END);
    }
}

/*
* This function checks for each instruction if it does a mov that can potentially
* transfer taint and if true adds the approriate analysis routine to check
* and propogate taint at run-time if needed
* This function is called every time a new trace is encountered.
*/
void instrumentTrace(TRACE trace, void *v) {
    /* Return inmediatly if there are no buffers of interest */
    if (taintedAdddrs.empty()) {
        return;
    }

    /* Or we surprassed the spatial location threshold */
    if (visitedAddrs.size() >= SPATIAL_THRESHOLD) {
        if (!thresholdTriggered) {
            LOG_INFO("io-counter=%d action=spatial-threshold-triggered\n", IOCounter);
            thresholdTriggered = true;
        }
        return;
    }

    const char *routine = "unknown";
    ADDRINT routineAddr = 0;
    RTN rtn = TRACE_Rtn(trace);
    if (RTN_Valid(rtn)) {
        routine = RTN_Name(rtn).c_str();
        routineAddr = RTN_Address(rtn);
    }

    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
            if ((INS_Opcode(ins) >= XED_ICLASS_MOV) && (INS_Opcode(ins) <= XED_ICLASS_MOVZX)) {
                propagateTaint(ins, routine, routineAddr);
            } else if (INS_IsCall(ins)) {
                analyzeCall(ins, routine, routineAddr);
            } else if ((INS_Opcode(ins) == XED_ICLASS_CMP) || (INS_Opcode(ins) == XED_ICLASS_TEST)) {
                analyzeComparison(ins, routine, routineAddr);
            } else {
                INS_InsertCall(
                    ins, IPOINT_BEFORE, (AFUNPTR)traceIns,
                    IARG_INST_PTR,
                    IARG_UINT32, INS_Size(ins),
                    IARG_PTR, new std::string(INS_Disassemble(ins)),
                    IARG_PTR, routine,
                    IARG_ADDRINT, routineAddr,
                    IARG_END);
            }
        }
    }
}

void moduleLoad(IMG img, void *v) {
    ADDRINT image_low = IMG_LowAddress(img);
    ADDRINT image_high = IMG_HighAddress(img);

    /* Avoid to hook the main executable */
    if (IMG_IsMainExecutable(img)) {
        if (KnobDebug) {
            PRINT_DEBUG("Main module loaded\t\t: %s (%s)\n", IMG_Name(img).c_str(), hexaddr(image_low).c_str());
        }
        LOG_INFO("action=relocate image-low=%s image-high=%s main-executable=\"%s\"\n", hexaddr(image_low).c_str(), hexaddr(image_high).c_str(), IMG_Name(img).c_str());
        MAIN_MODULE_LOW_ADDRESS = image_low;
        MAIN_MODULE_HIGH_ADDRESS = image_high;
        return;
    }

    if (KnobDebug) {
        PRINT_DEBUG("Module loaded\t\t\t: %s (%s)\n", IMG_Name(img).c_str(), hexaddr(image_low).c_str());
    }

    replaceSignatures(KnobDebug, img, taintedAdddrs, taintedRegs, visitedAddrs, thresholdTriggered, IOCounter);
}

int usage() {
    std::cerr << std::endl << "This Pintool traces all data activity sent and received over the network" << std::endl;
    std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;

    return -1;
}

int main(int argc, char *argv[]) {
    /* Symbol processing */
    PIN_InitSymbols();

    /* Init PIN framework */
    if (PIN_Init(argc, argv)) {
        return usage();
    }

    /* Output file to PID.log */
    std::string filename = getFilePath(KnobLogDir.Value(), getProcessId() + ".log");

    if (KnobDebug) {
        PRINT_DEBUG("Analysis started\n");
        PRINT_DEBUG("log file\t\t\t: %s\n", filename.c_str());
    }

    OPEN_LOG(filename.c_str());

    LOG_INFO("action=process-begin\n");

    /* Disassembly syntax to Intel format */
    PIN_SetSyntaxIntel();

    /* Replace calls on module load */
    IMG_AddInstrumentFunction(moduleLoad, 0);

    /* Instrument traces */
    TRACE_AddInstrumentFunction(instrumentTrace, 0);

    /* Follow child processes */
    PIN_AddFollowChildProcessFunction(followChild, 0);

    /* Follow before fork function in the parent process */
    PIN_AddForkFunction(FPOINT_BEFORE, followForkBefore, 0);

    /* Follow after fork function in the parent process */
    PIN_AddForkFunction(FPOINT_AFTER_IN_PARENT, followForkInParent, 0);

    /* Follow after fork function in the child process */
    PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD, followForkInChild, 0);

    /* Function called on program exit */
    PIN_AddFiniFunction(fini, 0);

    /* Start program and never returns */
    PIN_StartProgram();

    return 0;
}