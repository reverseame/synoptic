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

/*
* Rely on spatial location to minimize runtime overhead. Usually,
* message parsing is done just after receiving data over the network
*/
#define TRACE_THRESHOLD 1000
int insCount = 0;

/* Command line options */
KNOB<bool> KnobDebug(KNOB_MODE_WRITEONCE, "pintool", "debug", "0", "Enable debug messages");
KNOB<std::string> KnobLogFile(KNOB_MODE_WRITEONCE, "pintool", "log", "trace.log", "Absolute path of log filename (default to trace.log in current directory)");

/* Keep track of tainted addresses */
std::set<ADDRINT> taintedAdddrs;
/* Keep track of tainted registers */
bool taintedRegs[REG_LAST];

void fini(INT32 code, VOID *v) {
    LOG_INFO("action=process-end return=%x\n", code);
    //CLOSE_LOG();       // Rely on SO closing file during normal existing. Not calling close prevents several processes calling common log file
    if (KnobDebug) {
        PRINT_DEBUG("Analysis finished (PID: %s)\n", getProcessId().c_str());
    }
}

bool followChild(CHILD_PROCESS cProcess, VOID *val) {
    if (KnobDebug) {
        PRINT_DEBUG("New child process spawned\n");
    }
    LOG_INFO("action=new-child\n");
    /* true value to inject PIN into child process */
    return true;
}

void followForkInChild(THREADID threadid, const CONTEXT *ctxt, VOID *v) {
    if (KnobDebug) {
        PRINT_DEBUG("New process forked (PID: %s)\n", getProcessId().c_str());
    }
    LOG_INFO("action=process-forked\n");
}

void traceIns(ADDRINT insAddr, std::string *insDis, const char *routine) {
    LOG_INFO("routine=\"%s\" ins-addr=%s ins-dis=\"%s\"\n", routine, hexaddr(insAddr).c_str(), insDis->c_str());
}

/* Register copied to memory */
void regToAddr(ADDRINT insAddr, std::string *insDis, char *routine, ADDRINT reg_r, ADDRINT mem_w) {
    if (taintedRegs[reg_r]) {
        LOG_TAINT("routine=\"%s\" ins-addr=%s ins-dis=\"%s\" action=taint-addr origin=reg addr=%s reg=%s\n", routine, hexaddr(insAddr).c_str(), insDis->c_str(), hexaddr(mem_w).c_str(), REG_StringShort((REG)reg_r).c_str());
        taintedAdddrs.insert(mem_w);
    } else {
        /* reg not tainted --> mem not tainted */
        /* if mem is already not tainted nothing to do */
        if (taintedAdddrs.count(mem_w)) {
            LOG_TAINT("routine=\"%s\" ins-addr=%s ins-dis=\"%s\" action=free-addr origin=reg addr=%s reg=%s\n", routine, hexaddr(insAddr).c_str(), insDis->c_str(), hexaddr(mem_w).c_str(), REG_StringShort((REG)reg_r).c_str());
            taintedAdddrs.erase(taintedAdddrs.find(mem_w));
        } else {
            traceIns(insAddr, insDis, routine);
        }
    }
}

/* Memory copied to register */
void addrToReg(ADDRINT insAddr, std::string *insDis, char *routine, ADDRINT mem_r, ADDRINT reg_w) {
    if (taintedAdddrs.count(mem_r)) {
        LOG_TAINT("routine=\"%s\" ins-addr=%s ins-dis=\"%s\" action=taint-reg origin=addr reg=%s addr=%s\n", routine, hexaddr(insAddr).c_str(), insDis->c_str(), REG_StringShort((REG)reg_w).c_str(), hexaddr(mem_r).c_str());
        taintedRegs[reg_w] = true;
    } else if (taintedRegs[reg_w]) {
        /* mem is clean -> reg is cleaned */
        LOG_TAINT("routine=\"%s\" ins-addr=%s ins-dis=\"%s\" action=free-reg origin=addr reg=%s addr=%s\n", routine, hexaddr(insAddr).c_str(), insDis->c_str(), REG_StringShort((REG)reg_w).c_str(), hexaddr(mem_r).c_str());
        taintedRegs[reg_w] = false;
    } else {
        traceIns(insAddr, insDis, routine);
    }
}

/* Reg copied to another reg */
void regToReg(ADDRINT insAddr, std::string *insDis, char *routine, ADDRINT reg_r, ADDRINT reg_w) {
    if (taintedRegs[reg_r]) {
        LOG_TAINT("routine=\"%s\" ins-addr=%s ins-dis=\"%s\" action=taint-reg origin=reg reg-taint=%s reg-origin=%s\n", routine, hexaddr(insAddr).c_str(), insDis->c_str(), REG_StringShort((REG)reg_w).c_str(), REG_StringShort((REG)reg_r).c_str());
        taintedRegs[reg_w] = true;
    } else if (taintedRegs[reg_w]) {
        LOG_TAINT("routine=\"%s\" ins-addr=%s ins-dis=\"%s\" action=free-reg origin=reg reg-free=%s reg-origin=%s\n", routine, hexaddr(insAddr).c_str(), insDis->c_str(), REG_StringShort((REG)reg_w).c_str(), REG_StringShort((REG)reg_r).c_str());
        taintedRegs[reg_w] = false;
    } else {
        traceIns(insAddr, insDis, routine);
    }
}

/* Immediate copied to a register */
void immToReg(ADDRINT insAddr, std::string *insDis, char *routine, ADDRINT reg_w) {
    if (taintedRegs[reg_w]) {
        LOG_TAINT("routine=\"%s\" ins-addr=%s ins-dis=\"%s\" action=free-reg reg=%s\n", routine, hexaddr(insAddr).c_str(), insDis->c_str(), REG_StringShort((REG)reg_w).c_str());
        taintedRegs[reg_w] = false;
    } else {
        traceIns(insAddr, insDis, routine);
    }
}

/* Immediate copied to memory address */
void immToAddr(ADDRINT insAddr, std::string *insDis, char *routine, ADDRINT mem_w) {
    /* if mem is not tainted nothing to do */
    if (taintedAdddrs.count(mem_w)) {
        LOG_TAINT("routine=\"%s\" ins-addr=%s ins-dis=\"%s\" action=free-addr addr=%s\n", routine, hexaddr(insAddr).c_str(), insDis->c_str(), hexaddr(mem_w).c_str());
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
void traceCall(ADDRINT insAddr, std::string *insDis, char *routine, char *callType, ADDRINT targetAddr) {
    std::string target = RTN_FindNameByAddress(targetAddr);

    if (target.empty()) {
        target = "unknown";
    }

    LOG_INFO("routine=\"%s\" ins-addr=%s ins-dis=\"%s\" action=%s target=\"%s\"\n", routine, hexaddr(insAddr).c_str(), insDis->c_str(), callType, target.c_str());
}

/* Analyzes mov instructions */
void propagateTaint(INS ins, const char *routine) {
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
        PRINT_WARNING("Unable to propagate taint info: %s\n", INS_Disassemble(ins).c_str());
    }
}

void analyzeCall(INS ins, const char *routine) {
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
        PRINT_WARNING("Unknown call: %s\n", INS_Disassemble(ins).c_str());
    }
}

/* Immediate compared to memory address */
void compareImmToAddr(ADDRINT insAddr, std::string *insDis, char *routine, ADDRINT mem_r, REG reg_r, ADDRINT imm) {
    if (taintedAdddrs.count(mem_r)) {
        LOG_TAINT("routine=\"%s\" ins-addr=%s ins-dis=\"%s\" action=compare origin=imm-addr addr=%s reg=%s imm=%s\n", routine, hexaddr(insAddr).c_str(), insDis->c_str(), hexaddr(mem_r).c_str(), REG_StringShort(reg_r).c_str(), hexaddr(imm).c_str());
    } else {
        traceIns(insAddr, insDis, routine);
    }
}

/* Immediate compared to register */
void compareImmToReg(ADDRINT insAddr, std::string *insDis, char *routine, REG reg, ADDRINT imm) {
    if (taintedRegs[reg]) {
        LOG_TAINT("routine=\"%s\" ins-addr=%s ins-dis=\"%s\" action=compare origin=imm-reg reg=%s imm=%s\n", routine, hexaddr(insAddr).c_str(), insDis->c_str(), REG_StringShort(reg).c_str(), hexaddr(imm).c_str());
    } else {
        traceIns(insAddr, insDis, routine);
    }
}

/* Register compared to register */
void compareRegToReg(ADDRINT insAddr, std::string *insDis, char *routine, REG reg1, REG reg2) {
    if (taintedRegs[reg1] || taintedRegs[reg2]) {
        LOG_TAINT("routine=\"%s\" ins-addr=%s ins-dis=\"%s\" action=compare origin=reg-reg reg1=%s reg2=%s\n", routine, hexaddr(insAddr).c_str(), insDis->c_str(), REG_StringShort(reg1).c_str(), REG_StringShort(reg2).c_str());
    } else {
        traceIns(insAddr, insDis, routine);
    }
}

void analyzeComparison(INS ins, const char *routine) {
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
        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)traceIns,
            IARG_INST_PTR,
            IARG_PTR, new std::string(INS_Disassemble(ins)),
            IARG_PTR, routine,
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
    /*
    * Return inmediatly if there are no buffers of interest or we surprassed the
    * spatial location threshold
    */
    if (taintedAdddrs.empty() || insCount >= TRACE_THRESHOLD) {
        return;
    }

    /* Just analyze the main executable */
    IMG img = IMG_FindByAddress(TRACE_Address(trace));
    if (!IMG_Valid(img) || !IMG_IsMainExecutable(img)) {
        return;
    }

    const char *routine = "unknown";
    if (RTN_Valid(TRACE_Rtn(trace))) {
        routine = RTN_Name(TRACE_Rtn(trace)).c_str();
    }

    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        for (INS ins = BBL_InsHead(bbl); insCount < TRACE_THRESHOLD && INS_Valid(ins); ins = INS_Next(ins), insCount++) {
            PRINT_DEBUG("insCount: %d\n", insCount);
            if ((INS_Opcode(ins) >= XED_ICLASS_MOV) && (INS_Opcode(ins) <= XED_ICLASS_MOVZX)) {
                propagateTaint(ins, routine);
            } else if (INS_IsCall(ins)) {
                analyzeCall(ins, routine);
            } else if ((INS_Opcode(ins) == XED_ICLASS_CMP) || (INS_Opcode(ins) == XED_ICLASS_TEST)) {
                analyzeComparison(ins, routine);
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

void moduleLoad(IMG img, void *v) {
    ADDRINT image_base = IMG_LowAddress(img);

    /* Avoid to hook the main executable */
    if (IMG_IsMainExecutable(img)) {
        if (KnobDebug) {
            PRINT_DEBUG("Main module loaded\t\t: %s (%s)\n", IMG_Name(img).c_str(), hexaddr(image_base).c_str());
        }
        LOG_INFO("action=relocate image-base=%s main-executable=%s\n", hexaddr(image_base).c_str(), IMG_Name(img).c_str());
        return;
    }

    if (KnobDebug) {
        PRINT_DEBUG("Module loaded\t\t\t: %s (%s)\n", IMG_Name(img).c_str(), hexaddr(image_base).c_str());
    }

    replaceSignatures(KnobDebug, img, taintedAdddrs, taintedRegs, insCount);
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

    if (KnobDebug) {
        PRINT_DEBUG("Analysis started (PID: %s)\n", getProcessId().c_str());
        PRINT_DEBUG("log file\t\t\t: %s\n", KnobLogFile.Value().c_str());
    }

    OPEN_LOG(KnobLogFile.Value().c_str());

    LOG_INFO("action=process-begin\n");

    /* Disassembly syntax to Intel format */
    PIN_SetSyntaxIntel();

    /* Replace calls on module load */
    IMG_AddInstrumentFunction(moduleLoad, 0);

    /* Instrument traces */
    TRACE_AddInstrumentFunction(instrumentTrace, 0);

    /* Follow child processes */
    PIN_AddFollowChildProcessFunction(followChild, 0);

    /* Follow after fork function in the child process */
    PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD, followForkInChild, 0);

    /* Function called on program exit */
    PIN_AddFiniFunction(fini, 0);

    /* Start program and never returns */
    PIN_StartProgram();

    return 0;
}