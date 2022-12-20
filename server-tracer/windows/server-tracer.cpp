#include "pin.H"
#include <iostream>

#include "log.h"
#include "moduleload_windows.h"

void fini(INT32 code, void* v) {
    Logger::getInstance()->log("-----END TRACE-----\n");
    Logger::getInstance()->close();
    std::cout << "[*] server-tracer\t: INFO\t: Analysis finished" << std::endl;
}

int usage() {
    std::cout << "This Pintool aims to infer the protocol message format and protocol finite state machine of an unknown protocol" << std::endl;
    std::cout << KNOB_BASE::StringKnobSummary() << std::endl;

    return -1;
}

int main(int argc, char* argv[]) {
    std::cout << "[*] server-tracer\t: INFO\t: Analysis started" << std::endl;
    /* Symbol processing */
    PIN_InitSymbols();

    if (PIN_Init(argc, argv)) {
        return usage();
    }

    std::cout << "[*] server-tracer\t: INFO\t: Log file\t\t: " << Logger::getInstance()->getLogFileName() << std::endl;
    Logger::getInstance()->log("-----BEGIN TRACE-----\n");

    PIN_SetSyntaxIntel();

    /* Replace calls on module load */
    IMG_AddInstrumentFunction(moduleLoad, 0);

    /* Function called on program exit */
    PIN_AddFiniFunction(fini, 0);

    /* Start program and never returns */
    PIN_StartProgram();

    return 0;
}