#include "pin.H"
#include <stdio.h>

/* Output file */
FILE* trace;

void moduleLoad(IMG img, VOID *v) {
    ADDRINT image_base = IMG_LowAddress(img);
    printf("[*] server-tracer\t: INFO\t: Module loaded\t\t: %s (0x%08lx)\n", IMG_Name(img).c_str(), image_base);
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

    /* Function called on server exit */
    PIN_AddFiniFunction(fini, 0);

    PIN_StartProgram();

    return 0;
}
