#include "log.h"
#include "util.h"
#include "moduleload.h"

#include <iostream>

VOID moduleLoad(IMG img, VOID* v) {
    ADDRINT image_base = IMG_LowAddress(img);
    std::cout << "[*] server-tracer\t: INFO\t: Module loaded\t\t: " << IMG_Name(img) << " (" << hexily(image_base) << ")" << std::endl;

    /* Avoid to hook the main executable */
    if (IMG_IsMainExecutable(img)) {
        Logger::getInstance()->logInfo(std::string("thread=%d action=relocate image-base=") + hexily(image_base));
        return;
    }
}