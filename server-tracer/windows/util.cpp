#include "util.h"

std::string hexily(ADDRINT addr) {
    std::stringstream os;
    os << "0x" << std::hex << std::setw(8) << std::setfill('0') << addr;
    return os.str();
}