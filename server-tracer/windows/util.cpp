#include "util.h"

std::string hexaddr(ADDRINT addr) {
    std::stringstream ss;
    ss << "0x" << std::hex;
#if _WIN64 || __x86_64__
    ss << std::setw(16);
#elif _WIN32 || __i386__
    ss << std::setw(8);
#endif
    ss << std::setfill('0') << addr;
    return ss.str();
}