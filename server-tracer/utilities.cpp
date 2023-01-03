#include "utilities.h"

#if linux
#include <sys/syscall.h>
#elif _WIN32 || _WIN64
#include "windows_include.h"
#endif

std::string hexaddr(ADDRINT addr) {
    std::stringstream ss;
    ss << "0x" << std::hex;
#if __x86_64__ || _WIN64
    ss << std::setw(16);
#elif __i386__ || _WIN32
    ss << std::setw(8);
#endif
    ss << std::setfill('0') << addr;
    return ss.str();
}


std::string getThreadId() {
    std::stringstream ss;
#if linux
    ss << syscall(SYS_gettid);
#elif _WIN32 || _WIN64
    ss << WINDOWS::GetCurrentThreadId();
#endif
    return ss.str();
}
