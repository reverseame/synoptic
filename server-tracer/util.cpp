#include "util.h"

#if __GNUC__
#include <sys/types.h>
#elif _WIN32 || _WIN64
#include "windows_include.h"
#endif

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

std::string getTid() {
    std::stringstream ss;
#if __GNUC__
    ss << gettid();
#elif _WIN32 || _WIN64
    ss << WINDOWS::GetCurrentThreadId();
#endif
    return ss.str();
}