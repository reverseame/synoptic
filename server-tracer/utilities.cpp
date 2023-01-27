#include <time.h>
#include <stdio.h>

#include "utilities.h"

#if linux
#include <unistd.h>
#elif _WIN32 || _WIN64
#include "windows_include.h"
#endif

std::string getTimestamp() {
    /*
    * I should use clock_gettime or timespec_get instead of gettimeofday, but
    * it is returning me errno 95 every time. So, I stayed with the obsolete gettimeofday
    */
    char buffer[27];
    char timebuffer[20];
    struct timeval tv;

    gettimeofday(&tv, NULL);

    strftime(timebuffer, sizeof(timebuffer), "%F %T", localtime(&tv.tv_sec));
    snprintf(buffer, sizeof(buffer), "%s.%06ld", timebuffer, tv.tv_usec);

    return std::string(buffer);
}

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
std::string getParentProcessId() {
    std::stringstream ss;
#if linux
    ss << getppid();
#elif _WIN32 || _WIN64
    /* Such a convenient way to obtain your ppid */
    HANDLE hSnapshot;
    PROCESSENTRY32 pe32;
    DWORD ppid = 0;
    DWORD pid = GetCurrentProcessId();

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        ZeroMemory(&pe32, sizeof(pe32));
        pe32.dwSize = sizeof(pe32);
        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (pe32.th32ProcessID == pid) {
                    ss << pe32.th32ParentProcessID;
                    break;
                }
            } while(Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
#endif
    return ss.str();
}

std::string getProcessId() {
    std::stringstream ss;
#if linux
    ss << getpid();
#elif _WIN32 || _WIN64
    ss << WINDOWS::GetCurrentProcessId();
#endif
    return ss.str();
}

std::string getThreadId() {
    std::stringstream ss;
#if linux
    ss << gettid();
#elif _WIN32 || _WIN64
    ss << WINDOWS::GetCurrentThreadId();
#endif
    return ss.str();
}

std::string getFilePath(std::string path, std::string filename) {
    std::stringstream ss;
    ss << path;
#if linux
    ss << "/";
#elif _WIN32 || _WIN64
    ss << "\\";
#endif
    ss << filename;
    return ss.str();
}