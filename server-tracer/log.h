#pragma once

#include <iostream>

#include "utilities.h"

#define OPEN_LOG(filename) do { Log::getInstance()->openLogFile(filename); } while(0)
#define CLOSE_LOG() do { Log::getInstance()->closeLogfile(); } while(0)

#if linux
#define LOG_RAW(fmt, ...) do { fprintf(Log::getInstance()->getLogFile(), fmt __VA_OPT__(,) __VA_ARGS__); fflush(Log::getInstance()->getLogFile()); } while(0)
#define LOG_INFO(fmt, ...) do { fprintf(Log::getInstance()->getLogFile(), "level=info process=%s thread=%s " fmt, getProcessId().c_str(), getThreadId().c_str() __VA_OPT__(,) __VA_ARGS__); fflush(Log::getInstance()->getLogFile()); } while(0)
#define LOG_TAINT(fmt, ...) do { fprintf(Log::getInstance()->getLogFile(), "level=taint process=%s thread=%s " fmt, getProcessId().c_str(), getThreadId().c_str() __VA_OPT__(,) __VA_ARGS__); fflush(Log::getInstance()->getLogFile()); } while(0)
#define PRINT_DEBUG(fmt, ...) do { fprintf(stderr, "[*] server-tracer\t: DEBUG\t\t: " fmt __VA_OPT__(,) __VA_ARGS__) ;} while(0)
#define PRINT_WARNING(fmt, ...) do { fprintf(stderr, "[*] server-tracer\t: WARNING\t: " fmt __VA_OPT__(,) __VA_ARGS__) ;} while(0)
#define PRINT_ERROR(fmt, ...) do { fprintf(stderr, "[*] server-tracer\t: ERROR\t\t: " fmt __VA_OPT__(,) __VA_ARGS__) ;} while(0)
#elif _WIN32 || _WIN64
#define LOG_RAW(fmt, ...) do { fprintf(Log::getInstance()->getLogFile(), fmt, __VA_ARGS__); fflush(Log::getInstance()->getLogFile()); } while(0)
#define LOG_INFO(fmt, ...) do { fprintf(Log::getInstance()->getLogFile(), "level=info process=%s thread=%s " fmt, getProcessId().c_str(), getThreadId().c_str(), __VA_ARGS__); fflush(Log::getInstance()->getLogFile()); } while(0)
#define LOG_TAINT(fmt, ...) do { fprintf(Log::getInstance()->getLogFile(), "level=taint process=%s thread=%s " fmt, getProcessId().c_str(), getThreadId().c_str(), __VA_ARGS__); fflush(Log::getInstance()->getLogFile()); } while(0)
#define PRINT_DEBUG(fmt, ...) do { fprintf(stderr, "[*] server-tracer\t: DEBUG\t\t: " fmt, __VA_ARGS__) ;} while(0)
#define PRINT_WARNING(fmt, ...) do { fprintf(stderr, "[*] server-tracer\t: WARNING\t: " fmt, __VA_ARGS__) ;} while(0)
#define PRINT_ERROR(fmt, ...) do { fprintf(stderr, "[*] server-tracer\t: ERROR\t\t: " fmt, __VA_ARGS__) ;} while(0)
#endif

/* Singleton */
class Log {
private:
    Log();                      // Constructor is private
    static Log *instance;
    FILE *logfile;
    const char *logfilename;

public:
	static Log* getInstance();  // Get instance through function instead of constructor
    void openLogFile(const char *filename);
	void closeLogfile();
	FILE* getLogFile();
    const char* getLogFilename();
};