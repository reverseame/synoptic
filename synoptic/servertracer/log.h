#pragma once

#include <iostream>

#include "pin.H"
#include "utilities.h"

#define OPEN_LOG(filename) do { Log::getInstance()->openLogFile(filename); } while(0)
#define CLOSE_LOG() do { Log::getInstance()->closeLogfile(); } while(0)
#define FLUSH_LOG() do { Log::getInstance()->flushLogfile(); } while(0)

#if linux
#define __LOG__(fmt, loglevel, ...) do { Log::getInstance()->write("timestamp=\"%s\" level=%s pid=%s tid=%s ppid=%s " fmt, getTimestamp().c_str(), loglevel, getProcessId().c_str(), getThreadId().c_str(), getParentProcessId().c_str() __VA_OPT__(,) __VA_ARGS__); } while(0)
#define LOG_RAW(fmt, ...) do { Log::getInstance()->write(fmt __VA_OPT__(,) __VA_ARGS__); } while(0)
#define LOG_INFO(fmt, ...) do { __LOG__(fmt, "info" __VA_OPT__(,) __VA_ARGS__); } while(0)
#define LOG_TAINT(fmt, ...) do { __LOG__(fmt, "taint" __VA_OPT__(,) __VA_ARGS__); } while(0)
#define __PRINT__(fmt, loglevel, ...) do { fprintf(stderr, "synoptic.servertracer\t: %s\t: %s\t: " fmt, loglevel, getProcessId().c_str() __VA_OPT__(,) __VA_ARGS__); } while(0)
#define PRINT_DEBUG(fmt, ...) do { __PRINT__(fmt, "DEBUG" __VA_OPT__(,) __VA_ARGS__); } while(0)
#define PRINT_WARNING(fmt, ...) do { __PRINT__(fmt, "WARNING" __VA_OPT__(,) __VA_ARGS__); } while(0)
#define PRINT_ERROR(fmt, ...)  do { __PRINT__(fmt, "ERROR" __VA_OPT__(,) __VA_ARGS__); } while(0)
#elif _WIN32 || _WIN64
#define __LOG__(fmt, loglevel, ...) do { Log::getInstance()->write("timestamp=\"%s\" level=%s pid=%s tid=%s ppid=%s " fmt, getFormattedTime().c_str(), loglevel, getProcessId().c_str(), getThreadId().c_str(), getParentProcessId().c_str(), __VA_ARGS__); } while(0)
#define LOG_RAW(fmt, ...) do { Log::getInstance()->write(fmt, __VA_ARGS__); } while(0)
#define LOG_INFO(fmt, ...) do { __LOG__(fmt, "info", __VA_ARGS__); } while(0)
#define LOG_TAINT(fmt, ...) do { __LOG__(fmt, "taint", __VA_ARGS__); } while(0)
#define __PRINT__(fmt, loglevel, ...) do { fprintf(stderr, "synoptic.servertracer\t: %s\t: %s\t:" fmt, loglevel, getProcessId().c_str(), __VA_ARGS__); } while(0)
#define PRINT_DEBUG(fmt, ...) do { __PRINT__(fmt, "DEBUG", __VA_ARGS__); } while(0)
#define PRINT_WARNING(fmt, ...) do { __PRINT__(fmt, "WARNING", __VA_ARGS__); } while(0)
#define PRINT_ERROR(fmt, ...)  do { __PRINT__(fmt, "ERROR", __VA_ARGS__); } while(0)
#endif

/*
 * Singleton
 *
 * A record is written with several calls (LOG_INFO/LOG_TAINT followed by LOG_RAW
 * pieces) and ends with a newline. write() keeps the lock from the first piece
 * of a record until its newline, so records from different threads do not
 * interleave.
 */
class Log {
private:
    Log();                      // Constructor is private
    static Log *instance;
    FILE *logfile;
    const char *logfilename;
    PIN_LOCK lock;
    THREADID owner;

public:
	static Log* getInstance();  // Get instance through function instead of constructor
    void openLogFile(const char *filename);
	void closeLogfile();
    void flushLogfile();
	FILE* getLogFile();
    const char* getLogFilename();
    void write(const char *fmt, ...);
};