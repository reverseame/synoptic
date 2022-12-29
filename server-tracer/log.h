#pragma once

#include <iostream>

#include "util.h"

#define LOG_RAW(fmt, ...) do { fprintf(Log::getInstance()->getLogFile(), fmt, __VA_ARGS__); } while(0)
#define LOG_INFO(fmt, ...) do { fprintf(Log::getInstance()->getLogFile(), "level=info thread=%s "fmt"", getTid().c_str(), __VA_ARGS__); } while(0)
#define LOG_TAINT(fmt, ...) do { fprintf(Log::getInstance()->getLogFile(), "level=taint thread=%s "fmt"", getTid().c_str(), __VA_ARGS__); } while(0)
#define CLOSELOG() do { Log::getInstance()->closeLogfile(); } while(0)

#define LOG_FILENAME "trace.log"

/* Singleton */
class Log {
private:
	Log();						// Constructor is private
	static Log* instance;
	FILE* logfile;

public:
	static Log* getInstance();	// Serves as constructor
	void closeLogfile();
	FILE* getLogFile();
};