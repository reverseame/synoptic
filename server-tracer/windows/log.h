#pragma once

#include <iostream>

#define LOG_RAW(fmt, ...) fprintf(Log::getInstance()->getLogFile(), fmt, __VA_ARGS__)
#define LOG_INFO(fmt, ...) fprintf(Log::getInstance()->getLogFile(), "level=info "fmt"", __VA_ARGS__)
#define LOG_TAINT(fmt, ...) fprintf(Log::getInstance()->getLogFile(), "level=taint "fmt"", __VA_ARGS__)
#define CLOSELOG() Log::getInstance()->closeLogfile()

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