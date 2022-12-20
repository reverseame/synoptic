#pragma once

#include <stdio.h>
#include <iostream>

/* Singleton */
class Logger {
	private:
		Logger(void);	// Constructor is private
		static Logger* instance;
		FILE* trace;
		std::string logFilename = "trace.log";

	public:
		static Logger* getInstance();	// Serves as constructor
		std::string getLogFileName();
		void close();
		void log(char* str, ...);
		void logInfo(char* str, ...);
		void logTaint(char* str, ...);
};