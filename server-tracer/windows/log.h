#pragma once

#include <iostream>

#include <fstream>

/* Singleton */
class Logger {
	private:
		Logger(void);
		static Logger* instance;
		std::fstream logFile;
		std::string logFilename = "trace.log";

	public:
		static Logger* getInstance();
		std::string getLogFileName();
		void close();
		void log(std::string str);
		void logInfo(std::string str);
		void logTaint(std::string str);
};