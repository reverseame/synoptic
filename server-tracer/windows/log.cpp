#include "log.h"

#include<string>

/* Singleton */
Logger* Logger::instance = nullptr;

Logger* Logger::getInstance() {
	if (instance == nullptr) {
		instance = new Logger();
	}

	return instance;
}

Logger::Logger(void) {
	logFile.open(Logger::logFilename.c_str(), std::fstream::out | std::fstream::app);
}

void Logger::close() {
	logFile.close();
}

std::string Logger::getLogFileName() {
	return logFilename;
}

void Logger::log(std::string str) {
	logFile << str << std::endl;
}

void Logger::logInfo(std::string str) {
	logFile << "level=info " << str << std::endl;
}

void Logger::logTaint(std::string str) {
	logFile << "level=taint " << str << std::endl;
}