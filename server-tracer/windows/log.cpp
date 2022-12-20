#include "log.h"

/* Singleton */
Logger* Logger::instance = nullptr;

Logger* Logger::getInstance() {
	if (instance == nullptr) {
		instance = new Logger();
	}

	return instance;
}

Logger::Logger(void) {
	trace = fopen(logFilename.c_str(), "a");
}

void Logger::close() {
	fclose(trace);
}

std::string Logger::getLogFileName() {
	return logFilename;
}

void Logger::log(char* str, ...) {
	va_list args;
	va_start(args, str);
	vfprintf(trace, str, args);
	va_end(args);
}

void Logger::logInfo(char* str, ...) {
	fprintf(trace, "level=info ");
	log(str);
}

void Logger::logTaint(char* str, ...) {
	fprintf(trace, "level=taint ");
	log(str);
}