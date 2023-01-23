#include "log.h"

/* Singleton */
Log* Log::instance = nullptr;

Log* Log::getInstance() {
	if (instance == nullptr) {
		instance = new Log();
	}

	return instance;
}

/* Empty constructor */
Log::Log(void) {}

void Log::openLogFile(const char *filename) {
	logfilename = filename;
	logfile = fopen(logfilename, "a");
}

void Log::closeLogfile() {
	fflush(logfile);
	fclose(logfile);
}

FILE* Log::getLogFile() {
	return logfile;
}

const char* Log::getLogFilename() {
	return logfilename;
}