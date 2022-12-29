#include "log.h"

/* Singleton */
Log* Log::instance = nullptr;

Log* Log::getInstance() {
	if (instance == nullptr) {
		instance = new Log();
	}

	return instance;
}

Log::Log(void) {
	logfile = fopen(LOG_FILENAME, "a");
}

void Log::closeLogfile() {
	fflush(logfile);
	fclose(logfile);
}

FILE* Log::getLogFile() {
	return logfile;
}