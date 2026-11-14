#include <cstdarg>
#include <vector>

#include "log.h"

/* Singleton */
Log* Log::instance = nullptr;

Log* Log::getInstance() {
	if (instance == nullptr) {
		instance = new Log();
	}

	return instance;
}

Log::Log(void) : logfile(nullptr), logfilename(nullptr), owner(INVALID_THREADID) {
	PIN_InitLock(&lock);
}

void Log::openLogFile(const char *filename) {
	logfilename = filename;
	logfile = fopen(logfilename, "w");
}

void Log::closeLogfile() {
	fflush(logfile);
	fclose(logfile);
}

void Log::flushLogfile() {
	fflush(logfile);
}

FILE* Log::getLogFile() {
	return logfile;
}

const char* Log::getLogFilename() {
	return logfilename;
}

void Log::write(const char *fmt, ...) {
	char small[1024];
	va_list args;

	va_start(args, fmt);
	int len = vsnprintf(small, sizeof(small), fmt, args);
	va_end(args);
	if (len < 0) {
		return;
	}

	std::vector<char> large;
	const char *text = small;
	if ((size_t) len >= sizeof(small)) {
		large.resize(len + 1);
		va_start(args, fmt);
		vsnprintf(large.data(), large.size(), fmt, args);
		va_end(args);
		text = large.data();
	}

	THREADID tid = PIN_ThreadId();
	if (owner != tid) {
		PIN_GetLock(&lock, tid + 1);
		owner = tid;
	}

	fputs(text, logfile);

	/* A newline ends the record: let other threads write */
	if ((len > 0) && (text[len - 1] == '\n')) {
		owner = INVALID_THREADID;
		PIN_ReleaseLock(&lock);
	}
}
