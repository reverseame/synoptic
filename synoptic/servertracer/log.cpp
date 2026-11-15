#include <cstdarg>
#include <cstring>
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

Log::Log(void) : logfile(nullptr), logfilename(nullptr) {
	PIN_InitLock(&lock);
}

void Log::openLogFile(const char *filename) {
	logfilename = filename;
	logfile = fopen(logfilename, "w");
	/* e.g., a forked child that runs with fewer privileges than the directory requires */
	if (logfile == nullptr) {
		fprintf(stderr, "synoptic.servertracer\t: ERROR\t: unable to open log file %s\n", filename);
	}
}

void Log::closeLogfile() {
	if (logfile != nullptr) {
		fflush(logfile);
		fclose(logfile);
	}
}

void Log::flushLogfile() {
	if (logfile != nullptr) {
		fflush(logfile);
	}
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
	PIN_GetLock(&lock, tid + 1);

	std::vector<std::string> &records = pending[tid];
	/* Every record starts with its timestamp (see __LOG__) */
	if (records.empty() || (strncmp(text, "timestamp=", 10) == 0)) {
		records.push_back(std::string());
	}
	records.back() += text;

	/* Write completed records; an outer record still open stays buffered */
	while (!records.empty() && !records.back().empty() && (records.back().back() == '\n')) {
		if (logfile != nullptr) {
			fputs(records.back().c_str(), logfile);
		}
		records.pop_back();
	}

	PIN_ReleaseLock(&lock);
}
