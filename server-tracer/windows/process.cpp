#include "process.h"
#include "windows.h"

int getCurrentThreadId() {
	 return GetCurrentThreadId();
}