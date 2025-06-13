#pragma once

#include "pin.H"

std::string getTimestamp();
std::string hexaddr(ADDRINT addr);
std::string getParentProcessId();
std::string getProcessId();
std::string getThreadId();
std::string getFilePath(std::string path, std::string pid);