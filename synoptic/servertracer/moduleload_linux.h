#pragma once

#include "pin.H"

#include <set>

void replaceSignatures(bool KnobDebug, IMG img, std::set<ADDRINT> &taintedAddrs, std::map<ADDRINT, std::array<bool, REG_LAST>> &taintedRegs, std::set<ADDRINT> &visitedAddrs, bool &thresholdTriggered, int &IOCounter, ADDRINT &insFallthrough);