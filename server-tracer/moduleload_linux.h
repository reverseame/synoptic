#pragma once

#include "pin.H"

#include <set>

void replaceSignatures(bool KnobDebug, IMG img, std::set<ADDRINT> &taintedAdddrs, bool(&taintedRegs)[REG_LAST], std::set<ADDRINT> &visitedAddrs);