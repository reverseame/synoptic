#pragma once

#include "pin.H"

#include <set>

void replaceSignatures(IMG img, std::set<ADDRINT> &taintedAdddrs, bool(&taintedRegs)[REG_LAST]);