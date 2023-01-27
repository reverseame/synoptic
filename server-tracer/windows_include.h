#pragma once

/* Change path to your Windows SDK */
#define _WINDOWS_H_PATH_ C:/Program Files (x86)/Windows Kits/10/Include/10.0.22000.0/um

namespace WINDOWS {
#include <Windows.h>
#include <winsock2.h>
#include <tlhelp32.h>
}