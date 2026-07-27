#define CUSTOM_ENTRY
#include "r77mindef.h"

HWND Window;
HBITMAP SplashScreenImage;

LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

BOOL SetWindowSplashScreen(HWND window, HBITMAP bitmap);
HBITMAP GetImageResource(DWORD resourceID, LPCSTR type);
VOID StartTestConsole(LPCWSTR path);