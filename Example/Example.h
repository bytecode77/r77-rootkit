#define CUSTOM_ENTRY
#include "r77mindef.h"

DWORD WindowWidth;
DWORD WindowHeight;
BOOL ShowWarningIcon;
WCHAR Title[500];
WCHAR Text[1000];

HWND Window;
HWND CpuUsageComboBox;
HWND HelpButton;
HWND CloseButton;
HFONT TextFont;
HFONT TitleFont;
HBRUSH WhiteBrush;
HBRUSH LightGrayBrush;
HBITMAP LogoImage;
HBITMAP HelpImage;
HBITMAP WarningImage;

LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

HBITMAP GetImageResource(DWORD resourceID, LPCSTR type);
VOID DrawBitmapAlpha(HDC destination, HBITMAP image, DWORD x, DWORD y);