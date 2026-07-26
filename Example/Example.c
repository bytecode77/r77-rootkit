#define COBJMACROS
#include "Example.h"
#include "resource.h"
#include "CpuUsage.h"
#include "r77def.h"
#include "r77win.h"
#include <Shlwapi.h>
#include <CommCtrl.h>
#include <wincodec.h>

int main()
{
	WCHAR executablePath[MAX_PATH + 1];
	GetModuleFileNameW(NULL, executablePath, MAX_PATH);

	LPWSTR fileName = PathFindFileNameW(executablePath);

	WCHAR processId[100];
	Int32ToStrW(GetCurrentProcessId(), processId);

	StrCpyW(Title, fileName);
	StrCatW(Title, L" (PID: ");
	StrCatW(Title, processId);
	StrCatW(Title, L")");

	if (!StrCmpNIW(fileName, HIDE_PREFIX, HIDE_PREFIX_LENGTH))
	{
		WindowWidth = 460;
		WindowHeight = 200;
		ShowWarningIcon = FALSE;

		StrCpyW(Text, L"This executable's filename starts with \"");
		StrCatW(Text, HIDE_PREFIX);
		StrCatW(Text, L"\"\n\n");
		StrCatW(Text, L"  - A task manager that is injected with r77 will not display this process.\n");
		StrCatW(Text, L"  - File Explorer (or any other file browser) will not display this file.\n");
		StrCatW(Text, L"  - etc... (see documentation)");
	}
	else
	{
		WindowWidth = 400;
		WindowHeight = 150;
		ShowWarningIcon = TRUE;

		StrCpyW(Text, L"Rename this executable's file to start with \"");
		StrCatW(Text, HIDE_PREFIX);
		StrCatW(Text, L"\".\n");
		StrCatW(Text, L"It will be hidden by r77.");
	}

	HRESULT result = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	if (SUCCEEDED(result) || result == RPC_E_CHANGED_MODE)
	{
		TextFont = CreateFontW(16, 0, 0, 0, FW_DONTCARE, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_TT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
		TitleFont = CreateFontW(26, 0, 0, 0, FW_DONTCARE, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_TT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
		WhiteBrush = CreateSolidBrush(RGB(255, 255, 255));
		LightGrayBrush = CreateSolidBrush(RGB(240, 240, 240));
		LogoImage = GetImageResource(IDB_EXAMPLE32, "PNG");
		HelpImage = GetImageResource(IDB_HELP16, "PNG");
		WarningImage = GetImageResource(IDB_WARNING16, "PNG");

		WNDCLASSW wc;
		i_memset(&wc, 0, sizeof(wc));
		wc.hInstance = GetModuleHandleW(NULL);
		wc.lpszClassName = L"R77EXAMPLE";
		wc.lpfnWndProc = WindowProc;
		wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
		wc.hbrBackground = WhiteBrush;

		if (RegisterClassW(&wc))
		{
			RECT rect;
			SetRect(&rect, 0, 0, WindowWidth, WindowHeight);

			if (AdjustWindowRectEx(&rect, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, FALSE, WS_EX_DLGMODALFRAME))
			{
				Window = CreateWindowExW(WS_EX_DLGMODALFRAME, wc.lpszClassName, L"r77 Rootkit Example File", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, CW_USEDEFAULT, CW_USEDEFAULT, rect.right - rect.left, rect.bottom - rect.top, NULL, NULL, wc.hInstance, NULL);
				if (Window)
				{
					CpuUsageComboBox = CreateWindowW(WC_COMBOBOXW, NULL, WS_TABSTOP | WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST, 15, WindowHeight - 35, 120, 200, Window, NULL, wc.hInstance, NULL);
					SendMessageW(CpuUsageComboBox, WM_SETFONT, (WPARAM)TextFont, TRUE);
					SendMessageW(CpuUsageComboBox, CB_ADDSTRING, 0, (LPARAM)L"CPU Usage: 0%");
					SendMessageW(CpuUsageComboBox, CB_ADDSTRING, 0, (LPARAM)L"CPU Usage: 25%");
					SendMessageW(CpuUsageComboBox, CB_ADDSTRING, 0, (LPARAM)L"CPU Usage: 50%");
					SendMessageW(CpuUsageComboBox, CB_ADDSTRING, 0, (LPARAM)L"CPU Usage: 75%");
					SendMessageW(CpuUsageComboBox, CB_ADDSTRING, 0, (LPARAM)L"CPU Usage: 100%");
					SendMessageW(CpuUsageComboBox, CB_SETCURSEL, 0, 0);

					HelpButton = CreateWindowW(WC_BUTTONW, L"", WS_TABSTOP | WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 140, WindowHeight - 35, 23, 23, Window, NULL, wc.hInstance, NULL);

					CloseButton = CreateWindowW(WC_BUTTONW, L"Close", WS_TABSTOP | WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, WindowWidth - 90, WindowHeight - 35, 75, 23, Window, NULL, wc.hInstance, NULL);
					SendMessageW(CloseButton, WM_SETFONT, (WPARAM)TextFont, TRUE);

					InitializeCpuUsage();

					ShowWindow(Window, SW_SHOW);
					UpdateWindow(Window);

					MSG msg;
					BOOL messageResult;

					while ((messageResult = GetMessageW(&msg, NULL, 0, 0)) != 0)
					{
						if (messageResult == -1)
						{
							break;
						}

						if (!IsDialogMessageW(Window, &msg))
						{
							TranslateMessage(&msg);
							DispatchMessageW(&msg);
						}
					}

					UninitializeCpuUsage();
				}
			}

			UnregisterClassW(wc.lpszClassName, wc.hInstance);
		}

		if (TextFont) DeleteObject(TextFont);
		if (TitleFont) DeleteObject(TitleFont);
		if (WhiteBrush) DeleteObject(WhiteBrush);
		if (LightGrayBrush) DeleteObject(LightGrayBrush);
		if (LogoImage) DeleteObject(LogoImage);
		if (HelpImage) DeleteObject(HelpImage);
		if (WarningImage) DeleteObject(WarningImage);

		CoUninitialize();
	}

	return 0;
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch (msg)
	{
		case WM_PAINT:
		{
			PAINTSTRUCT ps;
			HDC hdc = BeginPaint(hwnd, &ps);
			SetBkMode(hdc, TRANSPARENT);

			DrawBitmapAlpha(hdc, LogoImage, 20, 20);

			HFONT oldFont = (HFONT)SelectObject(hdc, TitleFont);
			SetTextColor(hdc, RGB(0, 102, 204));
			TextOutW(hdc, 60, 20, Title, lstrlenW(Title));

			if (ShowWarningIcon)
			{
				DrawBitmapAlpha(hdc, WarningImage, 60, 60);
			}

			RECT rect;
			if (ShowWarningIcon)
			{
				SetRect(&rect, 85, 60, WindowWidth - 45, WindowHeight - 50);
			}
			else
			{
				SetRect(&rect, 60, 60, WindowWidth - 20, WindowHeight - 50);
			}

			SelectObject(hdc, TextFont);
			SetTextColor(hdc, RGB(0, 0, 0));
			DrawTextW(hdc, Text, -1, &rect, DT_LEFT | DT_TOP | DT_WORDBREAK);

			SetRect(&rect, 0, WindowHeight - 45, WindowWidth, WindowHeight);
			FillRect(hdc, &rect, LightGrayBrush);

			SelectObject(hdc, oldFont);
			EndPaint(hwnd, &ps);
			return 0;
		}
		case WM_DRAWITEM:
		{
			LPDRAWITEMSTRUCT drawItem = (LPDRAWITEMSTRUCT)lParam;
			if (drawItem && drawItem->hwndItem == HelpButton)
			{
				BITMAP bitmap;
				i_memset(&bitmap, 0, sizeof(bitmap));

				if (GetObjectW(HelpImage, sizeof(bitmap), &bitmap))
				{
					DrawBitmapAlpha(drawItem->hDC, HelpImage, drawItem->rcItem.left + (drawItem->rcItem.right - drawItem->rcItem.left - bitmap.bmWidth) / 2, drawItem->rcItem.top + (drawItem->rcItem.bottom - drawItem->rcItem.top - bitmap.bmHeight) / 2);
				}

				return TRUE;
			}
			break;
		}
		case WM_COMMAND:
		{
			if ((HWND)lParam == CloseButton && HIWORD(wParam) == BN_CLICKED)
			{
				DestroyWindow(hwnd);
			}
			else if ((HWND)lParam == HelpButton && HIWORD(wParam) == BN_CLICKED)
			{
				MessageBoxW(hwnd, L"CPU usage is hidden by r77. To see the effect, increase CPU usage of this process.\r\n\r\nThis process is running with idle priority to not interrupt other tasks.", L"Help", MB_OK | MB_ICONINFORMATION);
			}
			else if ((HWND)lParam == CpuUsageComboBox && HIWORD(wParam) == CBN_SELCHANGE)
			{
				switch ((DWORD)SendMessageW(CpuUsageComboBox, CB_GETCURSEL, 0, 0))
				{
					case 0: SetCpuUsage(0); break;
					case 1: SetCpuUsage(25); break;
					case 2: SetCpuUsage(50); break;
					case 3: SetCpuUsage(75); break;
					case 4: SetCpuUsage(100); break;
				}
			}

			return 0;
		}
		case WM_SETCURSOR:
		{
			if ((HWND)wParam == HelpButton)
			{
				SetCursor(LoadCursorW(NULL, IDC_HAND));
				return TRUE;
			}
			break;
		}
		case WM_DESTROY:
		{
			Window = NULL;
			PostQuitMessage(0);
			return 0;
		}
	}

	return DefWindowProcW(hwnd, msg, wParam, lParam);
}

HBITMAP GetImageResource(DWORD resourceID, LPCSTR type)
{
	LPBYTE resourceData;
	DWORD resourceSize;

	if (GetResource(resourceID, type, &resourceData, &resourceSize))
	{
		return CreateImage(resourceData, resourceSize);
	}

	return NULL;
}
HBITMAP CreateImage(LPCBYTE data, DWORD size)
{
	HBITMAP bitmap = NULL;

	IWICImagingFactory *factory;
	HRESULT result = CoCreateInstance(&CLSID_WICImagingFactory, NULL, CLSCTX_INPROC_SERVER, &IID_IWICImagingFactory, (LPVOID*)&factory);
	if (SUCCEEDED(result))
	{
		IWICStream *stream;
		result = IWICImagingFactory_CreateStream(factory, &stream);
		if (SUCCEEDED(result))
		{
			result = IWICStream_InitializeFromMemory(stream, (LPBYTE)data, size);
			if (SUCCEEDED(result))
			{
				IWICBitmapDecoder *decoder;
				result = IWICImagingFactory_CreateDecoderFromStream(factory, (IStream*)stream, NULL, WICDecodeMetadataCacheOnLoad, &decoder);
				if (SUCCEEDED(result))
				{
					IWICBitmapFrameDecode *frame;
					result = IWICBitmapDecoder_GetFrame(decoder, 0, &frame);
					if (SUCCEEDED(result))
					{
						IWICBitmapSource *convertedSource;
						result = WICConvertBitmapSource(&GUID_WICPixelFormat32bppPBGRA, (IWICBitmapSource *)frame, &convertedSource);
						if (SUCCEEDED(result))
						{
							UINT width;
							UINT height;
							result = IWICBitmapSource_GetSize(convertedSource, &width, &height);
							if (SUCCEEDED(result) && width > 0 && height > 0)
							{
								BITMAPINFO bitmapInfo;
								i_memset(&bitmapInfo, 0, sizeof(bitmapInfo));
								bitmapInfo.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
								bitmapInfo.bmiHeader.biWidth = (LONG)width;
								bitmapInfo.bmiHeader.biHeight = -(LONG)height;
								bitmapInfo.bmiHeader.biPlanes = 1;
								bitmapInfo.bmiHeader.biBitCount = 32;
								bitmapInfo.bmiHeader.biCompression = BI_RGB;

								LPVOID pixels;
								bitmap = CreateDIBSection(NULL, &bitmapInfo, DIB_RGB_COLORS, &pixels, NULL, 0);

								if (bitmap && pixels)
								{
									result = IWICBitmapSource_CopyPixels(convertedSource, NULL, width * 4, width * 4 * height, (LPBYTE)pixels);
									if (FAILED(result))
									{
										DeleteObject(bitmap);
										bitmap = NULL;
									}
								}
								else if (bitmap)
								{
									DeleteObject(bitmap);
									bitmap = NULL;
								}
							}

							IWICBitmapSource_Release(convertedSource);
						}

						IWICBitmapFrameDecode_Release(frame);
					}

					IWICBitmapDecoder_Release(decoder);
				}
			}

			IWICStream_Release(stream);
		}

		IWICImagingFactory_Release(factory);
	}

	return bitmap;
}
VOID DrawBitmapAlpha(HDC destination, HBITMAP image, DWORD x, DWORD y)
{
	if (destination && image)
	{
		BITMAP bitmap;
		i_memset(&bitmap, 0, sizeof(bitmap));

		if (GetObjectW(image, sizeof(bitmap), &bitmap))
		{
			HDC source = CreateCompatibleDC(destination);
			if (source)
			{
				HGDIOBJ oldImage = SelectObject(source, image);

				BLENDFUNCTION blend;
				blend.BlendOp = AC_SRC_OVER;
				blend.BlendFlags = 0;
				blend.SourceConstantAlpha = 255;
				blend.AlphaFormat = AC_SRC_ALPHA;

				AlphaBlend(destination, x, y, bitmap.bmWidth, bitmap.bmHeight, source, 0, 0, bitmap.bmWidth, bitmap.bmHeight, blend);
				SelectObject(source, oldImage);

				DeleteDC(source);
			}
		}
	}
}