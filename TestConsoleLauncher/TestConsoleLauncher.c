#define COBJMACROS
#include "TestConsoleLauncher.h"
#include "resource.h"
#include "r77win.h"
#include <Shlwapi.h>
#include <wincodec.h>

int main()
{
	// TestConsole is written in WPF .net 10.0 and deployed as a self-contained application.
	// The launcher simply decides which version to launch based on the OS bitness.

	// This executable shows a splash screen and starts the actual TestConsole.exe,
	// which will then terminate this process to hide the splash screen.

	WCHAR applicationDirectory[MAX_PATH + 1];
	GetModuleFileNameW(NULL, applicationDirectory, MAX_PATH);

	WCHAR testConsolePath[MAX_PATH + 1];
	LPCWSTR targetFileName = Is64BitOperatingSystem() ? L"TestConsole\\x64\\TestConsole.exe" : L"TestConsole\\x86\\TestConsole.exe";

	if (!PathRemoveFileSpecW(applicationDirectory) ||
		!PathCombineW(testConsolePath, applicationDirectory, targetFileName))
	{
		MessageBoxW(NULL, L"Error", L"Test Console", MB_OK | MB_ICONHAND);
		return 0;
	}

	if (!PathFileExistsW(testConsolePath))
	{
		WCHAR message[1000];
		StrCpyW(message, L"File '");
		StrCatW(message, targetFileName);
		StrCatW(message, L"' not found.\r\n\r\nIf you built the Solution, remember to run the publish profile of the TestConsole project.");

		MessageBoxW(NULL, message, L"Test Console", MB_OK | MB_ICONHAND);
		return 0;
	}

	SetProcessDPIAware();

	HRESULT result = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	if (SUCCEEDED(result) || result == RPC_E_CHANGED_MODE)
	{
		WNDCLASSEXW wc;
		i_memset(&wc, 0, sizeof(wc));
		wc.cbSize = sizeof(wc);
		wc.hInstance = GetModuleHandleW(NULL);
		wc.lpfnWndProc = WindowProc;
		wc.lpszClassName = L"TESTCONSOLE";
		wc.hCursor = LoadCursorW(NULL, IDC_ARROW);

		if (RegisterClassExW(&wc))
		{
			Window = CreateWindowExW(WS_EX_LAYERED | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE, wc.lpszClassName, NULL, WS_POPUP, 0, 0, 0, 0, NULL, NULL, wc.hInstance, NULL);
			if (Window)
			{
				SplashScreenImage = GetImageResource(IDB_SPLASHSCREEN, "PNG");

				SetWindowSplashScreen(Window, SplashScreenImage);
				ShowWindow(Window, SW_SHOWNOACTIVATE);

				StartTestConsole(testConsolePath);

				MSG message;
				while (GetMessageW(&message, NULL, 0, 0) > 0)
				{
					TranslateMessage(&message);
					DispatchMessageW(&message);
				}

			}

			UnregisterClassW(wc.lpszClassName, wc.hInstance);
		}

		if (SplashScreenImage) DeleteObject(SplashScreenImage);

		CoUninitialize();
	}

	return 0;
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch (msg)
	{
		case WM_CLOSE:
		{
			// Ignore closing of the splash screen.
			return 0;
		}
		case WM_SYSCOMMAND:
		{
			if ((wParam & 0xfff0) == SC_CLOSE)
			{
				return 0;
			}
			break;
		}
		case WM_DESTROY:
		{
			PostQuitMessage(0);
			return 0;
		}
	}

	return DefWindowProcW(hwnd, msg, wParam, lParam);
}

BOOL SetWindowSplashScreen(HWND window, HBITMAP bitmap)
{
	BOOL result = FALSE;

	BITMAP bitmapInformation;
	i_memset(&bitmapInformation, 0, sizeof(bitmapInformation));

	if (GetObjectW(bitmap, sizeof(bitmapInformation), &bitmapInformation))
	{
		MONITORINFO monitorInformation;
		i_memset(&monitorInformation, 0, sizeof(monitorInformation));
		monitorInformation.cbSize = sizeof(monitorInformation);

		if (GetMonitorInfoW(MonitorFromWindow(window, MONITOR_DEFAULTTOPRIMARY), &monitorInformation))
		{
			SIZE windowSize;
			windowSize.cx = bitmapInformation.bmWidth;
			windowSize.cy = bitmapInformation.bmHeight;

			POINT windowPosition;
			windowPosition.x = monitorInformation.rcWork.left + (monitorInformation.rcWork.right - monitorInformation.rcWork.left - windowSize.cx) / 2;
			windowPosition.y = monitorInformation.rcWork.top + (monitorInformation.rcWork.bottom - monitorInformation.rcWork.top - windowSize.cy) / 2;

			POINT sourcePosition;
			sourcePosition.x = 0;
			sourcePosition.y = 0;

			BLENDFUNCTION blendFunction;
			blendFunction.BlendOp = AC_SRC_OVER;
			blendFunction.BlendFlags = 0;
			blendFunction.SourceConstantAlpha = 255;
			blendFunction.AlphaFormat = AC_SRC_ALPHA;

			HDC screenDc = GetDC(NULL);
			if (screenDc)
			{
				HDC bitmapDc = CreateCompatibleDC(screenDc);
				if (bitmapDc)
				{
					HGDIOBJ oldImage = SelectObject(bitmapDc, bitmap);
					UpdateLayeredWindow(window, screenDc, &windowPosition, &windowSize, bitmapDc, &sourcePosition, 0, &blendFunction, ULW_ALPHA);
					result = TRUE;

					SelectObject(bitmapDc, oldImage);
					DeleteDC(bitmapDc);
				}

				ReleaseDC(NULL, screenDc);
			}
		}
	}

	return result;
}
HBITMAP GetImageResource(DWORD resourceID, LPCSTR type)
{
	LPBYTE resourceData;
	DWORD resourceSize;

	if (GetResource(resourceID, type, &resourceData, &resourceSize))
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
				result = IWICStream_InitializeFromMemory(stream, resourceData, resourceSize);
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

	return NULL;
}
VOID StartTestConsole(LPCWSTR path)
{
	STARTUPINFOW startupInfo;
	PROCESS_INFORMATION processInformation;
	i_memset(&startupInfo, 0, sizeof(STARTUPINFOW));
	i_memset(&processInformation, 0, sizeof(PROCESS_INFORMATION));
	startupInfo.cb = sizeof(startupInfo);

	CreateProcessW(path, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, &processInformation);
	CloseHandle(processInformation.hThread);
	CloseHandle(processInformation.hProcess);
}