
; SHELL32.DLL structures and constants

struct NOTIFYICONDATA
  cbSize	   dd ?
  hWnd		   dd ?
  uID		   dd ?
  uFlags	   dd ?
  uCallbackMessage dd ?
  hIcon 	   dd ?
  szTip 	   TCHAR 64 dup (?)
ends

struct NOTIFYICONDATAA
  cbSize	   dd ?
  hWnd		   dd ?
  uID		   dd ?
  uFlags	   dd ?
  uCallbackMessage dd ?
  hIcon 	   dd ?
  szTip 	   db 64 dup (?)
ends

struct NOTIFYICONDATAW
  cbSize	   dd ?
  hWnd		   dd ?
  uID		   dd ?
  uFlags	   dd ?
  uCallbackMessage dd ?
  hIcon 	   dd ?
  szTip 	   du 64 dup (?)
ends

struct BROWSEINFO
  hwndOwner	 dd ?
  pidlRoot	 dd ?
  pszDisplayName dd ?
  lpszTitle	 dd ?
  ulFlags	 dd ?
  lpfn		 dd ?
  lParam	 dd ?
  iImage	 dd ?
ends

; Taskbar icon messages

NIM_ADD        = 0
NIM_MODIFY     = 1
NIM_DELETE     = 2
NIM_SETFOCUS   = 3
NIM_SETVERSION = 4

; Taskbar icon flags

NIF_MESSAGE    = 01h
NIF_ICON       = 02h
NIF_TIP        = 04h
NIF_STATE      = 08h
NIF_INFO       = 10h
NIF_GUID       = 20h

; Constant Special Item ID List

CSIDL_DESKTOP		      = 0x0000
CSIDL_INTERNET		      = 0x0001
CSIDL_PROGRAMS		      = 0x0002
CSIDL_CONTROLS		      = 0x0003
CSIDL_PRINTERS		      = 0x0004
CSIDL_PERSONAL		      = 0x0005
CSIDL_FAVORITES 	      = 0x0006
CSIDL_STARTUP		      = 0x0007
CSIDL_RECENT		      = 0x0008
CSIDL_SENDTO		      = 0x0009
CSIDL_BITBUCKET 	      = 0x000A
CSIDL_STARTMENU 	      = 0x000B
CSIDL_MYDOCUMENTS	      = 0x000C
CSIDL_MYMUSIC		      = 0x000D
CSIDL_MYVIDEO		      = 0x000E
CSIDL_DESKTOPDIRECTORY	      = 0x0010
CSIDL_DRIVES		      = 0x0011
CSIDL_NETWORK		      = 0x0012
CSIDL_NETHOOD		      = 0x0013
CSIDL_FONTS		      = 0x0014
CSIDL_TEMPLATES 	      = 0x0015
CSIDL_COMMON_STARTMENU	      = 0x0016
CSIDL_COMMON_PROGRAMS	      = 0x0017
CSIDL_COMMON_STARTUP	      = 0x0018
CSIDL_COMMON_DESKTOPDIRECTORY = 0x0019
CSIDL_APPDATA		      = 0x001A
CSIDL_PRINTHOOD 	      = 0x001B
CSIDL_LOCAL_APPDATA	      = 0x001C
CSIDL_ALTSTARTUP	      = 0x001D
CSIDL_COMMON_ALTSTARTUP       = 0x001E
CSIDL_COMMON_FAVORITES	      = 0x001F
CSIDL_INTERNET_CACHE	      = 0x0020
CSIDL_COOKIES		      = 0x0021
CSIDL_HISTORY		      = 0x0022
CSIDL_COMMON_APPDATA	      = 0x0023
CSIDL_WINDOWS		      = 0x0024
CSIDL_SYSTEM		      = 0x0025
CSIDL_PROGRAM_FILES	      = 0x0026
CSIDL_MYPICTURES	      = 0x0027
CSIDL_PROFILE		      = 0x0028
CSIDL_SYSTEMX86 	      = 0x0029
CSIDL_PROGRAM_FILESX86	      = 0x002A
CSIDL_PROGRAM_FILES_COMMON    = 0x002B
CSIDL_PROGRAM_FILES_COMMONX86 = 0x002C
CSIDL_COMMON_TEMPLATES	      = 0x002D
CSIDL_COMMON_DOCUMENTS	      = 0x002E
CSIDL_COMMON_ADMINTOOLS       = 0x002F
CSIDL_ADMINTOOLS	      = 0x0030
CSIDL_CONNECTIONS	      = 0x0031
CSIDL_COMMON_MUSIC	      = 0x0035
CSIDL_COMMON_PICTURES	      = 0x0036
CSIDL_COMMON_VIDEO	      = 0x0037
CSIDL_RESOURCES 	      = 0x0038
CSIDL_RESOURCES_LOCALIZED     = 0x0039
CSIDL_COMMON_OEM_LINKS	      = 0x003A
CSIDL_CDBURN_AREA	      = 0x003B
CSIDL_COMPUTERSNEARME	      = 0x003D
CSIDL_PROFILES		      = 0x003E
CSIDL_FOLDER_MASK	      = 0x00FF
CSIDL_FLAG_PER_USER_INIT      = 0x0800
CSIDL_FLAG_NO_ALIAS	      = 0x1000
CSIDL_FLAG_DONT_VERIFY	      = 0x4000
CSIDL_FLAG_CREATE	      = 0x8000
CSIDL_FLAG_MASK 	      = 0xFF00
				      