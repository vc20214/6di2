#include <ntddk.h>
#include <ntimage.h>

// Suppress common warnings
#pragma warning(disable: 6320)  // EXCEPTION_EXECUTE_HANDLER
#pragma warning(disable: 6011)  // NULL pointer dereference  
#pragma warning(disable: 6322)  // Empty except block
#pragma warning(disable: 28159) // Use error logging instead of KeBugCheck
#pragma warning(disable: 28251) // Annotation mismatch
#pragma warning(disable: 28023) // Function class annotation

// Disable buffer security checks for kernel driver
#ifdef _MSC_VER
#pragma runtime_checks("", off)
#endif

// Security cookie implementation for kernel drivers
#ifdef _AMD64_
ULONG_PTR __security_cookie = 0x2B992DDFA232;

void __fastcall __security_check_cookie(ULONG_PTR cookie)
{
	if (cookie != __security_cookie)
		KeBugCheck(SECURITY_SYSTEM);
}
#endif

// Use common Windows pool tag to avoid detection
#define DRIVER_TAG 'eliF'  // Pretend to be File-related

UCHAR ObfuscatedTargetProcess[] = { 0x00 };

UCHAR Obfuscated??Service[] = {
	0x00
}; 

// Target process name (will be decrypted at runtime)
WCHAR g_TargetProcessName[32] = { 0 };
WCHAR g_??ServiceName[16] = { 0 };

// Debug output control - disabled in release
#ifdef DEBUG_BUILD
#define DBG_PRINT(x, ...) DbgPrint(x, __VA_ARGS__)
#else
#define DBG_PRINT(x, ...) 
#endif

// Missing status code
#ifndef STATUS_EXCEPTION_ENCOUNTERED
#define STATUS_EXCEPTION_ENCOUNTERED ((NTSTATUS)0x80000029L)
#endif

// System information class
#define SystemProcessInformation 5
#define SystemBigPoolInformation 0x42

// Memory constants
#ifndef MEM_COMMIT
#define MEM_COMMIT 0x1000
#endif
#ifndef MEM_RESERVE
#define MEM_RESERVE 0x2000
#endif
#ifndef MEM_RELEASE
#define MEM_RELEASE 0x8000
#endif
#ifndef PAGE_EXECUTE_READWRITE
#define PAGE_EXECUTE_READWRITE 0x40
#endif

// Windows structures that might be missing
#ifndef _PEB_LDR_DATA_DEFINED
#define _PEB_LDR_DATA_DEFINED

typedef struct _PEB_LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
	BOOLEAN ShutdownInProgress;
	HANDLE ShutdownThreadId;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union {
		LIST_ENTRY HashLinks;
		struct {
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	BOOLEAN BitField;
	HANDLE Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PVOID ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PVOID FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	PVOID CrossProcessFlags;
	PVOID UserSharedInfoPtr;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	PVOID ApiSetMap;
} PEB, * PPEB;

#endif

// KAPC_STATE structure
typedef struct _KAPC_STATE {
	LIST_ENTRY ApcListHead[2];
	struct _KPROCESS* Process;
	BOOLEAN KernelApcInProgress;
	BOOLEAN KernelApcPending;
	BOOLEAN UserApcPending;
} KAPC_STATE, * PKAPC_STATE;

// Windows API types
typedef PVOID HANDLE;
typedef ULONG DWORD;
typedef LONG BOOL;
typedef WCHAR* LPWSTR;
typedef CONST WCHAR* LPCWSTR;
typedef ULONG* LPDWORD;

// Shellcode structures with obfuscated names
typedef struct _HOOK_DATA {
	PVOID OrigFunc;
	PVOID HookFunc;
	WCHAR TargetName[256];
} HOOK_DATA, * PHOOK_DATA;

typedef struct _SC_DATA {
	PVOID CreateFileWOrig;
	PVOID CreateFileAOrig;
	PVOID DeviceIoControlOrig;
	PVOID NtDeviceIoControlFileOrig;
	PVOID LoadLibraryWOrig;
	PVOID LoadLibraryAOrig;
	WCHAR DeviceName[64];
	WCHAR DllName[64];
} SC_DATA, * PSC_DATA;

// IAT Hook structure with obfuscated name
typedef struct _HOOK_ENTRY {
	LIST_ENTRY ListEntry;
	PVOID OrigAddr;
	PVOID HookAddr;
	PVOID ScAddr;
	SIZE_T ScSize;
	CHAR FuncName[256];
	CHAR ModName[256];
} HOOK_ENTRY, * PHOOK_ENTRY;

// Process monitoring structure with obfuscated name
typedef struct _PROC_INFO {
	LIST_ENTRY ListEntry;
	HANDLE ProcId;
	PEPROCESS Proc;
	UNICODE_STRING ProcName;
	LIST_ENTRY Hooks;
	BOOLEAN Hooked;
	PVOID ScBase;
	SIZE_T ScSize;
	PSC_DATA ScData;
} PROC_INFO, * PPROC_INFO;

// External function declarations
NTKERNELAPI
NTSTATUS
PsLookupProcessByProcessId(
	IN HANDLE ProcessId,
	OUT PEPROCESS* Process
);

NTKERNELAPI
PUCHAR
PsGetProcessImageFileName(
	IN PEPROCESS Process
);

NTKERNELAPI
PPEB
PsGetProcessPeb(
	IN PEPROCESS Process
);

NTKERNELAPI
NTSTATUS
PsSetCreateProcessNotifyRoutine(
	IN PCREATE_PROCESS_NOTIFY_ROUTINE NotifyRoutine,
	IN BOOLEAN Remove
);

NTKERNELAPI
NTSTATUS
PsRemoveLoadImageNotifyRoutine(
	IN PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine
);

NTKERNELAPI
NTSTATUS
PsSetLoadImageNotifyRoutine(
	IN PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine
);

NTKERNELAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
	IN ULONG SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);

NTKERNELAPI
NTSTATUS
MmCopyVirtualMemory(
	PEPROCESS SourceProcess,
	PVOID SourceAddress,
	PEPROCESS TargetProcess,
	PVOID TargetAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T ReturnSize
);

NTKERNELAPI
NTSTATUS
ZwAllocateVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN ULONG_PTR ZeroBits,
	IN OUT PSIZE_T RegionSize,
	IN ULONG AllocationType,
	IN ULONG Protect
);

NTKERNELAPI
NTSTATUS
ZwFreeVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG FreeType
);

NTKERNELAPI
VOID
KeStackAttachProcess(
	IN PEPROCESS Process,
	OUT PKAPC_STATE ApcState
);

NTKERNELAPI
VOID
KeUnstackDetachProcess(
	IN PKAPC_STATE ApcState
);

NTKERNELAPI
NTSTATUS
ObOpenObjectByPointer(
	IN PVOID Object,
	IN ULONG HandleAttributes,
	IN PACCESS_STATE PassedAccessState OPTIONAL,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_TYPE ObjectType OPTIONAL,
	IN KPROCESSOR_MODE AccessMode,
	OUT PHANDLE Handle
);

// Add PsProcessType declaration
extern POBJECT_TYPE* PsProcessType;

// Globals with less suspicious names
BOOLEAN g_Active = FALSE;
BOOLEAN g_GameActive = FALSE;
BOOLEAN g_TargetNeutralized = FALSE;
LIST_ENTRY g_ProcList;
KSPIN_LOCK g_ProcLock;
PDEVICE_OBJECT g_Device = NULL;
PCREATE_PROCESS_NOTIFY_ROUTINE g_ProcCallback = NULL;
PLOAD_IMAGE_NOTIFY_ROUTINE g_ImgCallback = NULL;

// Random delay to avoid timing patterns
VOID RandomDelay()
{
	LARGE_INTEGER Delay;
	ULONG Random = (ULONG)KeQueryPerformanceCounter(NULL).QuadPart;
	Delay.QuadPart = -10000LL - (Random % 10000); // 1-2ms random delay
	KeDelayExecutionThread(KernelMode, FALSE, &Delay);
}

// Simple XOR decryption
VOID DecryptString(PUCHAR Encrypted, SIZE_T Length, UCHAR Key, PWCHAR Output)
{
	for (SIZE_T i = 0; i < Length; i++) {
		Output[i] = (WCHAR)(Encrypted[i] ^ Key);
	}
	Output[Length] = 0;
}

// x64 Shellcode templates with polymorphic instructions
UCHAR CreateFileHookShellcode[] = {
	// Random NOP sleds with different encodings
	0x90, 0x66, 0x90,                               // nop; nop with prefix
	// Save registers with alternative encoding
	0x50,                                           // push rax
	0x51,                                           // push rcx  
	0x52,                                           // push rdx
	0x41, 0x50,                                     // push r8
	0x41, 0x51,                                     // push r9
	0x48, 0x81, 0xEC, 0x28, 0x00, 0x00, 0x00,     // sub rsp, 0x28 (different encoding)

	// Check filename with indirect addressing
	0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, [ShellcodeData]
	0x48, 0x8D, 0x50, 0x50,                        // lea rdx, [rax+0x50]
	0xE8, 0x00, 0x00, 0x00, 0x00,                 // call CompareString
	0x48, 0x85, 0xC0,                              // test rax, rax
	0x74, 0x18,                                     // jz BlockAccess

	// Restore and call original with different instructions
	0x48, 0x81, 0xC4, 0x28, 0x00, 0x00, 0x00,     // add rsp, 0x28
	0x41, 0x59,                                     // pop r9
	0x41, 0x58,                                     // pop r8
	0x5A,                                           // pop rdx
	0x59,                                           // pop rcx
	0x58,                                           // pop rax
	0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, [OriginalFunction]
	0xFF, 0xE0,                                     // jmp rax

	// BlockAccess:
	0x48, 0x81, 0xC4, 0x28, 0x00, 0x00, 0x00,     // add rsp, 0x28
	0x41, 0x59,                                     // pop r9
	0x41, 0x58,                                     // pop r8
	0x5A,                                           // pop rdx
	0x59,                                           // pop rcx
	0x58,                                           // pop rax
	0x48, 0xC7, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF,     // mov rax, -1
	0xC3,                                           // ret
	0xCC, 0xCC                                      // int3 padding
};

UCHAR DeviceIoControlHookShellcode[] = {
	// Polymorphic NOP sled
	0x4D, 0x31, 0xC0,                              // xor r8, r8 (zeroing as NOP)
	0x4D, 0x85, 0xC0,                              // test r8, r8

	// Check device handle
	0x48, 0x83, 0xF9, 0x00,                        // cmp rcx, 0
	0x74, 0x23,                                     // je CallOriginal

	// Check IoControlCode with different comparison
	0x81, 0xFA, 0x00, 0x00, 0x22, 0x00,           // cmp edx, 0x220000
	0x72, 0x19,                                     // jb CallOriginal
	0x81, 0xFA, 0xFF, 0xFF, 0x22, 0x00,           // cmp edx, 0x22FFFF
	0x77, 0x11,                                     // ja CallOriginal

	// Block with alternative instructions
	0x31, 0xC0,                                     // xor eax, eax
	0x4D, 0x85, 0xC9,                              // test r9, r9
	0x74, 0x07,                                     // jz Return
	0x41, 0xC7, 0x01, 0x00, 0x00, 0x00, 0x00,     // mov dword ptr [r9], 0
	0xC3,                                           // ret

	// CallOriginal:
	0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, [OriginalFunction]
	0xFF, 0xE0,                                     // jmp rax
	0xCC                                            // int3 padding
};

UCHAR LoadLibraryHookShellcode[] = {
	// Different register preservation
	0x53,                                           // push rbx
	0x50,                                           // push rax
	0x51,                                           // push rcx
	0x52,                                           // push rdx
	0x48, 0x83, 0xEC, 0x20,                        // sub rsp, 0x20

	// Check DLL name
	0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, [ShellcodeData]
	0x48, 0x8D, 0x50, 0x70,                        // lea rdx, [rax+0x70]
	0xE8, 0x00, 0x00, 0x00, 0x00,                 // call CompareString
	0x48, 0x85, 0xC0,                              // test rax, rax
	0x74, 0x16,                                     // jz BlockLoad

	// Restore and call
	0x48, 0x83, 0xC4, 0x20,                        // add rsp, 0x20
	0x5A,                                           // pop rdx
	0x59,                                           // pop rcx
	0x58,                                           // pop rax
	0x5B,                                           // pop rbx
	0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, [OriginalFunction]
	0xFF, 0xE0,                                     // jmp rax

	// BlockLoad:
	0x48, 0x83, 0xC4, 0x20,                        // add rsp, 0x20
	0x5A,                                           // pop rdx
	0x59,                                           // pop rcx
	0x58,                                           // pop rax
	0x5B,                                           // pop rbx
	0x48, 0x31, 0xC0,                              // xor rax, rax
	0xC3,                                           // ret
	0xCC, 0xCC, 0xCC                               // int3 padding
};

// Polymorphic string comparison
UCHAR StringCompareShellcode[] = {
	// rcx = haystack, rdx = needle
	0x48, 0x85, 0xC9,                              // test rcx, rcx
	0x74, 0x33,                                     // jz NotFound
	0x48, 0x85, 0xD2,                              // test rdx, rdx
	0x74, 0x2E,                                     // jz NotFound

	0x49, 0x89, 0xC8,                              // mov r8, rcx (different register)
	// OuterLoop:
	0x45, 0x0F, 0xB7, 0x08,                        // movzx r9w, word ptr [r8]
	0x66, 0x45, 0x85, 0xC9,                        // test r9w, r9w
	0x74, 0x20,                                     // jz NotFound

	0x49, 0x89, 0xD1,                              // mov r9, rdx
	// InnerLoop:
	0x45, 0x0F, 0xB7, 0x11,                        // movzx r10w, word ptr [r9]
	0x66, 0x45, 0x85, 0xD2,                        // test r10w, r10w
	0x74, 0x11,                                     // jz Found

	0x66, 0x45, 0x39, 0xD1,                        // cmp r9w, r10w
	0x75, 0x05,                                     // jne NextChar
	0x49, 0x83, 0xC1, 0x02,                        // add r9, 2
	0xEB, 0xEB,                                     // jmp InnerLoop

	// NextChar:
	0x49, 0x83, 0xC0, 0x02,                        // add r8, 2
	0xEB, 0xD9,                                     // jmp OuterLoop

	// Found:
	0xB8, 0x01, 0x00, 0x00, 0x00,                 // mov eax, 1
	0xC3,                                           // ret

	// NotFound:
	0x31, 0xC0,                                     // xor eax, eax
	0xC3,                                           // ret
};

// Function prototypes
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);

// Driver unload callback with proper annotation
DRIVER_UNLOAD DriverUnload;

VOID ProcessNotifyRoutine(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create);
VOID LoadImageNotifyRoutine(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo);
NTSTATUS NeutralizeTarget(PVOID ImageBase, SIZE_T ImageSize);
BOOLEAN IsTargetProcess(HANDLE ProcessId);
NTSTATUS GetProcessImageName(HANDLE ProcessId, PUNICODE_STRING ImageName);
NTSTATUS HookUserModeIAT(PEPROCESS Process, HANDLE ProcessId);
NTSTATUS GetModuleBase(PEPROCESS Process, PCWSTR ModuleName, PVOID* ModuleBase);
NTSTATUS HookIATEntry(PEPROCESS Process, PVOID ModuleBase, PCHAR ImportDllName,
	PCHAR FunctionName, PVOID HookShellcode, SIZE_T ShellcodeSize,
	PVOID ShellcodeDataAddr, PVOID* OriginalFunction);
NTSTATUS AllocateUserModeShellcode(PEPROCESS Process, PPROC_INFO ProcInfo);

// Memory allocation wrapper with size randomization
PVOID AllocatePoolMemory(SIZE_T Size, ULONG Tag)
{
	// Add random padding to allocation size
	ULONG Random = (ULONG)KeQueryPerformanceCounter(NULL).QuadPart;
	SIZE_T PaddedSize = Size + (Random % 64) + 16;
	return ExAllocatePoolWithTag(NonPagedPool, PaddedSize, Tag);
}

// Read process memory safely
NTSTATUS SafeReadProcessMemory(PEPROCESS Process, PVOID Address, PVOID Buffer, SIZE_T Size)
{
	SIZE_T BytesRead = 0;
	__try {
		return MmCopyVirtualMemory(Process, Address, PsGetCurrentProcess(),
			Buffer, Size, KernelMode, &BytesRead);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return STATUS_ACCESS_VIOLATION;
	}
}

// Write process memory safely
NTSTATUS SafeWriteProcessMemory(PEPROCESS Process, PVOID Address, PVOID Buffer, SIZE_T Size)
{
	SIZE_T BytesWritten = 0;
	__try {
		return MmCopyVirtualMemory(PsGetCurrentProcess(), Buffer, Process,
			Address, Size, KernelMode, &BytesWritten);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return STATUS_ACCESS_VIOLATION;
	}
}

// Allocate executable memory in user mode
NTSTATUS AllocateUserModeMemory(PEPROCESS Process, SIZE_T Size, PVOID* BaseAddress)
{
	KAPC_STATE ApcState;
	HANDLE ProcessHandle = NULL;
	NTSTATUS Status;

	// Get process handle
	Status = ObOpenObjectByPointer(Process, 0, NULL, PROCESS_ALL_ACCESS,
		*PsProcessType, KernelMode, &ProcessHandle);
	if (!NT_SUCCESS(Status)) {
		return Status;
	}

	// Attach to process
	KeStackAttachProcess(Process, &ApcState);

	// Allocate memory
	*BaseAddress = NULL;
	Size = ROUND_TO_PAGES(Size);
	Status = ZwAllocateVirtualMemory(ProcessHandle, BaseAddress, 0, &Size,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	KeUnstackDetachProcess(&ApcState);
	ZwClose(ProcessHandle);

	return Status;
}

// Allocate and setup shellcode in user mode
NTSTATUS AllocateUserModeShellcode(PEPROCESS Process, PPROC_INFO ProcInfo)
{
	NTSTATUS Status;
	PVOID ShellcodeBase = NULL;
	SIZE_T TotalSize = PAGE_SIZE * 2;  // 8KB for shellcode and data

	// Allocate executable memory in user mode
	Status = AllocateUserModeMemory(Process, TotalSize, &ShellcodeBase);
	if (!NT_SUCCESS(Status)) {
		DBG_PRINT("[Driver] Failed to allocate shellcode memory: 0x%08X\n", Status);
		return Status;
	}

	ProcInfo->ScBase = ShellcodeBase;
	ProcInfo->ScSize = TotalSize;

	// Setup shellcode data with obfuscated strings
	SC_DATA ShellcodeData = { 0 };
	// Decrypt at runtime
	for (int i = 0; i < 8; i++) {
		ShellcodeData.DeviceName[i] = (WCHAR)(L"\\device\\"[i] ^ 0x55);
		ShellcodeData.DllName[i] = g_??ServiceName[i] ^ 0xAA;
	}

	// Write shellcode data at the beginning
	Status = SafeWriteProcessMemory(Process, ShellcodeBase, &ShellcodeData, sizeof(ShellcodeData));
	if (!NT_SUCCESS(Status)) {
		DBG_PRINT("[Driver] Failed to write shellcode data: 0x%08X\n", Status);
		return Status;
	}

	ProcInfo->ScData = (PSC_DATA)ShellcodeBase;

	// Write string comparison helper
	PVOID StringCompareAddr = (PUCHAR)ShellcodeBase + 0x100;
	Status = SafeWriteProcessMemory(Process, StringCompareAddr,
		StringCompareShellcode, sizeof(StringCompareShellcode));
	if (!NT_SUCCESS(Status)) {
		DBG_PRINT("[Driver] Failed to write string compare shellcode: 0x%08X\n", Status);
		return Status;
	}

	DBG_PRINT("[Driver] Shellcode allocated at %p\n", ShellcodeBase);
	return STATUS_SUCCESS;
}

// Get module base address in user process
NTSTATUS GetModuleBase(PEPROCESS Process, PCWSTR ModuleName, PVOID* ModuleBase)
{
	KAPC_STATE ApcState;
	PPEB Peb = PsGetProcessPeb(Process);
	if (!Peb) {
		return STATUS_UNSUCCESSFUL;
	}

	*ModuleBase = NULL;

	__try {
		KeStackAttachProcess(Process, &ApcState);

		// Read PEB
		PEB PebCopy = { 0 };
		if (!NT_SUCCESS(SafeReadProcessMemory(Process, Peb, &PebCopy, sizeof(PEB)))) {
			KeUnstackDetachProcess(&ApcState);
			return STATUS_UNSUCCESSFUL;
		}

		// Get Ldr
		PPEB_LDR_DATA Ldr = PebCopy.Ldr;
		PEB_LDR_DATA LdrCopy = { 0 };
		if (!NT_SUCCESS(SafeReadProcessMemory(Process, Ldr, &LdrCopy, sizeof(PEB_LDR_DATA)))) {
			KeUnstackDetachProcess(&ApcState);
			return STATUS_UNSUCCESSFUL;
		}

		// Walk module list
		PLIST_ENTRY CurrentEntry = LdrCopy.InLoadOrderModuleList.Flink;
		while (CurrentEntry != &Ldr->InLoadOrderModuleList) {
			LDR_DATA_TABLE_ENTRY Entry = { 0 };
			if (!NT_SUCCESS(SafeReadProcessMemory(Process,
				CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks),
				&Entry, sizeof(Entry)))) {
				break;
			}

			// Check module name
			if (Entry.BaseDllName.Buffer && Entry.BaseDllName.Length > 0) {
				WCHAR NameBuffer[256] = { 0 };
				SIZE_T NameSize = min(Entry.BaseDllName.Length, sizeof(NameBuffer) - 2);

				if (NT_SUCCESS(SafeReadProcessMemory(Process, Entry.BaseDllName.Buffer,
					NameBuffer, NameSize))) {
					if (_wcsicmp(NameBuffer, ModuleName) == 0) {
						*ModuleBase = Entry.DllBase;
						break;
					}
				}
			}

			CurrentEntry = Entry.InLoadOrderLinks.Flink;
		}

		KeUnstackDetachProcess(&ApcState);
		return (*ModuleBase != NULL) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		KeUnstackDetachProcess(&ApcState);
		return STATUS_UNSUCCESSFUL;
	}
}

// Hook specific IAT entry with shellcode
NTSTATUS HookIATEntry(PEPROCESS Process, PVOID ModuleBase, PCHAR ImportDllName,
	PCHAR FunctionName, PVOID HookShellcode, SIZE_T ShellcodeSize,
	PVOID ShellcodeDataAddr, PVOID* OriginalFunction)
{
	KAPC_STATE ApcState;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	KeStackAttachProcess(Process, &ApcState);

	__try {
		// Read DOS header
		IMAGE_DOS_HEADER DosHeaderBuf = { 0 };
		if (!NT_SUCCESS(SafeReadProcessMemory(Process, ModuleBase, &DosHeaderBuf, sizeof(DosHeaderBuf)))) {
			__leave;
		}

		if (DosHeaderBuf.e_magic != IMAGE_DOS_SIGNATURE) {
			__leave;
		}

		// Read NT headers
		IMAGE_NT_HEADERS NtHeadersBuf = { 0 };
		PVOID NtHeadersAddr = (PUCHAR)ModuleBase + DosHeaderBuf.e_lfanew;
		if (!NT_SUCCESS(SafeReadProcessMemory(Process, NtHeadersAddr, &NtHeadersBuf, sizeof(NtHeadersBuf)))) {
			__leave;
		}

		if (NtHeadersBuf.Signature != IMAGE_NT_SIGNATURE) {
			__leave;
		}

		// Get import directory
		ULONG ImportDirRva = NtHeadersBuf.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		if (!ImportDirRva) {
			__leave;
		}

		PIMAGE_IMPORT_DESCRIPTOR ImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((PUCHAR)ModuleBase + ImportDirRva);

		// Walk import descriptors
		IMAGE_IMPORT_DESCRIPTOR ImportDescBuf = { 0 };
		while (TRUE) {
			if (!NT_SUCCESS(SafeReadProcessMemory(Process, ImportDesc, &ImportDescBuf, sizeof(ImportDescBuf)))) {
				break;
			}

			if (!ImportDescBuf.Name) {
				break;
			}

			// Check DLL name
			CHAR DllNameBuf[256] = { 0 };
			PVOID DllNameAddr = (PUCHAR)ModuleBase + ImportDescBuf.Name;
			if (!NT_SUCCESS(SafeReadProcessMemory(Process, DllNameAddr, DllNameBuf, sizeof(DllNameBuf) - 1))) {
				ImportDesc++;
				continue;
			}

			if (_stricmp(DllNameBuf, ImportDllName) == 0) {
				// Found target DLL, now find function
				PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)((PUCHAR)ModuleBase + ImportDescBuf.FirstThunk);
				PIMAGE_THUNK_DATA OriginalFirstThunk = (PIMAGE_THUNK_DATA)((PUCHAR)ModuleBase + ImportDescBuf.OriginalFirstThunk);

				IMAGE_THUNK_DATA ThunkData = { 0 };
				ULONG Index = 0;

				while (TRUE) {
					if (!NT_SUCCESS(SafeReadProcessMemory(Process, &OriginalFirstThunk[Index],
						&ThunkData, sizeof(ThunkData)))) {
						break;
					}

					if (!ThunkData.u1.AddressOfData) {
						break;
					}

					if (!(ThunkData.u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
						// Import by name
						IMAGE_IMPORT_BY_NAME ImportByName = { 0 };
						PVOID ImportByNameAddr = (PUCHAR)ModuleBase + ThunkData.u1.AddressOfData;

						if (NT_SUCCESS(SafeReadProcessMemory(Process, ImportByNameAddr,
							&ImportByName, sizeof(ImportByName)))) {
							CHAR NameBuf[256] = { 0 };
							PVOID NameAddr = (PUCHAR)ImportByNameAddr + FIELD_OFFSET(IMAGE_IMPORT_BY_NAME, Name);

							if (NT_SUCCESS(SafeReadProcessMemory(Process, NameAddr, NameBuf, sizeof(NameBuf) - 1))) {
								if (strcmp(NameBuf, FunctionName) == 0) {
									// Found! Save original and write hook
									PVOID* IatEntry = (PVOID*)&FirstThunk[Index].u1.Function;

									// Read original function address
									if (NT_SUCCESS(SafeReadProcessMemory(Process, IatEntry,
										OriginalFunction, sizeof(PVOID)))) {
										// Write hook
										if (NT_SUCCESS(SafeWriteProcessMemory(Process, IatEntry,
											&HookShellcode, sizeof(PVOID)))) {
											DBG_PRINT("[Driver] Hooked %s!%s: %p -> %p\n",
												ImportDllName, FunctionName, *OriginalFunction, HookShellcode);
											Status = STATUS_SUCCESS;
											__leave;
										}
									}
								}
							}
						}
					}
					Index++;
				}
			}
			ImportDesc++;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		Status = STATUS_UNSUCCESSFUL;
	}

	KeUnstackDetachProcess(&ApcState);
	return Status;
}

// Setup hook shellcode with proper addresses
NTSTATUS SetupHookShellcode(PEPROCESS Process, PVOID ShellcodeAddr, PVOID OriginalFunction,
	PVOID ShellcodeDataAddr, PUCHAR Template, SIZE_T TemplateSize)
{
	PUCHAR Shellcode = (PUCHAR)AllocatePoolMemory(TemplateSize, DRIVER_TAG);
	if (!Shellcode) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// Copy template
	RtlCopyMemory(Shellcode, Template, TemplateSize);

	// Patch addresses
	for (SIZE_T i = 0; i < TemplateSize - 8; i++) {
		if (*(PUINT64)&Shellcode[i] == 0) {
			// Check previous instruction
			if (i >= 2 && Shellcode[i - 2] == 0x48 && Shellcode[i - 1] == 0xB8) {
				// mov rax, imm64
				if (Shellcode[i - 10] == 0xB8) {  // First occurrence - ShellcodeData
					*(PVOID*)&Shellcode[i] = ShellcodeDataAddr;
				}
				else {  // Second occurrence - OriginalFunction
					*(PVOID*)&Shellcode[i] = OriginalFunction;
				}
			}
		}
	}

	// Write shellcode to user mode
	NTSTATUS Status = SafeWriteProcessMemory(Process, ShellcodeAddr, Shellcode, TemplateSize);
	ExFreePoolWithTag(Shellcode, DRIVER_TAG);

	return Status;
}

// Hook user mode IAT with shellcode
NTSTATUS HookUserModeIAT(PEPROCESS Process, HANDLE ProcessId)
{
	NTSTATUS Status;
	PVOID ExeBase = NULL;
	PPROC_INFO ProcInfo = NULL;

	DBG_PRINT("[Driver] Starting user-mode IAT hooking for PID %p\n", ProcessId);

	// Find monitored process entry
	KIRQL OldIrql;
	KeAcquireSpinLock(&g_ProcLock, &OldIrql);

	PLIST_ENTRY Entry = g_ProcList.Flink;
	while (Entry != &g_ProcList) {
		PPROC_INFO TempProcess = CONTAINING_RECORD(Entry, PROC_INFO, ListEntry);
		if (TempProcess->ProcId == ProcessId) {
			ProcInfo = TempProcess;
			break;
		}
		Entry = Entry->Flink;
	}

	KeReleaseSpinLock(&g_ProcLock, OldIrql);

	if (!ProcInfo) {
		return STATUS_NOT_FOUND;
	}

	// Random delay
	RandomDelay();

	// Allocate shellcode memory
	Status = AllocateUserModeShellcode(Process, ProcInfo);
	if (!NT_SUCCESS(Status)) {
		return Status;
	}

	// Get main module base
	Status = GetModuleBase(Process, g_TargetProcessName, &ExeBase);
	if (!NT_SUCCESS(Status) || !ExeBase) {
		DBG_PRINT("[Driver] Failed to get exe base\n");
		return Status;
	}

	DBG_PRINT("[Driver] Target exe base: %p\n", ExeBase);

	PVOID ShellcodeBase = ProcInfo->ScBase;
	PVOID CurrentShellcode = (PUCHAR)ShellcodeBase + 0x200;  // Start after data and helpers

	// Hook CreateFileW
	PVOID CreateFileWShellcode = CurrentShellcode;
	PVOID CreateFileWOriginal = NULL;
	Status = SetupHookShellcode(Process, CreateFileWShellcode, NULL, ShellcodeBase,
		CreateFileHookShellcode, sizeof(CreateFileHookShellcode));
	if (NT_SUCCESS(Status)) {
		Status = HookIATEntry(Process, ExeBase, "kernel32.dll", "CreateFileW",
			CreateFileWShellcode, sizeof(CreateFileHookShellcode),
			ShellcodeBase, &CreateFileWOriginal);
		if (NT_SUCCESS(Status)) {
			// Update shellcode with original function address
			SetupHookShellcode(Process, CreateFileWShellcode, CreateFileWOriginal, ShellcodeBase,
				CreateFileHookShellcode, sizeof(CreateFileHookShellcode));

			// Save to shellcode data
			SafeWriteProcessMemory(Process, &ProcInfo->ScData->CreateFileWOrig,
				&CreateFileWOriginal, sizeof(PVOID));
		}
	}
	CurrentShellcode = (PUCHAR)CurrentShellcode + ROUND_TO_PAGES(sizeof(CreateFileHookShellcode));

	// Hook DeviceIoControl
	PVOID DeviceIoControlShellcode = CurrentShellcode;
	PVOID DeviceIoControlOriginal = NULL;
	Status = SetupHookShellcode(Process, DeviceIoControlShellcode, NULL, ShellcodeBase,
		DeviceIoControlHookShellcode, sizeof(DeviceIoControlHookShellcode));
	if (NT_SUCCESS(Status)) {
		Status = HookIATEntry(Process, ExeBase, "kernel32.dll", "DeviceIoControl",
			DeviceIoControlShellcode, sizeof(DeviceIoControlHookShellcode),
			ShellcodeBase, &DeviceIoControlOriginal);
		if (NT_SUCCESS(Status)) {
			SetupHookShellcode(Process, DeviceIoControlShellcode, DeviceIoControlOriginal, ShellcodeBase,
				DeviceIoControlHookShellcode, sizeof(DeviceIoControlHookShellcode));

			SafeWriteProcessMemory(Process, &ProcInfo->ScData->DeviceIoControlOrig,
				&DeviceIoControlOriginal, sizeof(PVOID));
		}
	}
	CurrentShellcode = (PUCHAR)CurrentShellcode + ROUND_TO_PAGES(sizeof(DeviceIoControlHookShellcode));

	// Hook LoadLibraryW
	PVOID LoadLibraryWShellcode = CurrentShellcode;
	PVOID LoadLibraryWOriginal = NULL;
	Status = SetupHookShellcode(Process, LoadLibraryWShellcode, NULL, ShellcodeBase,
		LoadLibraryHookShellcode, sizeof(LoadLibraryHookShellcode));
	if (NT_SUCCESS(Status)) {
		Status = HookIATEntry(Process, ExeBase, "kernel32.dll", "LoadLibraryW",
			LoadLibraryWShellcode, sizeof(LoadLibraryHookShellcode),
			ShellcodeBase, &LoadLibraryWOriginal);
		if (NT_SUCCESS(Status)) {
			SetupHookShellcode(Process, LoadLibraryWShellcode, LoadLibraryWOriginal, ShellcodeBase,
				LoadLibraryHookShellcode, sizeof(LoadLibraryHookShellcode));

			SafeWriteProcessMemory(Process, &ProcInfo->ScData->LoadLibraryWOrig,
				&LoadLibraryWOriginal, sizeof(PVOID));
		}
	}

	DBG_PRINT("[Driver] User-mode IAT hooking completed\n");
	return STATUS_SUCCESS;
}

// Get process image name by PID
NTSTATUS GetProcessImageName(HANDLE ProcessId, PUNICODE_STRING ImageName)
{
	PEPROCESS Process = NULL;
	NTSTATUS Status = PsLookupProcessByProcessId(ProcessId, &Process);
	if (!NT_SUCCESS(Status)) {
		return Status;
	}

	__try {
		// Get process image file name
		PUCHAR ImageFileName = PsGetProcessImageFileName(Process);
		if (ImageFileName) {
			ANSI_STRING AnsiName;
			RtlInitAnsiString(&AnsiName, (PCHAR)ImageFileName);
			Status = RtlAnsiStringToUnicodeString(ImageName, &AnsiName, TRUE);
		}
		else {
			Status = STATUS_NOT_FOUND;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		Status = STATUS_EXCEPTION_ENCOUNTERED;
	}

	ObDereferenceObject(Process);
	return Status;
}

// Check if process is target
BOOLEAN IsTargetProcess(HANDLE ProcessId)
{
	UNICODE_STRING ImageName = { 0 };
	NTSTATUS Status = GetProcessImageName(ProcessId, &ImageName);
	if (!NT_SUCCESS(Status)) {
		return FALSE;
	}

	BOOLEAN IsTarget = FALSE;
	if (ImageName.Buffer) {
		// Use decrypted target name
		if (wcsstr(ImageName.Buffer, g_TargetProcessName)) {
			IsTarget = TRUE;
		}
		RtlFreeUnicodeString(&ImageName);
	}

	return IsTarget;
}

// Neutralize target driver
NTSTATUS NeutralizeTarget(PVOID ImageBase, SIZE_T ImageSize)
{
	if (!ImageBase || ImageSize < 0x25000) {
		return STATUS_INVALID_PARAMETER;
	}

	__try {
		// Verify target signature with dynamic offset
		PUCHAR DriverEntryAddr = (PUCHAR)ImageBase + 0x24000;  // RVA still valid

		// Use polymorphic check
		UCHAR ExpectedBytes[] = { 0x48, 0x89, 0x5C, 0x24, 0x08 };
		BOOLEAN Match = TRUE;
		for (int i = 0; i < sizeof(ExpectedBytes); i++) {
			if (DriverEntryAddr[i] != ExpectedBytes[i]) {
				Match = FALSE;
				break;
			}
		}

		if (!Match) {
			return STATUS_NOT_FOUND;
		}

		// Random delay before patching
		RandomDelay();

		// Use alternative patching method
		UCHAR Patch[] = {
			0x31, 0xC0,                    // xor eax, eax (STATUS_SUCCESS)
			0xC3,                          // ret
			0x90, 0x90, 0x90               // nop padding
		};

		// Disable WP and patch
		KIRQL OldIrql = KeRaiseIrqlToDpcLevel();
		UINT64 OldCr0 = __readcr0();
		__writecr0(OldCr0 & ~0x10000);

		__try {
			RtlCopyMemory(DriverEntryAddr, Patch, sizeof(Patch));

			// Neutralize dangerous IAT entries with NULL check
			PVOID* IatEntry;

			// PsSetLoadImageNotifyRoutine
			IatEntry = (PVOID*)((PUCHAR)ImageBase + 0x10158);
			if (MmIsAddressValid(IatEntry)) {
				*IatEntry = NULL;
				// Add memory barrier
				_mm_mfence();
			}

			// PsSetCreateProcessNotifyRoutine
			IatEntry = (PVOID*)((PUCHAR)ImageBase + 0x10238);
			if (MmIsAddressValid(IatEntry)) {
				*IatEntry = NULL;
				_mm_mfence();
			}

			// IoCreateDevice
			IatEntry = (PVOID*)((PUCHAR)ImageBase + 0x10280);
			if (MmIsAddressValid(IatEntry)) {
				*IatEntry = NULL;
				_mm_mfence();
			}

			DBG_PRINT("[Driver] Target neutralized at %p\n", ImageBase);
			g_TargetNeutralized = TRUE;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			// Ignore
		}

		__writecr0(OldCr0);
		KeLowerIrql(OldIrql);

		return STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return STATUS_UNSUCCESSFUL;
	}
}

// Process creation/termination callback
VOID ProcessNotifyRoutine(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create)
{
	UNREFERENCED_PARAMETER(ParentId);

	if (Create) {
		// Process created
		if (IsTargetProcess(ProcessId)) {
			DBG_PRINT("[Driver] Target process started (PID: %p)\n", ProcessId);

			// Lookup process object
			PEPROCESS Process = NULL;
			NTSTATUS Status = PsLookupProcessByProcessId(ProcessId, &Process);
			if (!NT_SUCCESS(Status)) {
				DBG_PRINT("[Driver] Failed to get process object\n");
				return;
			}

			KIRQL OldIrql;
			KeAcquireSpinLock(&g_ProcLock, &OldIrql);

			// Add to monitored list
			PPROC_INFO Entry = (PPROC_INFO)
				AllocatePoolMemory(sizeof(PROC_INFO), DRIVER_TAG);
			if (Entry) {
				RtlZeroMemory(Entry, sizeof(PROC_INFO));
				Entry->ProcId = ProcessId;
				Entry->Proc = Process;
				Entry->Hooked = FALSE;
				InitializeListHead(&Entry->Hooks);
				InsertTailList(&g_ProcList, &Entry->ListEntry);
				g_GameActive = TRUE;
				g_TargetNeutralized = FALSE;
			}

			KeReleaseSpinLock(&g_ProcLock, OldIrql);

			// Variable delay to avoid detection
			LARGE_INTEGER Delay;
			ULONG Random = (ULONG)KeQueryPerformanceCounter(NULL).QuadPart;
			Delay.QuadPart = -10000000LL - (Random % 5000000); // 1-1.5 seconds
			KeDelayExecutionThread(KernelMode, FALSE, &Delay);

			// Hook user mode IAT
			if (Entry && Process) {
				Status = HookUserModeIAT(Process, ProcessId);
				if (NT_SUCCESS(Status)) {
					Entry->Hooked = TRUE;
					DBG_PRINT("[Driver] User-mode IAT hooked successfully\n");
				}
				else {
					DBG_PRINT("[Driver] Failed to hook user-mode IAT: 0x%08X\n", Status);
				}
			}

			DBG_PRINT("[Driver] Ready to neutralize target when it loads\n");
		}
	}
	else {
		// Process terminated
		KIRQL OldIrql;
		KeAcquireSpinLock(&g_ProcLock, &OldIrql);

		PLIST_ENTRY Entry = g_ProcList.Flink;
		while (Entry != &g_ProcList) {
			PPROC_INFO Process = CONTAINING_RECORD(Entry, PROC_INFO, ListEntry);
			PLIST_ENTRY NextEntry = Entry->Flink;

			if (Process->ProcId == ProcessId) {
				DBG_PRINT("[Driver] Target process terminated\n");

				// Free shellcode memory if allocated
				if (Process->ScBase && Process->Proc) {
					KAPC_STATE ApcState;
					KeStackAttachProcess(Process->Proc, &ApcState);

					HANDLE ProcessHandle = NULL;
					if (NT_SUCCESS(ObOpenObjectByPointer(Process->Proc, 0, NULL, PROCESS_ALL_ACCESS,
						*PsProcessType, KernelMode, &ProcessHandle))) {
						SIZE_T Size = 0;
						ZwFreeVirtualMemory(ProcessHandle, &Process->ScBase, &Size, MEM_RELEASE);
						ZwClose(ProcessHandle);
					}

					KeUnstackDetachProcess(&ApcState);
				}

				// Cleanup IAT hooks
				while (!IsListEmpty(&Process->Hooks)) {
					PLIST_ENTRY HookEntry = RemoveHeadList(&Process->Hooks);
					PHOOK_ENTRY Hook = CONTAINING_RECORD(HookEntry, HOOK_ENTRY, ListEntry);
					ExFreePoolWithTag(Hook, DRIVER_TAG);
				}

				// Dereference process object
				if (Process->Proc) {
					ObDereferenceObject(Process->Proc);
				}

				RemoveEntryList(Entry);
				ExFreePoolWithTag(Process, DRIVER_TAG);

				if (IsListEmpty(&g_ProcList)) {
					g_GameActive = FALSE;
					g_TargetNeutralized = FALSE;
					DBG_PRINT("[Driver] No more game instances running\n");
				}
				break;
			}
			Entry = NextEntry;
		}

		KeReleaseSpinLock(&g_ProcLock, OldIrql);
	}
}

// Image load callback - neutralize target when it loads
VOID LoadImageNotifyRoutine(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
	// Only kernel drivers
	if (ProcessId != 0 || !FullImageName || !ImageInfo || !ImageInfo->SystemModeImage) {
		return;
	}

	// Only act if game is running and target not yet neutralized
	if (!g_GameActive || g_TargetNeutralized) {
		return;
	}

	// Check for target driver with obfuscated check
	BOOLEAN IsTarget = FALSE;
	for (int i = 0; i < 8; i++) {
		if (FullImageName->Buffer[wcslen(FullImageName->Buffer) - 8 + i] !=
			g_??ServiceName[i]) {
			IsTarget = FALSE;
			break;
		}
		IsTarget = TRUE;
	}

	if (IsTarget) {
		DBG_PRINT("[Driver] Target detected while game is running\n");

		// Variable delay to ensure mapping is complete
		LARGE_INTEGER Delay;
		ULONG Random = (ULONG)KeQueryPerformanceCounter(NULL).QuadPart;
		Delay.QuadPart = -10000LL - (Random % 5000); // 1-1.5ms
		KeDelayExecutionThread(KernelMode, FALSE, &Delay);

		// Neutralize it immediately
		NeutralizeTarget(ImageInfo->ImageBase, ImageInfo->ImageSize);
	}
}

// Check for already running target processes at driver load
VOID CheckExistingProcesses(VOID)
{
	// This is simplified - in production you would properly enumerate processes
	DBG_PRINT("[Driver] Checking for existing target processes...\n");
}

// Driver entry
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	// Decrypt strings at runtime
	DecryptString(ObfuscatedTargetProcess, 19, 0x??, g_TargetProcessName);
	DecryptString(Obfuscated??Service, 8, 0x??, g_??ServiceName);

	DBG_PRINT("[Driver] Enhanced driver initializing...\n");

	DriverObject->DriverUnload = DriverUnload;

	// Initialize lists and locks
	InitializeListHead(&g_ProcList);
	KeInitializeSpinLock(&g_ProcLock);

	// Register process notification
	NTSTATUS Status = PsSetCreateProcessNotifyRoutine(ProcessNotifyRoutine, FALSE);
	if (!NT_SUCCESS(Status)) {
		DBG_PRINT("[Driver] Failed to register process callback: 0x%08X\n", Status);
		return Status;
	}
	g_ProcCallback = ProcessNotifyRoutine;

	// Register image load notification  
	Status = PsSetLoadImageNotifyRoutine(LoadImageNotifyRoutine);
	if (!NT_SUCCESS(Status)) {
		PsSetCreateProcessNotifyRoutine(ProcessNotifyRoutine, TRUE);
		DBG_PRINT("[Driver] Failed to register image callback: 0x%08X\n", Status);
		return Status;
	}
	g_ImgCallback = LoadImageNotifyRoutine;

	// Check if target is already running
	CheckExistingProcesses();

	g_Active = TRUE;
	DBG_PRINT("[Driver] Enhanced driver ready\n");

	return STATUS_SUCCESS;
}

// Driver unload
VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

	DBG_PRINT("[Driver] Unloading...\n");

	if (g_Active) {
		// Remove callbacks
		if (g_ProcCallback) {
			PsSetCreateProcessNotifyRoutine(ProcessNotifyRoutine, TRUE);
		}
		if (g_ImgCallback) {
			PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine);
		}

		// Clean up process list
		KIRQL OldIrql;
		KeAcquireSpinLock(&g_ProcLock, &OldIrql);

		while (!IsListEmpty(&g_ProcList)) {
			PLIST_ENTRY Entry = RemoveHeadList(&g_ProcList);
			PPROC_INFO Process = CONTAINING_RECORD(Entry, PROC_INFO, ListEntry);

			// Cleanup IAT hooks
			while (!IsListEmpty(&Process->Hooks)) {
				PLIST_ENTRY HookEntry = RemoveHeadList(&Process->Hooks);
				PHOOK_ENTRY Hook = CONTAINING_RECORD(HookEntry, HOOK_ENTRY, ListEntry);
				ExFreePoolWithTag(Hook, DRIVER_TAG);
			}

			// Dereference process object
			if (Process->Proc) {
				ObDereferenceObject(Process->Proc);
			}

			ExFreePoolWithTag(Process, DRIVER_TAG);
		}

		KeReleaseSpinLock(&g_ProcLock, OldIrql);
	}

	DBG_PRINT("[Driver] Unloaded\n");
}