## Bypassing Hyperion's NtCreateSection hook and LoadLibrary block

## The Problem

Hyperion hooks `NtCreateSection` and blocks anything with `SEC_IMAGE`. That's a problem because `LoadLibrary` uses `SEC_IMAGE` to load DLLs. 

## The Trick

But here's the thing - Before Windows goes through the trouble of creating a new section for a DLL, it first checks if that DLL is *already* loaded. It looks through `PEB->Ldr->InLoadOrderModuleList`, and if it finds a match, it just reuses that entry and **completely skips calling `NtCreateSection`**.

Internally, LoadLibraryA or any other variant, just calls "LoadLibraryStub" (a forwarder), which then calls LdrLoadDll, which calls LdrpLoadDll, which then calls LdrpLoadDllInternal, which then checks if the image is already loaded using LdrpFastpthReloadedDll -> LdrpFindLoadedDllByName to search PEB->Ldr->InLoadOrderModuleList, and if found (like our fake version.dll entry), it increments the load count, builds forwarder links, and returns STATUS_SUCCESS causing LdrpLoadDllInternal to skip LdrpMapDll entirely, meaning NtCreateSection(SEC_IMAGE) never gets called, which completely bypasses Hyperion's hook that's waiting to block exactly that call!

<img width="950" height="783" alt="image" src="https://github.com/user-attachments/assets/14e585b2-a08c-48a4-bb48-0afb4c1b3383" />

So our little hack works like this:

1. We create our own section with `PAGE_READWRITE`
2. We map it and write our DLL into it
3. We insert a fake entry into the loader's module list
4. We call `LoadLibrary` with a legit DLL name
5. The loader finds our fake entry and happily reuses it

Pretty clever, right?

## Step 1: Create the Section

First things first we need a section to hold our DLL.

```cpp
HANDLE hSection;
LARGE_INTEGER liSize;
liSize.QuadPart = dllSize;

NtCreateSection(
    &hSection,
    SECTION_ALL_ACCESS,
    NULL,
    &liSize,
    PAGE_READWRITE,
    SEC_COMMIT,
    NULL
);

PVOID pMappedBase = NULL;
SIZE_T viewSize = 0;
NtMapViewOfSection(
    hSection,
    GetCurrentProcess(),
    &pMappedBase,
    0, 0, NULL,
    &viewSize,
    1, 0,
    PAGE_READWRITE
);

memcpy(pMappedBase, dllBytes, dllSize);
```

## Step 2: Fake LDR Entry

The loader maintains a linked list of all loaded modules. We're going to add our own entry to that list.

```cpp
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

PLDR_DATA_TABLE_ENTRY pFakeEntry = (PLDR_DATA_TABLE_ENTRY)VirtualAlloc(
    NULL,
    sizeof(LDR_DATA_TABLE_ENTRY),
    MEM_COMMIT | MEM_RESERVE,
    PAGE_READWRITE
);

RtlZeroMemory(pFakeEntry, sizeof(LDR_DATA_TABLE_ENTRY));
pFakeEntry->DllBase = pMappedBase;
pFakeEntry->SizeOfImage = dllSize;
pFakeEntry->LoadCount = 1;

// We need to use a legit system DLL name
UNICODE_STRING usFullName, usBaseName;
RtlInitUnicodeString(&usFullName, L"C:\\Windows\\System32\\version.dll");
RtlInitUnicodeString(&usBaseName, L"version.dll");
pFakeEntry->FullDllName = usFullName;
pFakeEntry->BaseDllName = usBaseName;
```

## Step 3: Insert Into Loader's List

 We're going to insert our fake entry right into the loader's list:

```cpp
PPEB pPeb = (PPEB)__readgsqword(0x60);
PPEB_LDR_DATA pLdr = pPeb->Ldr;

PLIST_ENTRY pHead = &pLdr->InLoadOrderModuleList;
PLIST_ENTRY pNext = pHead->Flink;

pFakeEntry->InLoadOrderLinks.Flink = pNext;
```

And that's it!
