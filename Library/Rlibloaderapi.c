#include "Rlibloaderapi.h"

void DbgPrint(const PCSTR Format, ...)
{
    CHAR szBuf[512];
    va_list vargs;

    va_start(vargs, Format);
    vsprintf(szBuf, Format, vargs);
    va_end(vargs);
    OutputDebugStringA(szBuf);
}

PVOID GetRemotePeb(HANDLE ProcessHandle)
{
    PROCESS_BASIC_INFORMATION pbi = { 0, };
    NtQueryInformationProcess(ProcessHandle, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);
#ifdef _WIN64
    BOOL bWow64Process;
    IsWow64Process(ProcessHandle, &bWow64Process);
    return bWow64Process ? (ULONG_PTR)pbi.PebBaseAddress + 0x1000 : pbi.PebBaseAddress;
#else
    return pbi.PebBaseAddress;
#endif
}

HMODULE GetRemoteModuleHandleA(HANDLE ProcessHandle, LPCSTR lpModuleName)
{
    HMODULE hModule = NULL;
    LPWSTR ModuleName = NULL;
    int ModuleNameLength = MultiByteToWideChar(CP_ACP, 0, lpModuleName, -1, NULL, 0);
    ModuleName = calloc(ModuleNameLength, sizeof(wchar_t));
    MultiByteToWideChar(CP_ACP, 0, lpModuleName, -1, ModuleName, ModuleNameLength);
    hModule = GetRemoteModuleHandleW(ProcessHandle, ModuleName);
    free(ModuleName);
    return hModule;
}

HMODULE GetRemoteModuleHandleW(HANDLE ProcessHandle, LPCWSTR lpModuleName)
{
#ifdef _WIN64
    BOOL bWow64Process;
    IsWow64Process(ProcessHandle, &bWow64Process);
    size_t SizeOfPointer = bWow64Process ? 4 : 8;
#else
    size_t SizeOfPointer = 4;
#endif
    
    HMODULE hModule = NULL;
    PVOID PebBaseAddress = GetRemotePeb(ProcessHandle);

    if (PebBaseAddress == NULL)
        return hModule;

    PVOID PebLdrData = NULL;

    if (ReadProcessMemory(ProcessHandle, 
#ifdef _WIN64
            (ULONG_PTR)PebBaseAddress + (bWow64Process ? Peb_LdrOffset32 : Peb_LdrOffset64), 
#else
            (ULONG_PTR)PebBaseAddress + Peb_LdrOffset32,
#endif
            &PebLdrData, 
            SizeOfPointer, 
            NULL) == FALSE)
        return hModule;

#ifdef _WIN64
    PVOID LdrDataTableEntry = (ULONG_PTR)PebLdrData + (bWow64Process ? PebLdrData_LOMLOffset32 : PebLdrData_LOMLOffset64);
    size_t SizeOfUnicodeString = bWow64Process ? sizeof(UNICODE_STRING32) : sizeof(UNICODE_STRING64);
#else
    PVOID LdrDataTableEntry = (ULONG_PTR)PebLdrData + PebLdrData_LOMLOffset32;
    size_t SizeOfUnicodeString = sizeof(UNICODE_STRING);
#endif

    BYTE *UnicodeString = calloc(1, SizeOfUnicodeString);

    for (LPWSTR ModuleName = NULL; ReadProcessMemory(ProcessHandle, LdrDataTableEntry, &LdrDataTableEntry, SizeOfPointer, NULL) 
            && 
#ifdef _WIN64
            (ULONG_PTR)PebLdrData + (bWow64Process ? PebLdrData_LOMLOffset32 : PebLdrData_LOMLOffset64) != LdrDataTableEntry
#else
            (ULONG_PTR)PebLdrData + PebLdrData_LOMLOffset32 != LdrDataTableEntry
#endif
        ; free(ModuleName))
    {
        if (ReadProcessMemory(ProcessHandle, 
#ifdef _WIN64
                (ULONG_PTR)LdrDataTableEntry + (bWow64Process ? LdrDataTableEntry_BaseDllName32 : LdrDataTableEntry_BaseDllName64), 
#else
                (ULONG_PTR)LdrDataTableEntry + LdrDataTableEntry_BaseDllName32,
#endif
                UnicodeString, 
                SizeOfUnicodeString, 
                NULL) == FALSE)
            return hModule;

#ifdef _WIN64
        ModuleName = malloc(bWow64Process ? ((UNICODE_STRING32 *)UnicodeString)->Length + 2 : ((UNICODE_STRING64 *)UnicodeString)->Length + 2);
#else
        ModuleName = malloc(((UNICODE_STRING32 *)UnicodeString)->Length + 2);
#endif
        if (ReadProcessMemory(ProcessHandle, 
#ifdef _WIN64
                bWow64Process ? ((UNICODE_STRING32 *)UnicodeString)->Buffer : ((UNICODE_STRING64 *)UnicodeString)->Buffer, 
                ModuleName,
                bWow64Process ? ((UNICODE_STRING32 *)UnicodeString)->Length + 2 : ((UNICODE_STRING64 *)UnicodeString)->Length + 2,
#else
                ((UNICODE_STRING32 *)UnicodeString)->Buffer,
                ModuleName, 
                ((UNICODE_STRING32 *)UnicodeString)->Length + 2,
#endif
                NULL) == FALSE)
            return hModule;

        if (wcsicmp(lpModuleName, ModuleName))
            continue;

        if (ReadProcessMemory(ProcessHandle, 
#ifdef _WIN64
                (ULONG_PTR)LdrDataTableEntry + (bWow64Process ? LdrDataTableEntry_DllBase32 : LdrDataTableEntry_DllBase64), 
#else
                (ULONG_PTR)LdrDataTableEntry + LdrDataTableEntry_DllBase32,
#endif
                &hModule, 
                SizeOfPointer, // sizeof(HMODULE), 
                NULL) == FALSE && IFREE(ModuleName))
            return hModule;

        free(ModuleName);
        break;
    }

    free(UnicodeString);
    return hModule;
}

DWORD GetRemoteModuleFileNameA(HANDLE ProcessHandle, HMODULE hModule, LPSTR lpFilename, DWORD nSize)
{
    ZeroMemory(lpFilename, nSize);
    wchar_t Filename[MAX_PATH];
    DWORD Size = GetRemoteModuleFileNameW(ProcessHandle, hModule, Filename, MAX_PATH);
    int FilenameLength = WideCharToMultiByte(CP_ACP, 0, Filename, -1, NULL, 0, NULL, NULL);
    WideCharToMultiByte(CP_ACP, 0, Filename, -1, lpFilename, FilenameLength <= nSize ? FilenameLength : nSize, NULL, NULL);
    return FilenameLength <= nSize ? FilenameLength : nSize;
}

DWORD GetRemoteModuleFileNameW(HANDLE ProcessHandle, HMODULE hModule, LPWSTR lpFilename, DWORD nSize)
{
    return GetRemoteModuleName(ProcessHandle, hModule, lpFilename, nSize, FALSE);
}

DWORD GetRemoteModuleBaseNameA(HANDLE ProcessHandle, HMODULE hModule, LPSTR lpFilename, DWORD nSize)
{
    ZeroMemory(lpFilename, nSize);
    wchar_t Filename[MAX_PATH];
    DWORD Size = GetRemoteModuleBaseNameW(ProcessHandle, hModule, Filename, MAX_PATH);
    int FilenameLength = WideCharToMultiByte(CP_ACP, 0, Filename, -1, NULL, 0, NULL, NULL);
    WideCharToMultiByte(CP_ACP, 0, Filename, -1, lpFilename, FilenameLength <= nSize ? FilenameLength : nSize, NULL, NULL);
    return FilenameLength <= nSize ? FilenameLength : nSize;
}

DWORD GetRemoteModuleBaseNameW(HANDLE ProcessHandle, HMODULE hModule, LPWSTR lpFilename, DWORD nSize)
{
    return GetRemoteModuleName(ProcessHandle, hModule, lpFilename, nSize, TRUE);
}

DWORD GetRemoteModuleName(HANDLE ProcessHandle, HMODULE hModule, LPWSTR lpFilename, DWORD nSize, BOOL bBaseName)
{
#ifdef _WIN64
    BOOL bWow64Process;
    IsWow64Process(ProcessHandle, &bWow64Process);
    size_t SizeOfPointer = bWow64Process ? 4 : 8;
    size_t NameOffset = TERNARY(bBaseName, TERNARY(bWow64Process, LdrDataTableEntry_BaseDllName32, LdrDataTableEntry_BaseDllName64), TERNARY(bWow64Process, LdrDatatableEntry_FullDllName32, LdrDatatableEntry_FullDllName64));
#else
    size_t SizeOfPointer = 4;
    size_t NameOffset = TERNARY(bBaseName, LdrDataTableEntry_BaseDllName32, LdrDatatableEntry_FullDllName32);
#endif
    nSize -= 2;
    DWORD Size = 0;
    PVOID PebBaseAddress = GetRemotePeb(ProcessHandle);

    if (PebBaseAddress == NULL)
        return Size;

    PVOID PebLdrData = NULL;

    if (ReadProcessMemory(ProcessHandle, 
#ifdef _WIN64
            (ULONG_PTR)PebBaseAddress + (bWow64Process ? Peb_LdrOffset32 : Peb_LdrOffset64), 
#else
            (ULONG_PTR)PebBaseAddress + Peb_LdrOffset32,
#endif
            &PebLdrData, 
            SizeOfPointer, 
            NULL) == FALSE)
        return hModule;

#ifdef _WIN64
    PVOID LdrDataTableEntry = (ULONG_PTR)PebLdrData + (bWow64Process ? PebLdrData_LOMLOffset32 : PebLdrData_LOMLOffset64);
#else
    PVOID LdrDataTableEntry = (ULONG_PTR)PebLdrData + PebLdrData_LOMLOffset32;
#endif

    for (; ReadProcessMemory(ProcessHandle, LdrDataTableEntry, &LdrDataTableEntry, SizeOfPointer, NULL) 
            && 
#ifdef _WIN64
            (ULONG_PTR)PebLdrData + (bWow64Process ? PebLdrData_LOMLOffset32 : PebLdrData_LOMLOffset64) != LdrDataTableEntry
#else
            (ULONG_PTR)PebLdrData + PebLdrData_LOMLOffset32 != LdrDataTableEntry
#endif
        ;)
    {
        PVOID DllBase;

        if (ReadProcessMemory(ProcessHandle, 
#ifdef _WIN64
                (ULONG_PTR)LdrDataTableEntry + (bWow64Process ? LdrDataTableEntry_DllBase32 : LdrDataTableEntry_DllBase64),
#else
                (ULONG_PTR)LdrDataTableEntry + LdrDataTableEntry_DllBase32, 
#endif
                &DllBase, 
                SizeOfPointer, 
                NULL) == FALSE)
            return Size;
        
        if (DllBase != hModule)
            continue;

#ifdef _WIN64
        size_t SizeOfUnicodeString = bWow64Process ? sizeof(UNICODE_STRING32) : sizeof(UNICODE_STRING64);
#else
        size_t SizeOfUnicodeString = sizeof(UNICODE_STRING);
#endif
        BYTE *UnicodeString = calloc(1, SizeOfUnicodeString);

        if (ReadProcessMemory(ProcessHandle, 
                (ULONG_PTR)LdrDataTableEntry + NameOffset, 
                UnicodeString, 
                SizeOfUnicodeString, 
                NULL) == FALSE)
            return Size;

        ZeroMemory(lpFilename, nSize + 2);

        if (ReadProcessMemory(ProcessHandle, 
#ifdef _WIN64
                bWow64Process ? ((UNICODE_STRING32 *)UnicodeString)->Buffer : ((UNICODE_STRING64 *)UnicodeString)->Buffer, 
                lpFilename, 
                bWow64Process ? ((UNICODE_STRING32 *)UnicodeString)->Length <= nSize ? ((UNICODE_STRING32 *)UnicodeString)->Length : nSize : ((UNICODE_STRING64 *)UnicodeString)->Length <= nSize ? ((UNICODE_STRING64 *)UnicodeString)->Length : nSize, 
#else
                ((UNICODE_STRING32 *)UnicodeString)->Buffer,
                lpFilename,
                ((UNICODE_STRING32 *)UnicodeString)->Length <= nSize ? ((UNICODE_STRING32 *)UnicodeString)->Length : nSize,
#endif
                &Size) == FALSE && IFREE(UnicodeString))
            return Size;

        free(UnicodeString);
        break;
    }

    return Size;
}

FARPROC GetRemoteProcAddress(HANDLE ProcessHandle, HMODULE hModule, LPCSTR lpProcName)
{
#ifdef _WIN64
    BOOL bWow64Process;
    IsWow64Process(ProcessHandle, &bWow64Process);
    size_t SizeOfPointer = bWow64Process ? 4 : 8;
#else
    size_t SizeOfPointer = 4;
#endif
    FARPROC Proc = NULL;
    ULONG_PTR ImageBase = hModule;
    IMAGE_DOS_HEADER DOS;

    if (ReadProcessMemory(ProcessHandle, hModule, &DOS, sizeof(IMAGE_DOS_HEADER), NULL) == FALSE)
        return Proc;
#ifdef _WIN64
    BYTE *NT = malloc(bWow64Process ? sizeof(IMAGE_NT_HEADERS32) : sizeof(IMAGE_NT_HEADERS64));
#else
    IMAGE_NT_HEADERS32 *NT = malloc(sizeof(IMAGE_NT_HEADERS32));
#endif

    if (ReadProcessMemory(ProcessHandle, ImageBase + DOS.e_lfanew, NT, _msize(NT), NULL) == FALSE && IFREE(NT))
        return Proc;

    if (
#ifdef _WIN64
        (bWow64Process ? 
        ((IMAGE_NT_HEADERS32 *)NT)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress 
        :
        ((IMAGE_NT_HEADERS64 *)NT)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) 
#else
        NT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
#endif
         == NULL && IFREE(NT))
        return Proc;

    IMAGE_EXPORT_DIRECTORY EXPORT;

    if (ReadProcessMemory(ProcessHandle, 
            ImageBase 
            + 
#ifdef _WIN64
            (bWow64Process ? 
            ((IMAGE_NT_HEADERS32 *)NT)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress 
            :
            ((IMAGE_NT_HEADERS64 *)NT)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress), 
#else
            NT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, 
#endif
            &EXPORT, 
            sizeof(IMAGE_EXPORT_DIRECTORY), 
            NULL) == FALSE && IFREE(NT))
        return Proc;

    free(NT);

    for (DWORD i = 0; i < EXPORT.NumberOfNames; i++)
    {
        ULONG64 FunctionName = 0;
        char ch;

        if (ReadProcessMemory(ProcessHandle, ImageBase + EXPORT.AddressOfNames + i * 4, &FunctionName, 4, NULL) == FALSE)
            return Proc;
        
        FunctionName += ImageBase;

        for (DWORD j = 0; ReadProcessMemory(ProcessHandle, FunctionName + j, &ch, 1, NULL); j++)
        {
            if (ch != *(lpProcName + j))
                break;

            if (ch == NULL && *(lpProcName + j) == NULL)
            {
                WORD Ordinal;
                if (ReadProcessMemory(ProcessHandle, ImageBase + EXPORT.AddressOfNameOrdinals + i * 2, &Ordinal, sizeof(WORD), NULL) == FALSE)
                    return Proc;

                if (ReadProcessMemory(ProcessHandle, ImageBase + EXPORT.AddressOfFunctions + Ordinal * 4, &Proc, 4, NULL) == FALSE)
                    return Proc;

                Proc = (ULONG_PTR)Proc + ImageBase;
                break;
            }
            else if (ch == NULL || *(lpProcName + j) == NULL)
                break;
        }

        if (Proc)
            break;
    }

    return Proc;
}