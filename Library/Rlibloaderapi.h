#pragma once

#ifndef _RLIBLOADERAPI_H_
#define _RLIBLOADERAPI_H_

#include <malloc.h>
#include <windows.h>
#include <winternl.h>

#pragma comment (lib, "ntdll.lib")

#define Peb_LdrOffset32                 0x0C
#define Peb_LdrOffset64                 0x18
#define PebLdrData_LOMLOffset32         0x0C
#define PebLdrData_LOMLOffset64         0x10
#define LdrDataTableEntry_DllBase32     0x18
#define LdrDataTableEntry_DllBase64     0x30
#define LdrDatatableEntry_FullDllName32 0x24
#define LdrDatatableEntry_FullDllName64 0x48
#define LdrDataTableEntry_BaseDllName32 0x2C
#define LdrDataTableEntry_BaseDllName64 0x58
#define IFREE(HeapBase)                 (RtlFreeHeap(_get_heap_handle(), 0, (HeapBase)) || 1)
#define TERNARY(Condition, True, False) (Condition ? True : False)

#pragma pack(push, 4)
typedef struct _UNICODE_STRING32
{
    USHORT Length;
    USHORT MaximumLength;
    ULONG32 Buffer;
} UNICODE_STRING32, *PUNICODE_STRING32;
#pragma pack(pop)

#ifdef _WIN64
typedef struct _UNICODE_STRING64 {
    USHORT Length;
    USHORT MaximumLength;
    ULONG64 Buffer;
} UNICODE_STRING64, *PUNICODE_STRING64;
#endif

PVOID GetRemotePeb(HANDLE ProcessHandle);
HMODULE GetRemoteModuleHandleA(HANDLE ProcessHandle, LPCSTR lpModuleName);
HMODULE GetRemoteModuleHandleW(HANDLE ProcessHandle, LPCWSTR lpModuleName);
DWORD GetRemoteModuleFileNameA(HANDLE ProcessHandle, HMODULE hModule, LPSTR lpFilename, DWORD nSize);
DWORD GetRemoteModuleFileNameW(HANDLE ProcessHandle, HMODULE hModule, LPWSTR lpFilename, DWORD nSize);
DWORD GetRemoteModuleBaseNameA(HANDLE ProcessHandle, HMODULE hModule, LPSTR lpFilename, DWORD nSize);
DWORD GetRemoteModuleBaseNameW(HANDLE ProcessHandle, HMODULE hModule, LPWSTR lpFilename, DWORD nSize);
DWORD GetRemoteModuleName(HANDLE ProcessHandle, HMODULE hModule, LPWSTR lpFilename, DWORD nSize, BOOL bBaseName);
FARPROC GetRemoteProcAddress(HANDLE ProcessHandle, HMODULE hModule, LPCSTR lpProcName);

#endif