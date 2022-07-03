#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include "../Library/Rlibloaderapi.h"

WINBOOL CodePatch(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize)
{
    SIZE_T lpNumberOfBytesWritten = 0;
    return WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, &lpNumberOfBytesWritten) && nSize == lpNumberOfBytesWritten;
}

PVOID CodeInjection(HANDLE hProcess, PVOID lpBuffer, SIZE_T nSize)
{
    // Allocate memory in target process
    PVOID BufferAddress = VirtualAllocEx(hProcess, NULL, nSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (BufferAddress == NULL)
    {
        return NULL;
    }

    SIZE_T NumberOfBytesWritten;

    // Write the lpBuffer in allocated memory
    if (WriteProcessMemory(hProcess, BufferAddress, lpBuffer, nSize, &NumberOfBytesWritten) == FALSE || nSize > NumberOfBytesWritten)
    {
        VirtualFreeEx(hProcess, BufferAddress, 0, MEM_DECOMMIT);
        VirtualFreeEx(hProcess, BufferAddress, 0, MEM_RELEASE);
        return NULL;
    }

    return BufferAddress;
}

DWORD SearchCodePatchOffset(PVOID lpFunctionAddress, SIZE_T FunctionSize)
{
    for (int i = 0; i < FunctionSize - 8; i++)
    {
        // x86
        if (__SIZEOF_POINTER__ == 4 && *(ULONG_PTR *)((ULONG_PTR)lpFunctionAddress + i) == 0x11223344)
            return i;
        // x64
        else if (__SIZEOF_POINTER__ == 8 && *(ULONG_PTR *)((ULONG_PTR)lpFunctionAddress + i) == 0x1122334455667788)
            return i;
    }

    return -1;
}

int WINAPI NewMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    /*
    An error occurs in the following ways:
    return OriMessageBox(hWnd, "Hooked..!", lpCaption. uType);
    The compiled "Hooked..!" in this code points to a section of the process with a pointer, 
    so another process Occur EXCEPTION_ACCESS_VIOLATION.
    Therefore, you must store all the strings in the stack.
    */
    // All strings should be used as follows
    char Text[] = "Hooked..!";

    // Top 12 Bytes of MessageBoxA in user32.dll
    BYTE OriginCode[12] = { 
        0x48, 0x83, 0xEC, 0x38,      // sub rsp, 0x38
        0x45, 0x33, 0xDB,            // xor r11d, r11d
        0x44, 0x39, 0x1D, 0x02, 0x61 // cmp dword ptr ds:[address], r11d
    };
    
    // Variables to back up hook code
    BYTE HookCode[12];
    
    // 0x11223344 is code patched to original MessageBoxA address after Code Injection
    volatile int (WINAPI *OriMessageBox)(HWND, LPCSTR, LPCSTR, UINT) = 0x1122334455667788;

    for (int i = 0; i < 12; i++)
    {
        // Backup hook code
        HookCode[i] = *(BYTE *)((ULONG_PTR)OriMessageBox + i);
        
        // Overwrite Top 12 Bytes of MessageBoxA to original code.
        // Trampoline(Inline) Hook code to Original code
        *(BYTE *)((ULONG_PTR)OriMessageBox + i) = OriginCode[i];
    }

    // call after Manipulate lpText parameter and save return value
    int ret = OriMessageBox(hWnd, Text, lpCaption, uType);

    // Overwrite with hook code again when function ends
    for (int i = 0; i < 12; i++)
        *(BYTE *)((ULONG_PTR)OriMessageBox + i) = HookCode[i];

    return ret;
}

BOOL Trampoline_Hook(HANDLE hProcess, LPCSTR lpModuleName, LPCSTR lpProcName, PVOID lpNewApiAddress, SIZE_T NewApiSize)
{
    SIZE_T NumberOfBytesRead;

    // Code Injection of NewAPI(HOOK Function)
    PVOID NewApiAddress = CodeInjection(hProcess, lpNewApiAddress, NewApiSize);

    if (NewApiAddress == NULL)
        return FALSE;

    // Find address of target api
    PVOID ProcAddress = GetRemoteProcAddress(hProcess, GetRemoteModuleHandleA(hProcess, lpModuleName), lpProcName);

    if (ProcAddress == NULL)
    {
        VirtualFreeEx(hProcess, NewApiAddress, 0, MEM_DECOMMIT);
        VirtualFreeEx(hProcess, NewApiAddress, 0, MEM_RELEASE);
        return FALSE;
    }

    DWORD OldProtect;

    // Change memory protection option of Top 12 byte of target api (PAGE_EXECUTE_READ to PAGE_EXECUTE_READWRITE)
    if (VirtualProtectEx(hProcess, ProcAddress, 12, PAGE_EXECUTE_READWRITE, &OldProtect) == FALSE)
    {
        VirtualFreeEx(hProcess, NewApiAddress, 0, MEM_DECOMMIT);
        VirtualFreeEx(hProcess, NewApiAddress, 0, MEM_RELEASE);
        return FALSE;
    }

    // Assembly Code (12Byte Indirect Jump)
    BYTE JmpCode[12] = { 
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 0x0000000000000000
        0xFF, 0xE0                                                  // jmp rax
    };

    // Set the NewApiAddress(Hook Address)
    *(ULONGLONG *)(JmpCode + 2) = (ULONG_PTR)NewApiAddress; 

    // Code patch 0x1122334455667788 in new api
    if (CodePatch(hProcess, (ULONG_PTR)NewApiAddress + SearchCodePatchOffset(NewMessageBoxA, NewApiSize), &ProcAddress, 8) == FALSE)
    {
        VirtualFreeEx(hProcess, NewApiAddress, 0, MEM_DECOMMIT);
        VirtualFreeEx(hProcess, NewApiAddress, 0, MEM_RELEASE);
        return FALSE;
    }

    // Top 12 bytes code patch of target process
    if (CodePatch(hProcess, ProcAddress, JmpCode, 12) == FALSE)
    {
        VirtualFreeEx(hProcess, NewApiAddress, 0, MEM_DECOMMIT);
        VirtualFreeEx(hProcess, NewApiAddress, 0, MEM_RELEASE);
        return FALSE;
    }

    // Trampline(Inline) Hooking success!!
    return TRUE;
}

int main(int argc, char *argv[])
{
    DWORD PID = 0;
    printf("PID : ");
    scanf("%d", &PID);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (Trampoline_Hook(hProcess, "user32.dll", "MessageBoxA", NewMessageBoxA, (ULONG_PTR)Trampoline_Hook - (ULONG_PTR)NewMessageBoxA))
        printf("Trampoline Hooking Success\n");
    else
        printf("Trampoline Hooking Failed\n");
}