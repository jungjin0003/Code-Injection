#include <stdio.h>
#include <windows.h>
#include <winternl.h>

#define IFREE(HeapBase) (RtlFreeHeap(_get_heap_handle(), 0, (HeapBase)) || 1)
#define Upper(s1)       (s1 >= 65 && s1 <= 90 ? (char)s1 + 32 : s1)

WINBOOL CodePatch(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize)
{
    SIZE_T lpNumberOfBytesWritten = 0;
    return WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, &lpNumberOfBytesWritten) && nSize == lpNumberOfBytesWritten;
}

LPVOID FindIATAddress(HANDLE hProcess, LPCSTR lpModuleName, LPCSTR lpProcName)
{
    PROCESS_BASIC_INFORMATION pbi = { 0, };
    // Get target process PEB address using NtQueryInformationProcess
    NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);
    
    PVOID BaseAddress;
    // Read target process ImageBase from PEB
    if (ReadProcessMemory(hProcess, (ULONG_PTR)pbi.PebBaseAddress + 0x10, &BaseAddress, sizeof(ULONG_PTR), NULL) == FALSE)
    {
        return NULL;
    }

    IMAGE_DOS_HEADER *DOS = malloc(sizeof(IMAGE_DOS_HEADER));
    // Read(Copy) IMAGE_DOS_HEADER of target process
    if (ReadProcessMemory(hProcess, BaseAddress, DOS, sizeof(IMAGE_DOS_HEADER), NULL) == FALSE && IFREE(DOS))
    {
        return NULL;
    }

    IMAGE_NT_HEADERS *NT = malloc(sizeof(IMAGE_NT_HEADERS));
    // Read(Copy) IMAGE_NT_HEADERS of target process
    if (ReadProcessMemory(hProcess, (ULONG_PTR)BaseAddress + DOS->e_lfanew, NT, sizeof(IMAGE_NT_HEADERS), NULL) == FALSE && IFREE(DOS) && IFREE(NT))
    {
        return NULL;
    }

    free(DOS);

    IMAGE_IMPORT_DESCRIPTOR *IMPORT = malloc(NT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
    PVOID *FirstImport = IMPORT;
    // Read(Copy) IMAGE_IMPORT_DESCRIPTOR of target process to size
    if (ReadProcessMemory(hProcess, (ULONG_PTR)BaseAddress + NT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, IMPORT, NT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size, NULL) == FALSE && IFREE(NT) && IFREE(IMPORT))
    {
        return NULL;
    }

    free(NT);
    // Search IMAGE_IMPORT_DESCRIPTOR of target dll
    for (; IMPORT->OriginalFirstThunk != NULL; IMPORT++)
    {
        // Compare dll name of current IMAGE_IMPORT_DESCRIPTOR to target dll name
        for (char ch, i = 0; ReadProcessMemory(hProcess, (ULONG_PTR)BaseAddress + IMPORT->Name + i, &ch, 1, NULL); i++)
        {
            if (Upper(ch) != Upper(lpModuleName[i]))
                break;
            else if (ch == NULL && lpModuleName[i] == NULL)
                goto FOUND_MODULE;
        }
        continue;
FOUND_MODULE:
        break;
    }

    if (IMPORT->OriginalFirstThunk == NULL)
        return NULL;

    PVOID IATAddress = NULL;

    IMAGE_THUNK_DATA *THUNK = malloc(sizeof(IMAGE_THUNK_DATA));
    // Search iat address of target API
    for (int i = 0; ReadProcessMemory(hProcess, (ULONG_PTR)BaseAddress + IMPORT->OriginalFirstThunk + i * sizeof(void *), THUNK, sizeof(IMAGE_THUNK_DATA), NULL) && THUNK->u1.AddressOfData != NULL; i++)
    {
        if (THUNK->u1.Ordinal >= 0x80000000)
            continue;
        // Compare api name of current IMPORT->OriginalFirstThunk to target api name
        for (char ch, j = 0; ReadProcessMemory(hProcess, (ULONG_PTR)BaseAddress + THUNK->u1.AddressOfData + j + 2, &ch, 1, NULL); j++)
        {
            if (ch != lpProcName[j])
                break;
            else if (ch == NULL && lpProcName[j] == NULL)
            {
                IATAddress = (ULONG_PTR)BaseAddress + IMPORT->FirstThunk + i * sizeof(void *);
                goto FOUND_IAT;
            }
        }
    }
FOUND_IAT:
    free(THUNK);
    free(FirstImport);
    return IATAddress;
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
    // 0x1122334455667788 is code patched to original MessageBoxA address after Code Injection
    volatile int (WINAPI *OriMessageBox)(HWND, LPCSTR, LPCSTR, UINT) = 0x1122334455667788;
    // Use the code below to enable this feature on x86 systems
    // volatile int (WINAPI *OriMessageBox)(HWND, LPCSTR, LPCSTR, UINT) = 0x11223344; 

    // Manipulate lpText parameter
    return OriMessageBox(hWnd, Text, lpCaption, uType);
}

BOOL IAT_Hook(HANDLE hProcess, LPCSTR lpModuleName, LPCSTR lpProcName, PVOID lpNewApiAddress, SIZE_T NewApiSize)
{
    SIZE_T NumberOfBytesRead;
    // Code Injection of NewAPI(HOOK Function)
    PVOID NewApiAddress = CodeInjection(hProcess, lpNewApiAddress, NewApiSize);

    if (NewApiAddress == NULL)
        return FALSE;
    // Find IAT address of target api
    PVOID IATAddress = FindIATAddress(hProcess, lpModuleName, lpProcName);

    if (IATAddress == NULL)
    {
        VirtualFreeEx(hProcess, NewApiAddress, 0, MEM_DECOMMIT);
        VirtualFreeEx(hProcess, NewApiAddress, 0, MEM_RELEASE);
        return FALSE;
    }
    
    PVOID OriAPIAddress = NULL;
    // Read original api address from IAT
    if (ReadProcessMemory(hProcess, IATAddress, &OriAPIAddress, sizeof(PVOID), &NumberOfBytesRead) == FALSE || NumberOfBytesRead != 8)
    {
        VirtualFreeEx(hProcess, NewApiAddress, 0, MEM_DECOMMIT);
        VirtualFreeEx(hProcess, NewApiAddress, 0, MEM_RELEASE);
        return FALSE;
    }
    // Code patch 0xFFFFFFFFFFFFFFFF in new api
    if (CodePatch(hProcess, (ULONG_PTR)NewApiAddress + SearchCodePatchOffset(NewMessageBoxA, NewApiSize), &OriAPIAddress, sizeof(ULONG_PTR)) == FALSE)
    {
        VirtualFreeEx(hProcess, NewApiAddress, 0, MEM_DECOMMIT);
        VirtualFreeEx(hProcess, NewApiAddress, 0, MEM_RELEASE);
        return FALSE;
    }
    // IAT code patch of target process
    if (CodePatch(hProcess, IATAddress, &NewApiAddress, sizeof(ULONG_PTR)) == FALSE)
    {
        VirtualFreeEx(hProcess, NewApiAddress, 0, MEM_DECOMMIT);
        VirtualFreeEx(hProcess, NewApiAddress, 0, MEM_RELEASE);
        return FALSE;
    }
    // IAT Hooking success!!
    return TRUE;
}

int main(int argc, char *argv[])
{
    DWORD PID = 0;
    printf("PID : ");
    scanf("%d", &PID);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (IAT_Hook(hProcess, "user32.dll", "MessageBoxA", NewMessageBoxA, (ULONG_PTR)IAT_Hook - (ULONG_PTR)NewMessageBoxA))
    {
        printf("IAT Hooking Success\n");
    }
    else
    {
        printf("IAT Hooking Failed\n");
    }
}