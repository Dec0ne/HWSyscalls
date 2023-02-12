#include "HWSyscalls.h"

#pragma region GlobalVariables

PVOID exceptionHandlerHandle;
HANDLE myThread;
HANDLE hNtdll;
UINT64 ntFunctionAddress;
UINT64 k32FunctionAddress;
UINT64 retGadgetAddress;
UINT64 stackArgs[STACK_ARGS_LENGTH];
UINT64 callRegGadgetAddress;
UINT64 callRegGadgetAddressRet;
char callRegGadgetValue;
UINT64 regBackup;

#pragma endregion

#pragma region BinaryPatternMatching
// @janoglezcampos, @idov31 - https://github.com/Idov31/Cronos/blob/master/src/Utils.c

BOOL MaskCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
{
    for (; *szMask; ++szMask, ++pData, ++bMask)
        if (*szMask == 'x' && *pData != *bMask)
            return FALSE;
    return TRUE;
}

DWORD_PTR FindPattern(DWORD_PTR dwAddress, DWORD dwLen, PBYTE bMask, PCHAR szMask)
{
    for (DWORD i = 0; i < dwLen; i++)
        if (MaskCompare((PBYTE)(dwAddress + i), bMask, szMask))
            return (DWORD_PTR)(dwAddress + i);

    return 0;
}

DWORD_PTR FindInModule(LPCSTR moduleName, PBYTE bMask, PCHAR szMask)
{
    DWORD_PTR dwAddress = 0;
    PIMAGE_DOS_HEADER imageBase = (PIMAGE_DOS_HEADER)GetModuleHandleA(moduleName);

    if (!imageBase)
        return 0;

    DWORD_PTR sectionOffset = (DWORD_PTR)imageBase + imageBase->e_lfanew + sizeof(IMAGE_NT_HEADERS);

    if (!sectionOffset)
        return 0;

    PIMAGE_SECTION_HEADER textSection = (PIMAGE_SECTION_HEADER)(sectionOffset);
    dwAddress = FindPattern((DWORD_PTR)imageBase + textSection->VirtualAddress, textSection->SizeOfRawData, bMask, szMask);
    return dwAddress;
}

#pragma endregion

#pragma region PEBGetProcAddress

UINT64 GetModuleAddress(LPWSTR moduleName) {
    PPEB peb = (PPEB)__readgsqword(X64_PEB_OFFSET);
    LIST_ENTRY* ModuleList = NULL;

    if (!moduleName)
        return 0;

    for (LIST_ENTRY* pListEntry = peb->LoaderData->InMemoryOrderModuleList.Flink;
        pListEntry != &peb->LoaderData->InMemoryOrderModuleList;
        pListEntry = pListEntry->Flink) {

        PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        if (wcsstr(pEntry->FullDllName.Buffer, moduleName)) {
            return (UINT64)pEntry->DllBase;
        }
    }
    return 0;
}

UINT64 GetSymbolAddress(UINT64 moduleBase, const char* functionName) {
    UINT64 functionAddress = 0;
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;

    // Checking that the image is valid PE file.
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(moduleBase + dosHeader->e_lfanew);

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return functionAddress;
    }

    IMAGE_OPTIONAL_HEADER optionalHeader = ntHeaders->OptionalHeader;

    if (optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0) {
        return functionAddress;
    }

    // Iterating the export directory.
    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)(moduleBase + optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* addresses = (DWORD*)(moduleBase + exportDirectory->AddressOfFunctions);
    WORD* ordinals = (WORD*)(moduleBase + exportDirectory->AddressOfNameOrdinals);
    DWORD* names = (DWORD*)(moduleBase + exportDirectory->AddressOfNames);

    for (DWORD j = 0; j < exportDirectory->NumberOfNames; j++) {
        if (_stricmp((char*)(moduleBase + names[j]), functionName) == 0) {
            functionAddress = moduleBase + addresses[ordinals[j]];
            break;
        }
    }

    return functionAddress;
}

#pragma endregion

#pragma region HalosGate

DWORD64 FindSyscallNumber(DWORD64 functionAddress) {
    // @sektor7 - RED TEAM Operator: Windows Evasion course - https://blog.sektor7.net/#!res/2021/halosgate.md
    WORD syscallNumber = 0;

    for (WORD idx = 1; idx <= 500; idx++) {
        // check neighboring syscall down
        if (*((PBYTE)functionAddress + idx * DOWN) == 0x4c
            && *((PBYTE)functionAddress + 1 + idx * DOWN) == 0x8b
            && *((PBYTE)functionAddress + 2 + idx * DOWN) == 0xd1
            && *((PBYTE)functionAddress + 3 + idx * DOWN) == 0xb8
            && *((PBYTE)functionAddress + 6 + idx * DOWN) == 0x00
            && *((PBYTE)functionAddress + 7 + idx * DOWN) == 0x00) {
            BYTE high = *((PBYTE)functionAddress + 5 + idx * DOWN);
            BYTE low = *((PBYTE)functionAddress + 4 + idx * DOWN);

            syscallNumber = (high << 8) | low - idx;
            DEBUG_PRINT("[+] Found SSN: 0x%X\n", syscallNumber);
            break;
        }

        // check neighboring syscall up
        if (*((PBYTE)functionAddress + idx * UP) == 0x4c
            && *((PBYTE)functionAddress + 1 + idx * UP) == 0x8b
            && *((PBYTE)functionAddress + 2 + idx * UP) == 0xd1
            && *((PBYTE)functionAddress + 3 + idx * UP) == 0xb8
            && *((PBYTE)functionAddress + 6 + idx * UP) == 0x00
            && *((PBYTE)functionAddress + 7 + idx * UP) == 0x00) {
            BYTE high = *((PBYTE)functionAddress + 5 + idx * UP);
            BYTE low = *((PBYTE)functionAddress + 4 + idx * UP);

            syscallNumber = (high << 8) | low + idx;
            DEBUG_PRINT("[+] Found SSN: 0x%X\n", syscallNumber);
            break;
        }

    }

    if (syscallNumber == 0)
        DEBUG_PRINT("[-] Could not find SSN\n");

    return syscallNumber;
}

DWORD64 FindSyscallReturnAddress(DWORD64 functionAddress, WORD syscallNumber) {
    // @sektor7 - RED TEAM Operator: Windows Evasion course - https://blog.sektor7.net/#!res/2021/halosgate.md
    DWORD64 syscallReturnAddress = 0;

    for (WORD idx = 1; idx <= 32; idx++) {
        if (*((PBYTE)functionAddress + idx) == 0x0f && *((PBYTE)functionAddress + idx + 1) == 0x05) {
            syscallReturnAddress = (DWORD64)((PBYTE)functionAddress + idx);
            DEBUG_PRINT("[+] Found \"syscall;ret;\" opcode address: 0x%I64X\n", syscallReturnAddress);
            break;
        }
    }

    if (syscallReturnAddress == 0)
        DEBUG_PRINT("[-] Could not find \"syscall;ret;\" opcode address\n");

    return syscallReturnAddress;
}

#pragma endregion

UINT64 PrepareSyscall(char* functionName) {
    return k32FunctionAddress;
}

bool SetMainBreakpoint() {
    // Dynamically find the GetThreadContext and SetThreadContext functions
    GetThreadContext_t pGetThreadContext = (GetThreadContext_t)GetSymbolAddress(GetModuleAddress((LPWSTR)L"KERNEL32.DLL"), "GetThreadContext");
    SetThreadContext_t pSetThreadContext = (SetThreadContext_t)GetSymbolAddress(GetModuleAddress((LPWSTR)L"KERNEL32.DLL"), "SetThreadContext");

    DWORD old = 0;

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_ALL;

    // Get current thread context
    pGetThreadContext(myThread, &ctx);
    
    // Set hardware breakpoint on PrepareSyscall function
    ctx.Dr0 = (UINT64)&PrepareSyscall;
    ctx.Dr7 |= (1 << 0);
    ctx.Dr7 &= ~(1 << 16);
    ctx.Dr7 &= ~(1 << 17);
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    // Apply the modified context to the current thread
    if (!pSetThreadContext(myThread, &ctx)) {
        DEBUG_PRINT("[-] Could not set new thread context: 0x%X", GetLastError());
        return false;
    }

    return true;
}

LONG HWSyscallExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        if (ExceptionInfo->ContextRecord->Rip == (DWORD64)&PrepareSyscall) {
            DEBUG_PRINT("\n===============HWSYSCALLS DEBUG===============");
            DEBUG_PRINT("\n[+] PrepareSyscall Breakpoint Hit (%#llx)!\n", ExceptionInfo->ExceptionRecord->ExceptionAddress);
            
            // Find the address of the syscall function in ntdll we got as the first argument of the PrepareSyscall function
            ntFunctionAddress = GetSymbolAddress((UINT64)hNtdll, (const char*)(ExceptionInfo->ContextRecord->Rcx));
            DEBUG_PRINT("[+] Found %s address: 0x%I64X\n", (const char*)(ExceptionInfo->ContextRecord->Rcx), ntFunctionAddress);
            
            // Move breakpoint to the kernel32 function to be used as a proxy function before the syscall;
            DEBUG_PRINT("[+] Moving breakpoint to Kernel32 proxy function: 0x%I64X\n", k32FunctionAddress);
            ExceptionInfo->ContextRecord->Dr0 = k32FunctionAddress;
        }
        else if (ExceptionInfo->ContextRecord->Rip == (DWORD64)k32FunctionAddress) {
            DEBUG_PRINT("[+] Kernel32 Proxy Function Breakpoint Hit (%#llx)!\n", (DWORD64)ExceptionInfo->ExceptionRecord->ExceptionAddress);
            
            // Zeroing out the stackArgs array
            memset(stackArgs, 0, sizeof(UINT64) * STACK_ARGS_LENGTH);

            // Saving the stack arguments to stackArgs array to be restored after the "call rax;" gadget call
            for (size_t idx = 0; idx < STACK_ARGS_LENGTH; idx++)
            {
                const size_t offset = idx * STACK_ARGS_LENGTH + STACK_ARGS_RSP_OFFSET;
                stackArgs[idx] = *(PULONG64)(ExceptionInfo->ContextRecord->Rsp + offset);
            }
            DEBUG_PRINT("[+] Saved stack arguments\n");

            // Save CallRegGadget register value to be restored after the "call rax;" gadget call
            // Set the value of the appropriate register to point to the syscall function in ntdll
            DEBUG_PRINT("[+] Setting REGISTER value to NTAPI function address: 0x%I64X\n", ntFunctionAddress);
            switch (callRegGadgetValue)
            {
            case (char)CallRegGadgetEnum::CallRegGadget::Rax:
                regBackup = ExceptionInfo->ContextRecord->Rax;
                ExceptionInfo->ContextRecord->Rax = ntFunctionAddress;
                break;
            case (char)CallRegGadgetEnum::CallRegGadget::Rcx:
                regBackup = ExceptionInfo->ContextRecord->Rcx;
                ExceptionInfo->ContextRecord->Rcx = ntFunctionAddress;
                break;
            case (char)CallRegGadgetEnum::CallRegGadget::Rdx:
                regBackup = ExceptionInfo->ContextRecord->Rdx;
                ExceptionInfo->ContextRecord->Rdx = ntFunctionAddress;
                break;
            case (char)CallRegGadgetEnum::CallRegGadget::Rbx:
                regBackup = ExceptionInfo->ContextRecord->Rbx;
                ExceptionInfo->ContextRecord->Rbx = ntFunctionAddress;
                break;
            case (char)CallRegGadgetEnum::CallRegGadget::Rsi:
                regBackup = ExceptionInfo->ContextRecord->Rsi;
                ExceptionInfo->ContextRecord->Rsi = ntFunctionAddress;
                break;
            case (char)CallRegGadgetEnum::CallRegGadget::Rdi:
                regBackup = ExceptionInfo->ContextRecord->Rdi;
                ExceptionInfo->ContextRecord->Rdi = ntFunctionAddress;
                break;
            default:
                break;
            }
            
            // Move breakpoint to the syscall function in ntdll;
            DEBUG_PRINT("[+] Moving breakpoint to NTAPI function: 0x%I64X\n", ntFunctionAddress);
            ExceptionInfo->ContextRecord->Dr0 = ntFunctionAddress;

            // Change RIP to jump to the "call REGISTER;" gadget
            DEBUG_PRINT("[+] Jumping to \"call REGISTER;\" gadget address: 0x%I64x\n", callRegGadgetAddress);
            ExceptionInfo->ContextRecord->Rip = callRegGadgetAddress;

        }
        else if (ExceptionInfo->ContextRecord->Rip == (DWORD64)ntFunctionAddress) {
            DEBUG_PRINT("[+] NTAPI Function Breakpoint Hit (%#llx)!\n", (DWORD64)ExceptionInfo->ExceptionRecord->ExceptionAddress);

            // Restore stack arguments from stackArgs array
            for (size_t idx = 0; idx < STACK_ARGS_LENGTH; idx++)
            {
                const size_t offset = idx * STACK_ARGS_LENGTH + STACK_ARGS_RSP_OFFSET;
                *(PULONG64)(ExceptionInfo->ContextRecord->Rsp + offset) = stackArgs[idx];
            }

            // Restore CallRegGadget register
            switch (callRegGadgetValue)
            {
            case (char)CallRegGadgetEnum::CallRegGadget::Rax:
                ExceptionInfo->ContextRecord->Rax = regBackup;
                break;
            case (char)CallRegGadgetEnum::CallRegGadget::Rcx:
                ExceptionInfo->ContextRecord->Rcx = regBackup;
                break;
            case (char)CallRegGadgetEnum::CallRegGadget::Rdx:
                ExceptionInfo->ContextRecord->Rdx = regBackup;
                break;
            case (char)CallRegGadgetEnum::CallRegGadget::Rbx:
                ExceptionInfo->ContextRecord->Rbx = regBackup;
                break;
            case (char)CallRegGadgetEnum::CallRegGadget::Rsi:
                ExceptionInfo->ContextRecord->Rsi = regBackup;
                break;
            case (char)CallRegGadgetEnum::CallRegGadget::Rdi:
                ExceptionInfo->ContextRecord->Rdi = regBackup;
                break;
            default:
                break;
            }
            DEBUG_PRINT("[+] Restored stack arguments and REGISTER value\n");

            DWORD64 pFunctionAddress = ExceptionInfo->ContextRecord->Rip;

            char nonHookedSyscallBytes[] = { 0x4C,0x8B,0xD1,0xB8 };
            if (FindPattern(pFunctionAddress, 4, (PBYTE)nonHookedSyscallBytes, (PCHAR)"xxxx")) {
                DEBUG_PRINT("[+] Function is not hooked\n");
                DEBUG_PRINT("[+] Continuing with normal execution\n");
            }
            else {
                DEBUG_PRINT("[+] Function is HOOKED!\n");
                DEBUG_PRINT("[+] Looking for the SSN via Halos Gate\n");

                WORD syscallNumber = FindSyscallNumber(pFunctionAddress);

                if (syscallNumber == 0) {
                    ExceptionInfo->ContextRecord->Dr0 = callRegGadgetAddressRet;
                    return EXCEPTION_CONTINUE_EXECUTION;
                }

                DWORD64 syscallReturnAddress = FindSyscallReturnAddress(pFunctionAddress, syscallNumber);

                if (syscallReturnAddress == 0) {
                    ExceptionInfo->ContextRecord->Dr0 = callRegGadgetAddressRet;
                    return EXCEPTION_CONTINUE_EXECUTION;
                }

                // mov r10, rcx
                DEBUG_PRINT("[+] Moving RCX to R10 (mov r10, rcx)\n");
                ExceptionInfo->ContextRecord->R10 = ExceptionInfo->ContextRecord->Rcx;
                //mov eax, SSN
                DEBUG_PRINT("[+] Moving SSN to RAX (mov rax, 0x%X)\n", syscallNumber);
                ExceptionInfo->ContextRecord->Rax = syscallNumber;
                //Set RIP to syscall;ret; opcode address
                DEBUG_PRINT("[+] Jumping to \"syscall;ret;\" opcode address: 0x%I64X\n", syscallReturnAddress);
                ExceptionInfo->ContextRecord->Rip = syscallReturnAddress;

            }

            // Move breakpoint to callRegGadgetAddressRet so we can catch the execution once the syscall has finished
            DEBUG_PRINT("[+] Moving breakpoint to callRaxGadgetAddressRet to catch the return from NTAPI function: 0x%I64X\n", callRegGadgetAddressRet);
            ExceptionInfo->ContextRecord->Dr0 = callRegGadgetAddressRet;

        }
        else if (ExceptionInfo->ContextRecord->Rip == (DWORD64)callRegGadgetAddressRet) {
            DEBUG_PRINT("[+] callRegGadgetAddressRet Breakpoint Hit (%#llx)!\n", (DWORD64)ExceptionInfo->ExceptionRecord->ExceptionAddress);
            
            // Move breakpoint back to PrepareSyscall to catch the next invoke
            DEBUG_PRINT("[+] Moving breakpoint back to PrepareSyscall to catch the next invoke\n");
            ExceptionInfo->ContextRecord->Dr0 = (UINT64)&PrepareSyscall;

            // Change RIP to jump to the "ret;" gadget
            DEBUG_PRINT("[+] Jumping to \"ret;\" gadget address: 0x%I64X\n", retGadgetAddress);
            ExceptionInfo->ContextRecord->Rip = retGadgetAddress;

            DEBUG_PRINT("==============================================\n\n");

        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

bool FindCallRegGadget() {
    char buffer[2] = {0xFF, 0x00};

    // Dynamically search for a suitable "CALL REGISTER" gadget in both kernel32 and kernelbase
    if (callRegGadgetValue == 0) {
        for (CallRegGadgetEnum::CallRegGadget e : CallRegGadgetEnum::All) {
            buffer[1] = (char)e;
            callRegGadgetAddress = FindInModule("KERNEL32.DLL", (PBYTE)buffer, (PCHAR)"xx");
            if (callRegGadgetAddress != 0) {
                callRegGadgetValue = (char)e;
                return true;
            }
            else {
                callRegGadgetAddress = FindInModule("kernelbase.dll", (PBYTE)buffer, (PCHAR)"xx");
                if (callRegGadgetAddress != 0) {
                    callRegGadgetValue = (char)e;
                    return true;
                }
            }
        }
    }
    return false;
}

bool InitHWSyscalls() {
    myThread = GetCurrentThread();
    hNtdll = (HANDLE)GetModuleAddress((LPWSTR)L"ntdll.dll");

    // Find Kernel32 proxy function address
    k32FunctionAddress = GetSymbolAddress(GetModuleAddress((LPWSTR)L"KERNEL32.DLL"), "GetCalendarInfoA");

    // Find a suitable "CALL REGISTER" gadget
    if (!FindCallRegGadget()) {
        DEBUG_PRINT("[!] Could not find a suitable \"CALL REGISTER\" gadget in kernel32 or kernelbase. InitHWSyscalls failed.");
        return false;
    }

    callRegGadgetAddressRet = (UINT64)((char*)callRegGadgetAddress + 2);
    retGadgetAddress = FindInModule("KERNEL32.DLL", (PBYTE)"\xC3", (PCHAR)"x");

    // Register exception handler
    exceptionHandlerHandle = AddVectoredExceptionHandler(1, &HWSyscallExceptionHandler);

    if (!exceptionHandlerHandle)
        return false;

    return SetMainBreakpoint();
}

bool DeinitHWSyscalls() {
    return RemoveVectoredExceptionHandler(exceptionHandlerHandle) != 0;
}
