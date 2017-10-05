/**
 * MIT License
 *
 * Copyright (c) 2017 Rokas Kupstys
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#pragma once

#include <winsock2.h>   // To make MingW happy
#include <windows.h>

#if __cplusplus
extern "C" {
#endif

void* pe_run(void* image, const wchar_t* host_executable_path, const wchar_t* environment, PROCESS_INFORMATION* result,
             HANDLE user_token);
void pe_resume(PROCESS_INFORMATION* information);
void pe_close(PROCESS_INFORMATION* information);

#ifdef RUNPE_IMPLEMENTATION
#include <stdint.h>
#include <shlobj.h>

#ifdef _DEBUG
#   include <stdio.h>
#   define LOG_DEBUG(msg, ...) fprintf(stderr, msg "\n", __VA_ARGS__)
#else
#   define LOG_DEBUG(msg, ...)
#endif

#ifndef IS_VALID_HANDLE
#   define IS_VALID_HANDLE(handle) (((size_t)(handle) + 1) > 1)
#endif

void* pe_run(void* image, const wchar_t* host_executable_path, const wchar_t* environment, PROCESS_INFORMATION* result,
             HANDLE user_token)
{
    if (!image)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }

    wchar_t host_path_auto[MAX_PATH];
    if (host_executable_path == 0)
    {
        SHGetFolderPathW(0, CSIDL_SYSTEM, NULL, SHGFP_TYPE_DEFAULT, host_path_auto);
        wcscat(host_path_auto, L"\\svchost.exe");
        host_executable_path = host_path_auto;
    }

    STARTUPINFO si;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(STARTUPINFO);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    if (user_token)
    {
        si.lpDesktop = (LPWSTR)L"winsta0\\default";
        if (!CreateProcessAsUser(user_token, host_executable_path, 0, 0, 0, FALSE,
            CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, (LPVOID)environment, 0, &si, result))
        {
            LOG_DEBUG("CreateProcessAsUser error=%d", GetLastError());
            return 0;
        }
    }
    else
    {
        if (!CreateProcess(host_executable_path, 0, 0, 0, FALSE,
            CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, (LPVOID)environment, 0, &si, result))
        {
            LOG_DEBUG("CreateProcess error=%d", GetLastError());
            return 0;
        }
    }

    HANDLE hProcess = result->hProcess;
    HANDLE hThread = result->hThread;
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_FULL;
    result->hProcess = 0;
    result->hThread = 0;

    if (!GetThreadContext(hThread, &ctx))
    {
        LOG_DEBUG("GetThreadContext error=%d", GetLastError());
        return 0;
    }

    // PEB->lpImageBaseAddress
#if _M_X64 || __amd64__
    PBYTE lpImageBaseAddress = (PBYTE)ctx.Rdx + 12;
#else
    PBYTE lpImageBaseAddress = (PBYTE)ctx.Ebx + 8;
#endif

    PVOID pBase = 0;
    if (!ReadProcessMemory(hProcess, lpImageBaseAddress, &pBase, sizeof(SIZE_T), 0))
    {
        LOG_DEBUG("ReadProcessMemory error=%d", GetLastError());
        return 0;
    }
    //ZwUnmapViewOfSection( hNewProc, pBase );	// with this some processes stop working

    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)image;
    PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)((PBYTE)(dos_header) + dos_header->e_lfanew);
    void* base_address = VirtualAllocEx(hProcess, (PVOID)(nt_header->OptionalHeader.ImageBase),
        nt_header->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!base_address)
    {
        LOG_DEBUG("VirtualAllocEx error=%d", GetLastError());
        VirtualFreeEx(hProcess, base_address, nt_header->OptionalHeader.SizeOfImage, MEM_RELEASE|MEM_DECOMMIT);
        return 0;
    }

    if (!WriteProcessMemory(hProcess, base_address, dos_header, nt_header->OptionalHeader.SizeOfHeaders, 0))
    {
        LOG_DEBUG("WriteProcessMemory error=%d", GetLastError());
        VirtualFreeEx(hProcess, base_address, nt_header->OptionalHeader.SizeOfImage, MEM_RELEASE|MEM_DECOMMIT);
        return 0;
    }
    size_t isMapped = 0;
    PIMAGE_SECTION_HEADER sect = IMAGE_FIRST_SECTION(nt_header);
    for (unsigned long i = 0; i < nt_header->FileHeader.NumberOfSections; i++)
    {
        if (!WriteProcessMemory(hProcess, (PCHAR)(base_address) + sect[i].VirtualAddress,
                                (PCHAR)(dos_header) + (isMapped ? sect[i].VirtualAddress : sect[i].PointerToRawData),
                                sect[i].SizeOfRawData, 0))
        {
            LOG_DEBUG("WriteProcessMemory error=%d", GetLastError());
            VirtualFreeEx(hProcess, base_address, nt_header->OptionalHeader.SizeOfImage, MEM_RELEASE|MEM_DECOMMIT);
            return 0;
        }
    }
    if (!WriteProcessMemory(hProcess, lpImageBaseAddress, &base_address, sizeof(SIZE_T), 0))
    {
        LOG_DEBUG("WriteProcessMemory error=%d", GetLastError());
        VirtualFreeEx(hProcess, base_address, nt_header->OptionalHeader.SizeOfImage, MEM_RELEASE|MEM_DECOMMIT);
        return 0;
    }

    SIZE_T entry_point = (SIZE_T)(base_address) + nt_header->OptionalHeader.AddressOfEntryPoint;
#if _M_X64 || __amd64__
    ctx.Rcx = ctx.Rip = entry_point;
    ctx.SegGs = 0;
    ctx.SegFs = 0x53;
    ctx.SegEs = 0x2B;
    ctx.SegDs = 0x2B;
    ctx.SegSs = 0x2B;
    ctx.SegCs = 0x33;
    ctx.EFlags = 0x3000;
#else
    ctx.Eax = ctx.Eip = entry_point;
    ctx.SegGs = 0;
    ctx.SegFs = 0x38;
    ctx.SegEs = 0x20;
    ctx.SegDs = 0x20;
    ctx.SegSs = 0x20;
    ctx.SegCs = 0x18;
    ctx.EFlags = 0x3000;
#endif

    if (!SetThreadContext(hThread, &ctx))
    {
        LOG_DEBUG("SetThreadContext error=%d", GetLastError());
        return 0;
    }

    return base_address;
}

NTSYSAPI NTSTATUS NTAPI NtResumeThread(HANDLE ThreadHandle, PULONG SuspendCount);

void pe_resume(PROCESS_INFORMATION* information)
{
    if (information == NULL || !IS_VALID_HANDLE(information))
        return;

#if RUNPE_USE_NTRESUMETHREAD
    NtResumeThread(information->hThread, NULL);
#else
    ResumeThread(information->hThread);
#endif
}

void pe_close(PROCESS_INFORMATION* information)
{
    if (information == NULL)
        return;

    if (IS_VALID_HANDLE(information->hThread))
        CloseHandle(information->hThread);

    if (IS_VALID_HANDLE(information->hProcess))
        CloseHandle(information->hProcess);
}


#endif

#if __cplusplus
};
#endif
