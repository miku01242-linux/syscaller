#pragma once

#include <Windows.h>

#ifdef DEBUG
#define DbgPrint(format, ...) fprintf(stderr, format, ##__VA_ARGS__)
#else
#define DbgPrint(format, ...)
#endif

namespace syscaller {
    static LPVOID pCodeLoc = nullptr;
    static DWORD NumberOfNames = 0;
    struct SyscallList {
        CHAR FunctionName[64];
        DWORD syscallNumber;
    };
    SyscallList *sl = nullptr;

    namespace helper {
        PVOID RVAtoRawOffset(DWORD_PTR RVA, PIMAGE_SECTION_HEADER section) {
            return (PVOID)(RVA - section->VirtualAddress + section->PointerToRawData);
        }

        BOOL get_syscall_numbers() {
            HANDLE hFile = CreateFileA(
                "C:\\Windows\\System32\\ntdll.dll",
                GENERIC_READ,
                FILE_SHARE_READ,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr
            );
            if (hFile == INVALID_HANDLE_VALUE) return FALSE;
            DWORD size = GetFileSize(hFile, nullptr);
            LPVOID data = HeapAlloc(GetProcessHeap(), 0, size);
            if (!data) return FALSE;

            DWORD bytesRead = 0;
            if (!ReadFile(hFile, data, size, &bytesRead, nullptr)) {
                HeapFree(GetProcessHeap(), 0, data);
                CloseHandle(hFile);
                return FALSE;
            }

            PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)data;
            PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)data + dosHeader->e_lfanew);
            DWORD exportDirRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(imageNTHeaders);

            PIMAGE_SECTION_HEADER textSection = section;
            PIMAGE_SECTION_HEADER rdataSection = section;

            CHAR rdata[] = { '.', 'r', 'd', 'a', 't', 'a', '\0' };
            for (int i = 0; i < imageNTHeaders->FileHeader.NumberOfSections; i++) {
                if (memcmp(section->Name, rdata, sizeof(rdata)) == 0) { 
                    rdataSection = section;
                    break;
                }
                section++;
            }

            PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)RVAtoRawOffset((DWORD_PTR)data + exportDirRVA, rdataSection);

            PDWORD addressOfNames = (PDWORD)RVAtoRawOffset((DWORD_PTR)data + *(&exportDirectory->AddressOfNames), rdataSection);
            PDWORD addressOfFunctions = (PDWORD)RVAtoRawOffset((DWORD_PTR)data + *(&exportDirectory->AddressOfFunctions), rdataSection);

            syscaller::NumberOfNames = exportDirectory->NumberOfNames;
            syscaller::sl = new SyscallList[syscaller::NumberOfNames];
            for (DWORD i = 0; i < syscaller::NumberOfNames; i++) {
                DWORD_PTR functionNameVA = (DWORD_PTR)RVAtoRawOffset((DWORD_PTR)data + addressOfNames[i], rdataSection);
                BYTE* functionVA = (BYTE*)RVAtoRawOffset((DWORD_PTR)data + addressOfFunctions[i + 1], textSection);
                LPCSTR functionNameResolved = (LPCSTR)functionNameVA;

                if (
                    strncmp(functionNameResolved, "Nt", 2) != 0 &&
                    strncmp(functionNameResolved, "Zw", 2) != 0
                ) continue;

                if (functionVA[0] == 0x4C && functionVA[1] == 0x8B && functionVA[2] == 0xD1 && functionVA[3] == 0xB8) {
                    memcpy(syscaller::sl[i].FunctionName, functionNameResolved, 64);
                    syscaller::sl[i].syscallNumber = *(DWORD*)(functionVA + 4);
                }
            }

            HeapFree(GetProcessHeap(), 0, data);
            CloseHandle(hFile);
            return TRUE;
        }

        BOOL get_text_section_info(PBYTE* ppSectionStart, DWORD* pdwSectionSize) {
            HMODULE hModule = GetModuleHandle(nullptr);
            if (!hModule) return FALSE;

            PIMAGE_DOS_HEADER dos_head = (PIMAGE_DOS_HEADER)hModule;
            if (dos_head->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

            PIMAGE_NT_HEADERS nt_head = (PIMAGE_NT_HEADERS)((PBYTE)hModule + dos_head->e_lfanew);
            if (nt_head->Signature != IMAGE_NT_SIGNATURE) return FALSE;

            PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(nt_head);
            DWORD dwNumberOfSections = nt_head->FileHeader.NumberOfSections;

            CHAR text[] = { '.', 't', 'e', 'x', 't', '\0' };
            for (DWORD i = 0; i < dwNumberOfSections; ++i) {
                if (memcmp(pSection[i].Name, text, sizeof(text)) == 0) {
                    *ppSectionStart = (PBYTE)hModule + pSection[i].VirtualAddress;
                    *pdwSectionSize = pSection[i].Misc.VirtualSize;
                    return TRUE;
                }
            }

            return FALSE;
        }

        PBYTE find_code_cave(PBYTE pStart, DWORD dwSize, DWORD dwCaveSize) {
            for (DWORD i = 0; i <= dwSize - dwCaveSize; ++i) {
                BOOL bIsCave = TRUE;
                for (DWORD j = 0; j < dwCaveSize; ++j) {
                    BYTE bByte = pStart[i + j];
                    if (bByte != 0x00 && bByte != 0x90) {
                        bIsCave = FALSE;
                        break;
                    }
                }
                if (bIsCave) {
                    return pStart + i;
                }
            }
            return nullptr;
        }

        void clean() {
            delete[] syscaller::sl;
        }
    };

    template<typename T, typename ...args> T syscall(const char* sFunction) {
        if (!syscaller::pCodeLoc || !syscaller::sl) {
            DbgPrint("[*] Init Syscall Stub\n");

            if (!syscaller::helper::get_syscall_numbers()) {
                DbgPrint("[-] Failed to get syscall number\n");
                return nullptr;
            }
            DbgPrint("[+] Get Syscall Numbers\n");

            PBYTE pTextStart = nullptr;
            DWORD dwTextSize = 0;
            if (!syscaller::helper::get_text_section_info(&pTextStart, &dwTextSize)) {
                DbgPrint("[-] Failed to retrieve .text section info\n");
                return nullptr;
            }
            DbgPrint("[+] .text section start: %p, size: %lu\n", pTextStart, dwTextSize);

            DbgPrint("[*] Searching for code cave of size: 0x%X\n", 0x10);
            syscaller::pCodeLoc = syscaller::helper::find_code_cave(pTextStart, dwTextSize, 0x10);
            if (!syscaller::pCodeLoc) {
                DbgPrint("[-] Failed to find code cave\n");
                return nullptr;
            }
            DbgPrint("[+] Found code cave at: %p\n", syscaller::pCodeLoc);

            atexit(syscaller::helper::clean);

            constexpr BYTE cb[] = {
                0x4C, 0x8B, 0xD1,              // mov r10, rcx
                0xB8, 0x00, 0x00, 0x00, 0x00,  // mov eax, <syscall number>
                0x0F, 0x05,                    // syscall
                0xC3                           // ret
            };

            DWORD oldProtect;
            if (!VirtualProtect(syscaller::pCodeLoc, 0x10, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                DbgPrint("[-] Failed to change memory protection: %lu\n", GetLastError());
            }
            DbgPrint("[+] Changed memory protection to RWX at: %p\n", syscaller::pCodeLoc);

            auto size = sizeof(cb) / sizeof(cb[0]);
            memcpy(syscaller::pCodeLoc, cb, size);
            DbgPrint("[+] Writing syscall stub to: %p\n", syscaller::pCodeLoc);
        }

        DWORD syscallNumber = 0;
        bool found = false;
        for (DWORD i = 0; i < syscaller::NumberOfNames; ++i) {
            if (_stricmp(syscaller::sl[i].FunctionName, sFunction) == 0) {
                syscallNumber = syscaller::sl[i].syscallNumber;
                found = true;
                break;
            }
        }
        if (!found) {
            DbgPrint("[-] Syscall not found for: %s\n", sFunction);
            return nullptr;
        }

        memcpy((BYTE*)syscaller::pCodeLoc + 4, &syscallNumber, sizeof(DWORD));
        DbgPrint("[*] Syscall stub at %p:", syscaller::pCodeLoc);
        for (int i = 0; i < 12; ++i) {
            DbgPrint(" %02X", ((BYTE*)syscaller::pCodeLoc)[i]);
        }
        DbgPrint("\n");

        return reinterpret_cast<T>(syscaller::pCodeLoc);
    }
};

