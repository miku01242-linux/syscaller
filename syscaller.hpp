#pragma once

#include <Windows.h>

#ifdef DEBUG
#define DbgPrint(format, ...) fprintf(stderr, format, ##__VA_ARGS__)
#else
#define DbgPrint(format, ...)
#endif

namespace syscaller {
    struct SyscallList {
        CHAR FunctionName[64];
        DWORD syscallNumber;
    };

    extern LPVOID pCodeLoc;
    extern DWORD NumberOfNames;
    extern SyscallList *sl;

    namespace helper {
        PVOID RVAtoRawOffset(DWORD_PTR RVA, PIMAGE_SECTION_HEADER section);
        BOOL get_syscall_numbers();
        BOOL get_text_section_info(PBYTE* ppSectionStart, DWORD* pdwSectionSize);
        PBYTE find_code_cave(PBYTE pStart, DWORD dwSize, DWORD dwCaveSize);
        void clean();
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

