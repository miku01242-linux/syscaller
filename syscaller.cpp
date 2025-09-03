#include "syscaller.hpp"

LPVOID syscaller::pCodeLoc = nullptr;
DWORD syscaller::NumberOfNames = 0;
syscaller::SyscallList* syscaller::sl = nullptr;

PVOID syscaller::helper::RVAtoRawOffset(DWORD_PTR RVA, PIMAGE_SECTION_HEADER section) {
    return (PVOID)(RVA - section->VirtualAddress + section->PointerToRawData);
}

BOOL syscaller::helper::get_syscall_numbers() {
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

BOOL syscaller::helper::get_text_section_info(PBYTE* ppSectionStart, DWORD* pdwSectionSize) {
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

PBYTE syscaller::helper::find_code_cave(PBYTE pStart, DWORD dwSize, DWORD dwCaveSize) {
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

void syscaller::helper::clean() {
    delete[] syscaller::sl;
}

