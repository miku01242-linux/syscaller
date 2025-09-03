# syscaller

A lightweight C++ header-only implementation for dynamically resolving and executing Windows system calls (syscalls) without relying on hardcoded syscall numbers or external libraries.

> ⚠️ This project is intended for **64-bit Windows** only.

---

## Features

- Parses `ntdll.dll` directly from disk to extract syscall numbers
- Builds runtime syscall stubs in a code cave inside the `.text` section of the current module
- Avoids detection by dynamically generating `syscall` instructions
- Header-only and self-contained

---

## How It Works

1. **Parses** the PE structure of `ntdll.dll` to extract the export table.
2. **Scans** for functions starting with `Nt` or `Zw`.
3. **Identifies** syscall stubs by matching their byte signature (e.g. `mov r10, rcx; mov eax, X; syscall; ret`).
4. **Extracts** the syscall number (from `mov eax, <syscall_number>`).
5. **Locates a code cave** inside the current module’s `.text` section.
6. **Writes a syscall stub** to that location.
7. **Updates** the stub with the correct syscall number at runtime.
8. **Executes** the syscall by calling the stub as a function pointer.

---

## Usage

```cpp
#include "syscaller.hpp"

using NtAllocateVirtualMemory_t = NTSTATUS(WINAPI*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);

int main() {
    PVOID alloc = nullptr;
    SIZE_T size = sizeof(shellcode) / sizeof(shellcode[0]);

    auto NtAllocateVirtualMemory = syscaller::syscall<NtAllocateVirtualMemory_t>("NtAllocateVirtualMemory");
    NTSTATUS status = NtAllocateVirtualMemory(
        GetCurrentProcess(),
        &alloc,
        0,
        &size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
}
