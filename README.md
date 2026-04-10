# Reflective PE Loader (x64)

A custom, bare-metal Portable Executable (PE) Loader written in C++ for Windows. This project manually maps, relocates, and executes a 64-bit Windows executable entirely from memory, bypassing the standard Windows OS loader (`LoadLibrary`/`CreateProcess`).

## 🧠 Architecture & Modules

The loader mimics the behavior of the Windows OS loader by executing the following pipeline:

1. **File I/O & Validation:** Reads the raw executable from disk into a heap buffer and validates the DOS (`MZ`) and NT (`PE\0\0`) headers.
2. **Memory Allocation & Section Mapping:** Parses the Section Headers, allocates executable virtual memory (`VirtualAlloc`), and maps raw section data into their correct Virtual Addresses (VA).
3. **Base Relocation:** Parses the `.reloc` directory and patches absolute addresses (Delta calculation for `IMAGE_REL_BASED_DIR64`) in case the payload is not loaded at its preferred `ImageBase`.
4. **IAT Resolution:** Parses the Import Directory, dynamically loads dependent DLLs using `LoadLibraryA`, and resolves function pointers (by Name or Ordinal) using `GetProcAddress` to rebuild the Import Address Table (IAT).
5. **Execution:** Resolves the `AddressOfEntryPoint`, casts it to a function pointer, and transfers execution control to the injected payload.

## 🛠️ Prerequisites

* Windows OS (64-bit)
* C++ Compiler (MinGW-w64 `g++` or MSVC `cl.exe`)

## 🚀 Usage & Compilation

### 1. Compile the Loader
Compile the main PE Loader source code. 
Using `g++`:
```bash
g++ -O2 -m64 pe_loader.cpp -o pe_loader.exe
```

### 2. Compile a Target Payload
Create a simple payload. It must be compiled as a 64-bit executable, and it is highly recommended to link it statically and disable Control Flow Guard (CFG) for this basic loader.

Using `g++`:
```bash
g++ -O2 -m64 -static target.cpp -o target.exe
```

### 3. Run the Loader
Pass the target executable as a command-line argument to the loader:
```bash
.\pe_loader.exe target.exe
```

## 🖥️ Example Output

Below is an example of a successful run of ".\pe_loader.exe target.exe":

```text
=== PREPARATION ===
[+] Valid DOS header (MZ)
[+] Valid NT header (PE\0\0)
[+] Allocated virtual memory for the image at: 0x1d459540000

=== HEADERS COPYING ===
[+] Copied headers (600 bytes) to virtual memory

=== SECTIONS COPYING ===
[+] Section: .text    copied to virtual address: 0x20b35e51000
[+] Section: .data    copied to virtual address: 0x20b35f20000
[+] Section: .rdata   copied to virtual address: 0x20b35f24000
[+] Section: .pdata   copied to virtual address: 0x20b35f36000
[+] Section: .xdata   copied to virtual address: 0x20b35f42000
[*] Section: .bss     has no raw data (skipped copying)
[+] Section: .idata   copied to virtual address: 0x20b35f53000
[+] Section: .tls     copied to virtual address: 0x20b35f55000
[+] Section: .rsrc    copied to virtual address: 0x20b35f56000
[+] Section: .reloc   copied to virtual address: 0x20b35f57000
[+] Section: /4       copied to virtual address: 0x20b35f59000
[+] Section: /19      copied to virtual address: 0x20b35f5a000
[+] Section: /31      copied to virtual address: 0x20b35f73000
[+] Section: /45      copied to virtual address: 0x20b35f78000
[+] Section: /57      copied to virtual address: 0x20b35f84000
[+] Section: /70      copied to virtual address: 0x20b35f86000
[+] Section: /81      copied to virtual address: 0x20b35f87000
[+] Section: /97      copied to virtual address: 0x20b35f8a000
[+] Section: /113     copied to virtual address: 0x20b35f98000

[+] Freed temporary raw file buffer.

=== RELOCATIONS ===
[+] Fixed absolute addresses successfully (Applied 16b8 bytes of relocations)

=== LOADING DLLs ===
[*] Loading DLL: KERNEL32.dll
[*] Loading DLL: api-ms-win-crt-convert-l1-1-0.dll
[*] Loading DLL: api-ms-win-crt-environment-l1-1-0.dll
[*] Loading DLL: api-ms-win-crt-filesystem-l1-1-0.dll
[*] Loading DLL: api-ms-win-crt-heap-l1-1-0.dll
[*] Loading DLL: api-ms-win-crt-locale-l1-1-0.dll
[*] Loading DLL: api-ms-win-crt-math-l1-1-0.dll
[*] Loading DLL: api-ms-win-crt-private-l1-1-0.dll
[*] Loading DLL: api-ms-win-crt-runtime-l1-1-0.dll
[*] Loading DLL: api-ms-win-crt-stdio-l1-1-0.dll
[*] Loading DLL: api-ms-win-crt-string-l1-1-0.dll
[*] Loading DLL: api-ms-win-crt-time-l1-1-0.dll
[*] Loading DLL: api-ms-win-crt-utility-l1-1-0.dll
[+] Import Address Table (IAT) resolved successfully.

[!] Executing payload...
[!] Payload output:
Hello from the injected payload!
```

## ⚠️ Disclaimer

This project was developed strictly for **educational purposes** to understand the Windows Portable Executable format, memory management, and operating system internals. It should not be used for malicious purposes.