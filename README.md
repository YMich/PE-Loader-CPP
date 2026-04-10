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
Create a simple payload (e.g., a `MessageBox` application). It must be compiled as a 64-bit executable, and it is highly recommended to link it statically and disable Control Flow Guard (CFG) for this basic loader.

Using `g++`:
```bash
g++ -O2 -m64 -static target.cpp -o target.exe
```

### 3. Run the Loader
Pass the target executable as a command-line argument to the loader:
```bash
.\pe_loader.exe target.exe
```

## ⚠️ Disclaimer

This project was developed strictly for **educational purposes** to understand the Windows Portable Executable format, memory management, and operating system internals. It should not be used for malicious purposes.
```