/**
 * @file pe_loader.cpp
 * @brief Reflective PE Loader (x64) with IAT Hooking.
 *
 * This program manually maps a 64-bit Windows Portable Executable (PE) into memory,
 * applies base relocations, resolves the Import Address Table (IAT), and executes it.
 * It bypasses the standard Windows OS loader (ntdll.dll), allowing for in-memory execution.
 * Additionally, it hooks GetCommandLineA/W to spoof command-line arguments for the payload.
 */

#include <windows.h>
#include <iostream>
#include <iomanip>
#include <string.h>

#define IMAGE_REL_BASED_DIR64 10

using namespace std;

BOOL isValidDosHeader(PCHAR buff);
BOOL isValidNtHeader(PCHAR buff);
PCHAR getFile(char* argv[]);
DWORD getSizeOfImage(PCHAR buff); 
PCHAR allocVirtualMem(PCHAR tmpBuff);
void copyHeaders(PCHAR peBuff, PCHAR pImageBase);
void copySections(PCHAR peBuff, PCHAR pImageBase);
void fixAbsoluteAddresses(PCHAR pImageBase);
void resolveIAT(PCHAR pImageBase);
void executeProc(PCHAR pImageBase);
void initUserArgs(int argc, char* argv[]);
LPSTR MyGetCommandLineA();
LPWSTR MyGetCommandLineW();

/** @brief Global buffer holding the spoofed ANSI command line string. */
PCHAR userArgsA;
/** @brief Global buffer holding the spoofed Unicode command line string. */
PWCHAR userArgsW;

/**
 * @brief The main entry point for the PE Loader.
 * Orchestrates the entire loading pipeline: file reading, memory allocation,
 * section mapping, relocation, IAT resolution, and payload execution.
 * @param argc Argument count.
 * @param argv Argument vector. argv[1] must be the path to the target payload.
 * @return int Exit status (0 on success).
 */
int main(int argc, char* argv[]) {
    if (argc <= 1){
        cout << "Wrong number of arguments! Command form: .\\pe_loader.exe <FilePath>" << endl;
        exit(1);
    }

    initUserArgs(argc, argv);
    
    // Allocation of virtual memory
    cout << "=== PREPARATION ===" << endl;
    PCHAR tmpBuff = getFile(argv);
    if (!isValidDosHeader(tmpBuff) || !isValidNtHeader(tmpBuff)){
        HeapFree(GetProcessHeap(), 0, (LPVOID)tmpBuff);
        exit(1);
    }
    PCHAR pImageBase = allocVirtualMem(tmpBuff);

    // Copy PE headers and sections into the allocated memory
    copyHeaders(tmpBuff, pImageBase);
    copySections(tmpBuff, pImageBase);

    // Free temporary buffer
    HeapFree(GetProcessHeap(), 0, (LPVOID)tmpBuff);
    cout << endl << "[+] Freed temporary raw file buffer." << endl;

    fixAbsoluteAddresses(pImageBase);
    resolveIAT(pImageBase);
    executeProc(pImageBase);

    VirtualFree(pImageBase, 0, MEM_RELEASE);
    HeapFree(GetProcessHeap(), 0, (LPVOID)userArgsA);
    HeapFree(GetProcessHeap(), 0, (LPVOID)userArgsW);

    return 0;
}

/**
 * @brief Custom hook function for GetCommandLineA.
 * Injected into the target's IAT to spoof the ANSI command line.
 * @return LPSTR Pointer to the spoofed ANSI command line string.
 */
LPSTR WINAPI MyGetCommandLineA(){
    return (LPSTR)userArgsA;
}

/**
 * @brief Custom hook function for GetCommandLineW.
 * Injected into the target's IAT to spoof the Unicode command line.
 * @return LPWSTR Pointer to the spoofed Unicode command line string.
 */
LPWSTR WINAPI MyGetCommandLineW(){
    return (LPWSTR)userArgsW;
}

/**
 * @brief Initializes the global spoofed command-line buffers.
 * Concatenates the loader's arguments (starting from the target payload name)
 * into a single string to be served to the payload when it asks for the command line.
 * @param argc Argument count passed to the loader.
 * @param argv Argument vector passed to the loader.
 */
void initUserArgs(int argc, char* argv[]){
    DWORD size = 0;
    for (int i = 1; i < argc; i++){
        size += strlen(argv[i]);
    }

    userArgsA = (PCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size + argc);
    if (userArgsA == NULL){
        cout << "[-] HeapAlloc failed!" << endl;
        exit(1);
    }

    for (int i = 1; i < argc; i++) {
        strcat(userArgsA, argv[i]);
        strcat(userArgsA, " ");
    }
    userArgsA[strlen(userArgsA)] = 0;

    userArgsW = (PWCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 2*(size + argc));
    if (userArgsW == NULL){
        cout << "[-] HeapAlloc failed!" << endl;
        exit(1);
    }

    int result = MultiByteToWideChar(
        CP_ACP,
        0,
        userArgsA,
        -1,
        userArgsW,
        MAX_PATH);
    if (result == 0) {
        cout << "Conversion failed\n";
        exit(1);
    }
}

/**
 * @brief Transfers execution control to the injected payload.
 * @param pImageBase Pointer to the allocated and mapped virtual memory 
 * where the payload is fully prepared (sections mapped, 
 * relocations applied, and IAT resolved).
 * @note This is the point of no return. Once the payload is executed, 
 * the execution flow belongs to the injected code. If the payload 
 * does not return (e.g., it runs an infinite loop or calls exit()), 
 * this loader will not resume execution.
 */
void executeProc(PCHAR pImageBase){
    typedef void (*EntryPoint)();

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pImageBase + pDosHeader->e_lfanew);

    PCHAR virtualAddressOfEntryPoint = (PCHAR)(pImageBase + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
    EntryPoint ep = (EntryPoint)virtualAddressOfEntryPoint;

    cout << endl << "[!] Executing payload..." 
         << endl << "[!] Payload output:" << endl;

    ep();
}

/**
 * @brief Resolves the Import Address Table (IAT) by loading required DLLs and finding function addresses.
 * Integrates IAT Hooking logic to intercept calls to specific Windows APIs (e.g., GetCommandLine).
 * @param pImageBase Pointer to the allocated and mapped virtual memory.
 */
void resolveIAT(PCHAR pImageBase){
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pImageBase + pDosHeader->e_lfanew);

    cout << endl << "=== LOADING DLLs ===" << endl;
    DWORD rvaImportDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (rvaImportDir == 0) {
        cout << "[*] No Import Table found." << endl;
        return;
    }

    PIMAGE_IMPORT_DESCRIPTOR pDllEntry = (PIMAGE_IMPORT_DESCRIPTOR)(pImageBase + rvaImportDir);

    // Loop over each DLL
    while (pDllEntry->Name != 0){
        LPCSTR lpLibFileName = (LPCSTR)(pImageBase + pDllEntry->Name);
        HMODULE hModule = LoadLibraryA(lpLibFileName);
        
        cout << "[*] Loading DLL: " << lpLibFileName << endl;

        DWORD rvaOriginalFirstThunk = pDllEntry->OriginalFirstThunk;
        DWORD rvaFirstThunk  = pDllEntry->FirstThunk;

        // If the original table was stripped by the compiler (Bound Imports), use the second one.
        if (rvaOriginalFirstThunk == 0) {
            rvaOriginalFirstThunk = rvaFirstThunk;
        }

        PIMAGE_THUNK_DATA64 pThunk = (PIMAGE_THUNK_DATA64)(pImageBase + rvaOriginalFirstThunk);
        PIMAGE_THUNK_DATA64 importAddressArr = (PIMAGE_THUNK_DATA64)(pImageBase + rvaFirstThunk);
        DWORD i = 0;

        // Loop over every single imported function within the DLL
        while (pThunk[i].u1.AddressOfData != 0){
            FARPROC procAddress;

            // 64-bit number that can represent two things: an ordinal or a pointer to a name.
            ULONGLONG ulValue = pThunk[i].u1.AddressOfData;

            // The function is imported by ordinal
            if (ulValue & IMAGE_ORDINAL_FLAG64) {
                WORD ordinal = (WORD)(ulValue & 0xFFFF);

                procAddress = GetProcAddress(hModule, MAKEINTRESOURCEA(ordinal)); 
            }
            else {
                // The function is imported by name
                PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)(pImageBase + ulValue);
                LPCSTR lpProcName = ibn->Name;

                // --- IAT HOOKING LOGIC ---
                if (strcmp(lpProcName, "GetCommandLineA") == 0){
                    procAddress = (FARPROC)MyGetCommandLineA;
                    cout << "[*] -> HOOKED GetCommandLineA!" << endl;
                }
                else if (strcmp(lpProcName, "GetCommandLineW") == 0){
                    procAddress = (FARPROC)MyGetCommandLineW;
                    cout << "[*] -> HOOKED GetCommandLineW!" << endl;
                }
                else{
                    procAddress = GetProcAddress(hModule, lpProcName);
                }
            }

            importAddressArr[i].u1.Function = (ULONGLONG)procAddress;

            i++;
        }

        pDllEntry++;
    }
    
    cout << "[+] Import Address Table (IAT) resolved successfully." << endl;
}

/**
 * ================================================================================
 * EXPLANATION OF THE BASE RELOCATION DIRECTORY (.reloc)
 * ================================================================================
 * * When a PE file is loaded at an address different from its preferred ImageBase,
 * all hardcoded, absolute memory addresses within the code become invalid. 
 * The Base Relocation table provides the loader with a list of "pointers to fix".
 * * To save space, the directory is not a flat list. It is divided into "Blocks".
 * Each block groups together all the relocations needed for a specific 4KB page.
 * * STRUCTURE OF A SINGLE BLOCK:
 * * 1. THE HEADER (IMAGE_BASE_RELOCATION structure - 8 Bytes)
 * - DWORD VirtualAddress : The base RVA of the 4KB page being patched.
 * - DWORD SizeOfBlock    : The total size of this block (Header + Entries).
 * * 2. THE ENTRIES (Array of WORDs - 2 Bytes each)
 * Immediately following the 8-byte header is an array of 16-bit entries. 
 * The number of entries is calculated as: (SizeOfBlock - 8) / sizeof(WORD).
 * * Each 16-bit WORD entry is bitwise-split into two parts:
 * [ TYPE (Top 4 bits) ] [ OFFSET (Bottom 12 bits) ]
 * * - Type (BitShift >> 12) : Dictates the math used to fix the address.
 * 10 (0xA) = IMAGE_REL_BASED_DIR64 (Add 64-bit Delta)
 * 0 (0x0) = IMAGE_REL_BASED_ABSOLUTE (Padding, do nothing)
 * * - Offset (Bitwise & 0x0FFF) : The exact position within the 4KB page.
 * Target RVA to patch = Block.VirtualAddress + Offset.
 * ================================================================================
 *
 * @brief Applies Base Relocations to the mapped image if it was loaded at a different ImageBase.
 * @param pImageBase Pointer to the allocated and mapped virtual memory.
 */
void fixAbsoluteAddresses(PCHAR pImageBase){
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pImageBase + pDosHeader->e_lfanew);

    DWORD sizeRelocationDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    DWORD rvaRelocationDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;

    cout << endl << "=== RELOCATIONS ===" << endl;
    if (sizeRelocationDir == 0) {
        cout << "[*] No relocations found or needed." << endl;
        return;
    }

    ULONG_PTR delta = (ULONG_PTR)pImageBase - pNtHeaders->OptionalHeader.ImageBase;

    if (delta == 0) {
        cout << "[+] Image loaded at preferred base address. No relocations required." << endl;
        return;
    }

    DWORD currRealocBlock = 0;
    while (currRealocBlock < sizeRelocationDir){

        PIMAGE_BASE_RELOCATION relocBlock = (PIMAGE_BASE_RELOCATION)(pImageBase + rvaRelocationDir + currRealocBlock);
        DWORD countEntry = (relocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        PWORD entries = (PWORD)(relocBlock + 1);

        for (DWORD i = 0; i < countEntry; i++){
            BYTE type = entries[i] >> 12;
            WORD offset = entries[i] & 0x0FFF;

            if (type == IMAGE_REL_BASED_DIR64){
                PDWORD64 pAddressToFix = (PDWORD64)(pImageBase + relocBlock->VirtualAddress + offset);
                
                *pAddressToFix += delta;
            }
        }

        currRealocBlock += relocBlock->SizeOfBlock;
    }
    
    cout <<"[+] Fixed absolute addresses successfully (Applied " << sizeRelocationDir << " bytes of relocations)" << endl;
}

/**
 * @brief Copies the PE headers (DOS, NT, and Section Table) to the allocated virtual memory.
 * @param peBuff Pointer to the raw PE file data.
 * @param pImageBase Pointer to the allocated virtual memory.
 */
void copyHeaders(PCHAR peBuff, PCHAR pImageBase){
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)peBuff;
    LONG e_lfanew = pDosHeader->e_lfanew;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(peBuff + e_lfanew);

    DWORD sizeOfHeaders = pNtHeaders->OptionalHeader.SizeOfHeaders;
    memcpy(pImageBase, peBuff, sizeOfHeaders);

    cout << endl << "=== HEADERS COPYING ===" << endl;
    cout << "[+] Copied headers (" << sizeOfHeaders << " bytes) to virtual memory" << endl;
}

/**
 * @brief Maps each section from the raw file buffer to its correct VirtualAddress in memory.
 * @param peBuff Pointer to the raw PE file data.
 * @param pImageBase Pointer to the allocated virtual memory.
 */
void copySections(PCHAR peBuff, PCHAR pImageBase){
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)peBuff;
    LONG e_lfanew = pDosHeader->e_lfanew;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(peBuff + e_lfanew);

    WORD numberOfSections = pNtHeaders->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    
    cout << endl << "=== SECTIONS COPYING ===" << endl;
    for (int i = 0; i < numberOfSections; i++){
        CHAR sSectionName[9] = {0};
        memcpy(sSectionName, pSectionHeader[i].Name, 8);

        if (pSectionHeader[i].SizeOfRawData > 0) {
            memcpy(pImageBase + pSectionHeader[i].VirtualAddress, 
                   peBuff + pSectionHeader[i].PointerToRawData, 
                   pSectionHeader[i].SizeOfRawData);

            cout << "[+] Section: " << left << setw(8) << sSectionName 
                 << " copied to virtual address: 0x" 
                 << right << hex << setfill('0') << setw(8) << (uintptr_t)(pImageBase + pSectionHeader[i].VirtualAddress) << setfill(' ') << endl;
        } else {
            cout << "[*] Section: " << left << setw(8) << sSectionName 
                 << " has no raw data (skipped copying)" << endl;
        }
    }
}

/**
 * @brief Allocates the final virtual memory space required for the PE image to execute.
 * It parses the Optional Header to find the SizeOfImage and requests executable memory from the OS.
 * @param tmpBuff Pointer to the raw PE file data (used to extract SizeOfImage).
 * @return PCHAR A pointer to the newly allocated executable memory (ImageBase). 
 * The caller must free this using VirtualFree. Exits the program if allocation fails.
 */
PCHAR allocVirtualMem(PCHAR tmpBuff){
    DWORD sizeOfImage = getSizeOfImage(tmpBuff);
    
    PCHAR pImageBase = (PCHAR)VirtualAlloc(
        NULL,
        sizeOfImage,
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_EXECUTE_READWRITE);
        
    if (pImageBase == NULL) {
        cout << "[-] VirtualAlloc failed!" << endl;
        HeapFree(GetProcessHeap(), 0, (LPVOID)tmpBuff);
        exit(1);
    }
    
    cout << "[+] Allocated virtual memory for the image at: 0x" << hex << (uintptr_t)pImageBase << endl;

    return pImageBase;
}

/**
 * @brief Reads the raw contents of a file from the disk into a dynamically allocated heap buffer.
 * @param argv Array containing the file path at index 1.
 * @return PCHAR A pointer to the heap-allocated buffer containing the raw file data.
 * The caller is responsible for freeing this memory using HeapFree.
 */
PCHAR getFile(char* argv[]){
    LPCSTR pFilePath = argv[1];
    HANDLE hFile = CreateFileA(
        pFilePath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
        
    if (hFile == INVALID_HANDLE_VALUE){
        cout << "[-] Failed to open file!" << endl;
        exit(1);
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    
    PCHAR tmpBuff = (PCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize);
    if (tmpBuff == NULL){
        cout << "[-] HeapAlloc failed!" << endl;
        CloseHandle(hFile);
        exit(1);
    }

    DWORD bytesRead = 0;
    ReadFile(hFile, tmpBuff, fileSize, &bytesRead, NULL);
    if (bytesRead != fileSize){
        cout << "[-] ReadFile failed!" << endl;
        CloseHandle(hFile);
        HeapFree(GetProcessHeap(), 0, (LPVOID)tmpBuff);
        exit(1);
    }
    CloseHandle(hFile);

    return tmpBuff;
}

/**
 * @brief Validates the presence of the DOS header signature (MZ) in the given buffer.
 * @param buff Pointer to the raw PE file data.
 * @return BOOL True if the signature is "MZ" (0x5A4D), False otherwise.
 */
BOOL isValidDosHeader(PCHAR buff){
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)buff;
    if (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE){
        cout << "[+] Valid DOS header (MZ)" << endl;
        return true;
    } 
    else{
        cout << "[-] Invalid file format!" << endl;
        return false;
    }
}

/**
 * @brief Validates the presence of the NT header signature (PE\0\0) in the given buffer.
 * @param buff Pointer to the raw PE file data.
 * @return BOOL True if the signature is "PE\0\0" (0x00004550), False otherwise.
 */
BOOL isValidNtHeader(PCHAR buff){
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)buff;
    LONG e_lfanew = pDosHeader->e_lfanew;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(buff + e_lfanew);
    
    if (pNtHeaders->Signature == IMAGE_NT_SIGNATURE){
        cout << "[+] Valid NT header (PE\\0\\0)" << endl;
        return true;
    }
    else{
        cout << "[-] Invalid NT header (signature)" << endl;
        return false;
    }
}

/**
 * @brief Retrieves the total virtual memory size required to load the PE image.
 * @param buff Pointer to the raw PE file data.
 * @return DWORD The size of the image in bytes (SizeOfImage from the Optional Header).
 */
DWORD getSizeOfImage(PCHAR buff){
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)buff;
    LONG e_lfanew = pDosHeader->e_lfanew;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(buff + e_lfanew);

    return pNtHeaders->OptionalHeader.SizeOfImage;
}