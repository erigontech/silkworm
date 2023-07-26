/*
   Copyright 2023 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include <stdio.h>

#ifdef __APPLE__
#include <dlfcn.h>
#include <mach-o/dyld.h>
#endif  // __APPLE__

#include <silkworm/api/silkworm_api.h>

const char* kSilkwormApiPath = "libsilkworm_api.so";
const char* kSilkwormExecuteBlocksSymbol = "_silkworm_execute_blocks";

typedef enum SilkwormStatusCode (*SilkwormExecuteBlocksPtr)(
    MDBX_txn* txn, uint64_t chain_id, uint64_t start_block, uint64_t max_block,
    uint64_t batch_size, bool write_receipts, uint64_t* last_executed_block,
    int* mdbx_error_code); // Function pointer for Silkworm execute_blocks API

#ifdef __APPLE__
#if __MAC_OS_X_VERSION_MAX_ALLOWED >= 1050
int main_macos(void) {
    return 0;
}
#else  // __MAC_OS_X_VERSION_MAX_ALLOWED < 1050
int main_macos(void) {
    NSObjectFileImage img; // Represents the bundle's object file
    NSModule handle; // Handle to the loaded bundle
    NSSymbol sym; // Represents a symbol in the bundle
    SilkwormExecuteBlocksPtr silkworm_execute_blocks;

    /* Get an object file for the bundle. */
    const NSObjectFileImageReturnCode rc = NSCreateObjectFileImageFromFile(kSilkwormApiPath, &img);
    if (rc != NSObjectFileImageSuccess) {
        fprintf(stderr, "Could not load %s.\n", kSilkwormApiPath);
        return -1;
    }

    /* Get a handle for the bundle. */
    handle = NSLinkModule(img, kSilkwormApiPath, FALSE);

    /* Look up the silkworm_execute_blocks function. */
    sym = NSLookupSymbolInModule(handle, kSilkwormExecuteBlocksSymbol);
    if (sym == NULL) {
        fprintf(stderr, "Could not find symbol: %s.\n", kSilkwormExecuteBlocksSymbol);
        return -2;
    }

    /* Get the address of the function. */
    silkworm_execute_blocks = (SilkwormExecuteBlocksPtr)NSAddressOfSymbol(sym);
    if (silkworm_execute_blocks == NULL) {
        fprintf(stderr, "Could not get address of symbol: %s.\n", kSilkwormExecuteBlocksSymbol);
        return -3;
    }

    /* Invoke the function. */
    uint64_t last_executed_block;
    int mdbx_error_code;
    enum SilkwormStatusCode status_code =
        silkworm_execute_blocks(NULL, 1, 0, 0, 1, false, &last_executed_block, &mdbx_error_code);
    if (status_code != kSilkwormSuccess) {
        fprintf(stderr, "Execution failed: %d\n", (int)status_code);
        return -4;
    }

    return 0;
}
#endif  // __MAC_OS_X_VERSION_MAX_ALLOWED < 1050
#endif  // __APPLE__

#ifdef _WIN32
int main_win() {
    return 0;
}
#endif  // _WIN32

#ifdef __linux__
int main_linux() {
    return 0;
}
#endif  // __linux__

int main(int argc, char* argv[]) {
    if (argc > 1) {
        const char* argv1 = argv[1];
        printf("argv1=%s\n", argv1);
    }

#if defined __APPLE__
    return main_macos();
#elif defined _WIN32
    return main_win();
#elif defined __linux__
    return main_linux();
#endif
}
