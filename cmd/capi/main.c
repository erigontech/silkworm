/*
   Copyright 2024 The Silkworm Authors

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

#include <silkworm/capi/silkworm.h>

int main(int argc, char* argv[]) {
    (void)argc, (void)argv;
#if defined(_MSC_VER)
    printf("MSVC version: %d\n", _MSC_FULL_VER);
#elif defined(__GNUC__) && !defined(__clang__)
    printf("gcc version: %d.%d.%d\n", __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
#else
    printf("AppleClang version: %d.%d.%d\n", __clang_major__, __clang_minor__, __clang_patchlevel__);
#endif
    printf("C API silkworm_libmdbx_version: %s\n", silkworm_libmdbx_version());
    return 0;
}
