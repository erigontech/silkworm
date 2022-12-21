/*
   Copyright 2022 The Silkworm Authors

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

#include <memory>

#ifdef __linux__
#include <unistd.h>

#include <cstdio>
#endif

#ifdef __APPLE__
#include <mach/mach_init.h>
#include <mach/task.h>
#endif

#ifdef _WINDOWS
// clang-format off
#include <windows.h>
#include <Psapi.h>
// clang-format on
#endif

// Inspired by: https://stackoverflow.com/questions/372484/how-do-i-programmatically-check-memory-use-in-a-fairly-portable-way-c-c

// The amount of memory currently being used by this process, in bytes.
// if resident=true it will report the resident set in RAM (if supported on that OS)
// otherwise returns the full virtual arena
size_t get_mem_usage(bool resident) {
#if defined(__linux__)
    // getrusage doesn't work well on Linux. Try grabbing info directly from the /proc pseudo-filesystem.
    // Reading from /proc/self/statm gives info on your own process, as one line of numbers that are:
    // virtual mem program size, resident set size, shared pages, text/code, data/stack, library, dirty pages.
    // The mem sizes should all be multiplied by the page size.
    size_t vm_size = 0, rm_size = 0;
    FILE* file = fopen("/proc/self/statm", "r");
    if (file) {
        unsigned long vm = 0, rm = 0;
        if (fscanf(file, "%lu %lu", &vm, &rm) == 2) {  // the first 2 num: vm size, resident set size
            vm_size = vm * static_cast<size_t>(getpagesize());
            rm_size = rm * static_cast<size_t>(getpagesize());
        }
        fclose(file);
    }
    return (resident ? rm_size : vm_size);

#elif defined(__APPLE__)
    // Inspired by: http://miknight.blogspot.com/2005/11/resident-set-size-in-mac-os-x.html
    struct task_basic_info t_info;
    mach_msg_type_number_t t_info_count = TASK_BASIC_INFO_COUNT;
    task_info(current_task(), TASK_BASIC_INFO, reinterpret_cast<task_info_t>(&t_info), &t_info_count);
    size_t size = (resident ? t_info.resident_size : t_info.virtual_size);
    return size;

#elif defined(_WINDOWS)
    static HANDLE phandle{GetCurrentProcess()};
    PROCESS_MEMORY_COUNTERS_EX counters;
    if (K32GetProcessMemoryInfo(phandle, (PROCESS_MEMORY_COUNTERS*)&counters, sizeof(counters))) {
        return (resident ? counters.WorkingSetSize : counters.PagefileUsage);
    }

#else
    // Unsupported platform
    (void)resident;  // disable unused-parameter warning
    return 0;
#endif
}
