// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "terminal.hpp"

#include <cstdio>

#if defined(_WIN32)
#include <io.h>
#include <windows.h>
#if !defined(ENABLE_VIRTUAL_TERMINAL_PROCESSING)
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif
#else
#include <unistd.h>
#endif

namespace silkworm {

void init_terminal() {
#if defined(_WIN32)
    // Change code page to UTF-8 so log characters are displayed correctly in console
    // and also support virtual terminal processing for coloring output
    SetConsoleOutputCP(CP_UTF8);
    HANDLE output_handle = GetStdHandle(STD_OUTPUT_HANDLE);
    if (output_handle != INVALID_HANDLE_VALUE) {
        DWORD mode = 0;
        if (GetConsoleMode(output_handle, &mode)) {
            mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            SetConsoleMode(output_handle, mode);
        }
    }
#endif
}

bool is_terminal(int fd) {
#if defined(_WIN32)
    return _isatty(fd);
#else
    return isatty(fd);
#endif
}

static bool is_terminal_stream(FILE* stream) {
#if defined(_WIN32)
    return is_terminal(_fileno(stream));
#else
    return is_terminal(fileno(stream));
#endif
}

bool is_terminal_stdout() {
    return is_terminal_stream(stdout);
}

bool is_terminal_stderr() {
    return is_terminal_stream(stderr);
}

}  // namespace silkworm