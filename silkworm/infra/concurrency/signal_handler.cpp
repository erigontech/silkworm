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

#include "signal_handler.hpp"

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <stdexcept>

namespace silkworm {

static const char* sig_name(int sig_code) {
    switch (sig_code) {
        case SIGSEGV:
            return "SIGSEGV";
#if defined(__linux__) || defined(__APPLE__)
        case SIGBUS:
            return "SIGBUS";
        case SIGSYS:
            return "SIGSYS";
#endif
        case SIGFPE:
            return "SIGFPE";
        case SIGILL:
            return "SIGILL";
#if defined(__linux__) || defined(__APPLE__)
        case SIGTRAP:
            return "SIGTRAP";
#endif
#if defined(SIGBREAK)
        case SIGBREAK:
            return "SIGBREAK";
#endif
#if defined(__linux__) || defined(__APPLE__)
        case SIGQUIT:
            return "SIGQUIT";
#if defined(SIGSTP)
        case SIGSTP:
            return "SIGSTP";
#endif
        case SIGSTOP:
            return "SIGSTOP";
        case SIGKILL:
            return "SIGKILL";
#endif
        case SIGABRT:
            return "SIGABRT";
#if defined(SIGABRT_COMPAT)
        case SIGABRT_COMPAT:
            return "SIGABRT_COMPAT";
#endif
        case SIGINT:
            return "SIGINT";
        case SIGTERM:
            return "SIGTERM";
#if defined(__linux__) || defined(__APPLE__)
        case SIGVTALRM:
            return "SIGVTALRM";
        case SIGXFSZ:
            return "SIGXFZS";
        case SIGXCPU:
            return "SIGXCPU";
        case SIGHUP:
            return "SIGHUP";
        case SIGALRM:
            return "SIGALRM";
        case SIGUSR1:
            return "SIGUSR1";
        case SIGUSR2:
            return "SIGUSR2";
#endif
        default:
            return "Unknown";
    }
}

inline constexpr int kHandleableCodes[] {
#if defined(SIGBREAK)
    SIGBREAK,  // Windows keyboard CTRL+Break
#endif
#if defined(__linux__) || defined(__APPLE__)
        SIGQUIT,  // CTRL+\ (like CTRL+C but also generates a coredump)
        SIGTSTP,  // CTRL+Z to interrupt a process
#endif
        SIGINT,  // Keyboard CTRL+C
        SIGTERM  // Termination request (kill/killall default)
};

std::atomic_uint32_t SignalHandler::sig_count_{0};
std::atomic_int SignalHandler::sig_code_{0};
std::atomic_bool SignalHandler::signalled_{false};
std::function<void(int)> SignalHandler::custom_handler_;
bool SignalHandler::silent_{false};
std::map<int, void (*)(int)> previous_signal_handlers;

void SignalHandler::init(std::function<void(int)> custom_handler, bool silent) {
    for (const int sig_code : kHandleableCodes) {
        // Register our signal handler and remember the existing ones
        auto previous_handler{signal(sig_code, &SignalHandler::handle)};
        if (previous_handler != SIG_ERR) {
            previous_signal_handlers[sig_code] = previous_handler;
        }
    }
    custom_handler_ = std::move(custom_handler);
    silent_ = silent;
}

void SignalHandler::handle(int sig_code) {
    bool expected{false};
    if (signalled_.compare_exchange_strong(expected, true)) {
        sig_code_ = sig_code;
        if (!silent_) {
            std::fputs("\nGot ", stderr);
            std::fputs(sig_name(sig_code), stderr);
            std::fputs(". Shutting down ...\n", stderr);
        }
    }
    uint32_t sig_count = ++sig_count_;
    if (sig_count >= 10) {
        std::abort();
    }
    if (sig_count > 1 && !silent_) {
        std::fputs("Already shutting down. Interrupt more to panic. ", stderr);
        char digit_with_endl[3];
        digit_with_endl[0] = static_cast<char>('0' + (10 - sig_count));
        digit_with_endl[1] = '\n';
        digit_with_endl[2] = '\0';
        std::fputs(digit_with_endl, stderr);
    }
    if (custom_handler_) {
        custom_handler_(sig_code);
    }
    signal(sig_code, &SignalHandler::handle);  // Re-enable the hook
}

void SignalHandler::reset() {
    signalled_ = false;
    sig_count_ = 0;
    // Restore any previous signal handlers
    for (const int sig_code : kHandleableCodes) {
        if (previous_signal_handlers.contains(sig_code)) {
            signal(sig_code, previous_signal_handlers[sig_code]);
        }
    }
}

void SignalHandler::throw_if_signalled() {
    if (!signalled()) {
        return;
    }
    throw std::runtime_error(sig_name(sig_code_));
}

}  // namespace silkworm
