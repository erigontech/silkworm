// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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

using SignalHandlerFunc = void (*)(int);
std::map<int, SignalHandlerFunc> previous_signal_handlers;

static SignalHandlerFunc register_signal_action(const int sig_code, SignalHandlerFunc handler_func) {
#ifdef _WIN32
    return signal(sig_code, handler_func);
#else
    struct sigaction sa {};
    sa.sa_handler = handler_func;
    sa.sa_flags = SA_ONSTACK;
    sigfillset(&sa.sa_mask);
    struct sigaction previous_sa {};
    const int result = ::sigaction(sig_code, &sa, &previous_sa);
    if (result == -1) {
        return SIG_ERR;
    }
    return previous_sa.sa_handler;
#endif  // _WIN32
}

void SignalHandler::init(std::function<void(int)> custom_handler, bool silent) {
    for (const int sig_code : kHandleableCodes) {
        // Register our signal handler and remember the existing ones
        auto previous_handler{register_signal_action(sig_code, &SignalHandler::handle)};
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
            (void)std::fputs("\nGot ", stderr);
            (void)std::fputs(sig_name(sig_code), stderr);
            (void)std::fputs(". Shutting down ...\n", stderr);
        }
    }
    uint32_t sig_count = ++sig_count_;
    if (sig_count >= 10) {
        std::abort();
    }
    if (sig_count > 1 && !silent_) {
        (void)std::fputs("Already shutting down. Interrupt more to panic. ", stderr);
        char digit_with_endl[3];
        digit_with_endl[0] = static_cast<char>('0' + (10 - sig_count));
        digit_with_endl[1] = '\n';
        digit_with_endl[2] = '\0';
        (void)std::fputs(digit_with_endl, stderr);
    }
    if (custom_handler_) {
        custom_handler_(sig_code);
    }
    if (register_signal_action(sig_code, &SignalHandler::handle) == SIG_ERR) {  // Re-enable the hook
        (void)std::fputs("Failed to re-enable signal hook :(", stderr);
    }
}

void SignalHandler::reset() {
    signalled_ = false;
    sig_count_ = 0;

    // Restore any previous signal handlers
    for (const int sig_code : kHandleableCodes) {
        if (previous_signal_handlers.contains(sig_code)) {
            if (register_signal_action(sig_code, previous_signal_handlers[sig_code]) == SIG_ERR) {
                (void)std::fputs("Failed to restore previous signal handlers :(", stderr);
            }
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
