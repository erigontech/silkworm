// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "common.hpp"

#include <cstring>

//! Build Silkworm log level from its C representation
static silkworm::log::Level make_log_level(const SilkwormLogLevel c_log_level) {
    silkworm::log::Level verbosity{};
    switch (c_log_level) {
        case SilkwormLogLevel::SILKWORM_LOG_NONE:
            verbosity = silkworm::log::Level::kNone;
            break;
        case SilkwormLogLevel::SILKWORM_LOG_CRITICAL:
            verbosity = silkworm::log::Level::kCritical;
            break;
        case SilkwormLogLevel::SILKWORM_LOG_ERROR:
            verbosity = silkworm::log::Level::kError;
            break;
        case SilkwormLogLevel::SILKWORM_LOG_WARNING:
            verbosity = silkworm::log::Level::kWarning;
            break;
        case SilkwormLogLevel::SILKWORM_LOG_INFO:
            verbosity = silkworm::log::Level::kInfo;
            break;
        case SilkwormLogLevel::SILKWORM_LOG_DEBUG:
            verbosity = silkworm::log::Level::kDebug;
            break;
        case SilkwormLogLevel::SILKWORM_LOG_TRACE:
            verbosity = silkworm::log::Level::kTrace;
            break;
    }
    return verbosity;
}

silkworm::log::Settings make_log_settings(const SilkwormLogLevel c_log_level) {
    return {
        .log_utc = false,       // display local time
        .log_timezone = false,  // no timezone ID
        .log_trim = true,       // compact rendering (i.e. no whitespaces)
        .log_verbosity = make_log_level(c_log_level),
    };
}
