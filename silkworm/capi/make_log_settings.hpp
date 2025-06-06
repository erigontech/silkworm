// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/infra/common/log.hpp>

#include "log_level.h"

//! Build log configuration matching Erigon log format w/ custom verbosity level
silkworm::log::Settings make_log_settings(SilkwormLogLevel c_log_level);
