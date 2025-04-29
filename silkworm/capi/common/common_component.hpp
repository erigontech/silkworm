// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <filesystem>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/context_pool_settings.hpp>

namespace silkworm::capi {

struct CommonComponent {
    silkworm::log::Settings log_settings;
    silkworm::concurrency::ContextPoolSettings context_pool_settings;
    std::filesystem::path data_dir_path;
};

}  // namespace silkworm::capi
