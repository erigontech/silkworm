// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <functional>
#include <memory>

#include <silkworm/core/common/base.hpp>

namespace silkworm::stagedsync {

class BodiesStage;
struct SyncContext;

using BodiesStageFactory = std::function<std::unique_ptr<BodiesStage>(SyncContext*)>;

}  // namespace silkworm::stagedsync
