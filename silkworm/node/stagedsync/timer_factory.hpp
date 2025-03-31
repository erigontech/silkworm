// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <functional>
#include <memory>

#include <silkworm/infra/common/timer.hpp>

namespace silkworm::stagedsync {

using TimerFactory = std::function<std::shared_ptr<Timer>(std::function<bool()> callback)>;

}  // namespace silkworm::stagedsync
