// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/infra/common/directories.hpp>

namespace silkworm::node {

//! Log for resource usage
class ResourceUsageLog {
  public:
    explicit ResourceUsageLog(const DataDirectory& data_directory)
        : data_directory_(data_directory) {}

    Task<void> run();

  private:
    const DataDirectory& data_directory_;
};

}  // namespace silkworm::node
