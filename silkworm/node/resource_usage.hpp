// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <atomic>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/any_io_executor.hpp>

#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/concurrency/event_notifier.hpp>

namespace silkworm::node {

//! Log for resource usage
class ResourceUsageLog {
  public:
    explicit ResourceUsageLog(const boost::asio::any_io_executor& executor, const DataDirectory& data_directory)
        : stop_notifier_(executor), data_directory_(data_directory) {}

    Task<void> run();
    void stop();

  private:
    std::atomic_bool stop_requested_{false};
    concurrency::EventNotifier stop_notifier_;
    const DataDirectory& data_directory_;
};

}  // namespace silkworm::node
