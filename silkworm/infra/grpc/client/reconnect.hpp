// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <string>

#include <silkworm/infra/concurrency/task.hpp>

#include <grpcpp/grpcpp.h>

namespace silkworm::rpc {

bool is_disconnect_error(const grpc::Status& status, grpc::Channel& channel);

inline constexpr int64_t kDefaultMinBackoffReconnectTimeout{5'000};
inline constexpr int64_t kDefaultMaxBackoffReconnectTimeout{600'000};

//! Compute next timeout as truncated exponential backoff starting from min up to max
//! \details Return values: min_msec, min_msec*2, min_msec*4, ... max_msec, max_msec, ...
int64_t backoff_timeout(size_t attempt, int64_t min_msec, int64_t max_msec);

Task<void> reconnect_channel(grpc::Channel& channel,
                             std::string log_prefix,
                             int64_t min_msec = kDefaultMinBackoffReconnectTimeout,
                             int64_t max_msec = kDefaultMaxBackoffReconnectTimeout);

}  // namespace silkworm::rpc
