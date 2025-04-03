// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <ostream>

#include <silkworm/infra/common/log.hpp>

namespace silkworm::test_util {

//! Utility class using RAII to change the log verbosity level (necessary to make tests work in shuffled order)
class SetLogVerbosityGuard {
  public:
    explicit SetLogVerbosityGuard(log::Level new_level) : current_level_(log::get_verbosity()) {
        set_verbosity(new_level);
    }
    ~SetLogVerbosityGuard() { log::set_verbosity(current_level_); }

  private:
    log::Level current_level_;
};

//! Utility class using RAII to swap the underlying buffers of the provided streams
class StreamSwap {
  public:
    StreamSwap(std::ostream& o1, std::ostream& o2) : buffer_(o1.rdbuf()), stream_(o1) { o1.rdbuf(o2.rdbuf()); }
    ~StreamSwap() { stream_.rdbuf(buffer_); }

  private:
    std::streambuf* buffer_;
    std::ostream& stream_;
};

}  // namespace silkworm::test_util
