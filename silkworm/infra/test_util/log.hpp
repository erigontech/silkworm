/*
   Copyright 2022 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

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
