/*
   Copyright 2023 The Silkworm Authors

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

#include "context_test_base.hpp"

namespace silkworm::test_util {

ContextTestBase::ContextTestBase()
    : log_guard_{log::Level::kNone},
      context_{0},
      io_context_{*context_.io_context()},
      grpc_context_{*context_.grpc_context()},
      context_thread_{[&]() { context_.execute_loop(); }} {}

ContextTestBase::~ContextTestBase() {
    context_.stop();
    if (context_thread_.joinable()) {
        context_thread_.join();
    }
}

}  // namespace silkworm::test_util
