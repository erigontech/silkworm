/*
   Copyright 2020 The Silkrpc Authors

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

#include <silkworm/silkrpc/common/block_cache.hpp>
#include <silkworm/silkrpc/common/log.hpp>
#include <silkworm/silkrpc/ethdb/kv/state_cache.hpp>

namespace silkrpc::test {

ContextTestBase::ContextTestBase()
    : init_dummy{[] {
          SILKRPC_LOG_VERBOSITY(LogLevel::None);
          return true;
      }()},
      context_{[]() { return grpc::CreateChannel("localhost:12345", grpc::InsecureChannelCredentials()); },
               std::make_shared<BlockCache>(), std::make_shared<ethdb::kv::CoherentStateCache>()},
      io_context_{*context_.io_context()},
      grpc_context_{*context_.grpc_context()},
      context_thread_{[&]() { context_.execute_loop(); }} {
}

ContextTestBase::~ContextTestBase() {
    context_.stop();
    if (context_thread_.joinable()) {
        context_thread_.join();
    }
}

}  // namespace silkrpc::test
