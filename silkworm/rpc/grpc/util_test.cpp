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

#include "util.hpp"

#include <catch2/catch.hpp>

#include <silkworm/infra/test_util/log.hpp>

namespace silkworm {

TEST_CASE("print grpc::Status", "[rpc][grpc][util]") {
    CHECK_NOTHROW(test_util::null_stream() << grpc::Status::OK);
    CHECK_NOTHROW(test_util::null_stream() << grpc::Status::CANCELLED);
}

}  // namespace silkworm
