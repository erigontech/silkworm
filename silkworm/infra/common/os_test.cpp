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

#include "os.hpp"

#include <catch2/catch_test_macros.hpp>

namespace silkworm::os {

TEST_CASE("os::max_file_descriptors", "[silkworm][infra][common][os]") {
    const auto current_max_descriptors = max_file_descriptors();
    CHECK(current_max_descriptors > 0);
}

TEST_CASE("os::set_max_file_descriptors", "[silkworm][infra][common][os]") {
    const auto current_max_descriptors = max_file_descriptors();
    CHECK(set_max_file_descriptors(current_max_descriptors - 1));
}

TEST_CASE("os::page_size", "[silkworm][infra][common][os]") {
    CHECK(page_size() >= 4096);
}

}  // namespace silkworm::os
