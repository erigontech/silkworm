/*
   Copyright 2024 The Silkworm Authors

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

#include <utility>
#include <vector>

namespace silkworm::test_util {

//! Test fixtures are predefined data sets that you initialize before running your tests
template <typename Input, typename ExpectedResult>
using Fixture = std::pair<Input, ExpectedResult>;

template <typename Input, typename ExpectedResult>
using Fixtures = std::vector<Fixture<Input, ExpectedResult>>;

}  // namespace silkworm::test_util
