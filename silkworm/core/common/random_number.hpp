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

#include <limits>
#include <random>

namespace silkworm {

class RandomNumber {
  public:
    // Use to generate integers uniformly distributed on the closed interval [a, b]
    explicit RandomNumber(uint64_t a = 0, uint64_t b = std::numeric_limits<uint64_t>::max()) : distr_(a, b) {}

    // Not copyable nor movable
    RandomNumber(const RandomNumber&) = delete;
    RandomNumber& operator=(const RandomNumber&) = delete;

    uint64_t generate_one() { return distr_(generator_); }

  private:
    std::mt19937_64 generator_{std::random_device{}()};  // seed the generator randomly
    std::uniform_int_distribution<uint64_t> distr_;
};

}  // namespace silkworm
