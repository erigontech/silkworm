// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
