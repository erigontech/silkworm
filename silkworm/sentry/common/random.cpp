// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "random.hpp"

namespace silkworm::sentry {

Bytes random_bytes(Bytes::size_type size) {
    std::default_random_engine random_engine{std::random_device{}()};
    std::uniform_int_distribution<uint16_t> random_distribution{0, UINT8_MAX};

    Bytes data(size, 0);
    for (auto& d : data) {
        d = static_cast<uint8_t>(random_distribution(random_engine));
    }
    return data;
}

}  // namespace silkworm::sentry
