/*
Copyright 2020-2022 The Silkworm Authors

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

#include "node_key.hpp"
#include <array>
#include <random>
#include <silkworm/common/util.hpp>
#include <silkworm/common/secp256k1_context.hpp>

namespace silkworm::sentry {

NodeKey::NodeKey() {
    SecP256K1Context ctx;

    std::default_random_engine random_engine{std::random_device{}()};
    std::uniform_int_distribution<uint8_t> random_distribution;

    std::array<uint8_t, 32> data{};
    do {
        for (auto& d : data)
            d = random_distribution(random_engine);
    } while (!ctx.verify_private_key_data(data));

    private_key_ = Bytes(data.data(), data.size());
}

NodeKey::NodeKey(Bytes data) : private_key_(std::move(data)) {
    SecP256K1Context ctx;

    if (!ctx.verify_private_key_data(private_key_)) {
        throw std::invalid_argument("Invalid node key");
    }
}

NodeKey::NodeKey(const ByteView& data) : NodeKey(Bytes(data)) {
}

std::string NodeKey::to_hex() const {
    return ::silkworm::to_hex(private_key_);
}

}  // namespace silkworm::sentry
