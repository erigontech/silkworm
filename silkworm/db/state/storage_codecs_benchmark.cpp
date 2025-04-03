// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <array>
#include <numeric>

#include <benchmark/benchmark.h>

#include <silkworm/core/common/random_number.hpp>

#include "storage_codecs.hpp"

namespace silkworm::db::state {

template <size_t kSize>
static void fill_random_byte_array(uint8_t (&arr)[kSize]) {
    static RandomNumber random{0, UINT8_MAX};
    for (uint8_t& v : arr) {
        v = static_cast<uint8_t>(random.generate_one());
    }
}

static void storage_address_and_location_encoder(benchmark::State& state) {
    StorageAddressAndLocationSnapshotsCodec encoder;
    fill_random_byte_array(encoder.value.address.bytes);
    fill_random_byte_array(encoder.value.location_hash.bytes);

    for ([[maybe_unused]] auto _ : state) {
        ByteView word = encoder.encode_word();
        [[maybe_unused]] unsigned char sum = std::accumulate(word.begin(), word.end(), static_cast<unsigned char>(0));
    }
}
BENCHMARK(storage_address_and_location_encoder);

}  // namespace silkworm::db::state
