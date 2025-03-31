// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <benchmark/benchmark.h>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/execution/precompile.hpp>

static void ec_recovery(benchmark::State& state) {
    using namespace silkworm;
    Bytes in{
        *from_hex("18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c0000000000000000000000000000"
                  "00000000000000000000000000000000001c73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9a"
                  "a6a5a75feeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549")};
    for ([[maybe_unused]] auto _ : state) {
        precompile::ecrec_run(in);
    }
}

BENCHMARK(ec_recovery);
