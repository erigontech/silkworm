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
