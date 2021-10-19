/*
Copyright 2021 The Silkworm Authors

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

#include <silkworm/common/base.hpp>

#include "preverified_hashes.hpp"

namespace silkworm {

using namespace evmc::literals;

PreverifiedHashes PreverifiedHashes::mainnet = {
    {
        0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3_bytes32,
        0x723899e82d352c6eabd21e34942f868687203ca14b3d5a23aeb47c555c123390_bytes32,

    },
    12690240  // mainnet_preverified_height
};

}  // namespace silkworm

