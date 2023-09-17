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

#pragma once

#include <optional>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/sentry/common/ecc_public_key.hpp>
#include <silkworm/sentry/discovery/common/node_address.hpp>

namespace silkworm::sentry::discovery::enr {

struct EnrRecord {
    EccPublicKey public_key;
    uint64_t seq_num;
    std::optional<NodeAddress> address_v4;
    std::optional<NodeAddress> address_v6;
    std::optional<Bytes> eth1_fork_id_data;
    std::optional<Bytes> eth2_fork_id_data;
    std::optional<Bytes> eth2_attestation_subnets_data;
};

}  // namespace silkworm::sentry::discovery::enr
