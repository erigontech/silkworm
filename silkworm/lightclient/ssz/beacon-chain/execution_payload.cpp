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

#include "execution_payload.hpp"

namespace eth {

std::vector<ssz::Chunk> ExecutionPayload::hash_tree() const {
    return hash_tree_({&parent_hash,
                       &fee_recipient,
                       &state_root,
                       &receipts_root,
                       &logs_bloom,
                       &prev_randao,
                       &block_number,
                       &gas_limit,
                       &gas_used,
                       &timestamp,
                       &extra_data,
                       &base_fee_per_gas,
                       &block_hash,
                       &transactions});
}
BytesVector ExecutionPayload::serialize() const {
    return serialize_({&parent_hash,
                       &fee_recipient,
                       &state_root,
                       &receipts_root,
                       &logs_bloom,
                       &prev_randao,
                       &block_number,
                       &gas_limit,
                       &gas_used,
                       &timestamp,
                       &extra_data,
                       &base_fee_per_gas,
                       &block_hash,
                       &transactions});
}

bool ExecutionPayload::deserialize(ssz::SSZIterator it, ssz::SSZIterator end) {
    return deserialize_(it, end, {&parent_hash,
                                  &fee_recipient,
                                  &state_root,
                                  &receipts_root,
                                  &logs_bloom,
                                  &prev_randao,
                                  &block_number,
                                  &gas_limit,
                                  &gas_used,
                                  &timestamp,
                                  &extra_data,
                                  &base_fee_per_gas,
                                  &block_hash,
                                  &transactions});
}

/*YAML::Node ExecutionPayload::encode() const {
    return encode_({{"parent_hash", &parent_hash_},
                    {"fee_recipient", &fee_recipient_},
                    {"state_root", &state_root_},
                    {"receipts_root", &receipts_root_},
                    {"logs_bloom", &logs_bloom_},
                    {"prev_randao", &prev_randao_},
                    {"block_number", &block_number_},
                    {"gas_limit", &gas_limit_},
                    {"gas_used", &gas_used_},
                    {"timestamp", &timestamp_},
                    {"extra_data", &extra_data_},
                    {"base_fee_per_gas", &base_fee_per_gas_},
                    {"block_hash", &block_hash_},
                    {"transactions", &transactions}});
}

bool ExecutionPayload::decode(const YAML::Node &node) {
    return decode_(node, {{"parent_hash", &parent_hash_},
                          {"fee_recipient", &fee_recipient_},
                          {"state_root", &state_root_},
                          {"receipts_root", &receipts_root_},
                          {"logs_bloom", &logs_bloom_},
                          {"prev_randao", &prev_randao_},
                          {"block_number", &block_number_},
                          {"gas_limit", &gas_limit_},
                          {"gas_used", &gas_used_},
                          {"timestamp", &timestamp_},
                          {"extra_data", &extra_data_},
                          {"base_fee_per_gas", &base_fee_per_gas_},
                          {"block_hash", &block_hash_},
                          {"transactions", &transactions}});
}*/

} // namespace eth
