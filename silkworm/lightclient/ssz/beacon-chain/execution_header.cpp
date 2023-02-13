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

#include "execution_header.hpp"

namespace eth {
    std::vector<ssz::Chunk> ExecutionHeader::hash_tree() const {
        return hash_tree_({&parent_hash_,
                           &fee_recipient_,
                           &state_root_,
                           &receipts_root_,
                           &logs_bloom_,
                           &prev_randao_,
                           &block_number_,
                           &gas_limit_,
                           &gas_used_,
                           &timestamp_,
                           &extra_data_,
                           &base_fee_per_gas_,
                           &block_hash_,
                           &transient_root_});
    }
    BytesVector ExecutionHeader::serialize() const {
        return serialize_({&parent_hash_,
                           &fee_recipient_,
                           &state_root_,
                           &receipts_root_,
                           &logs_bloom_,
                           &prev_randao_,
                           &block_number_,
                           &gas_limit_,
                           &gas_used_,
                           &timestamp_,
                           &extra_data_,
                           &base_fee_per_gas_,
                           &block_hash_,
                           &transient_root_});
    }

    bool ExecutionHeader::deserialize(ssz::SSZIterator it, ssz::SSZIterator end) {
        return deserialize_(it, end, {&parent_hash_,
                                      &fee_recipient_,
                                      &state_root_,
                                      &receipts_root_,
                                      &logs_bloom_,
                                      &prev_randao_,
                                      &block_number_,
                                      &gas_limit_,
                                      &gas_used_,
                                      &timestamp_,
                                      &extra_data_,
                                      &base_fee_per_gas_,
                                      &block_hash_,
                                      &transient_root_});
    }

    /*YAML::Node ExecutionHeader::encode() const {
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
                        {"transient_root", &transient_root_}});
    }
    bool ExecutionHeader::decode(const YAML::Node &node) {
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
                              {"transient_root", &transient_root_}});
    }*/
} // namespace eth
