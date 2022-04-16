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

#ifndef SILKWORM_RPC_STATE_CHANGE_COLLECTION_HPP_
#define SILKWORM_RPC_STATE_CHANGE_COLLECTION_HPP_

#include <functional>
#include <map>
#include <vector>

#include <evmc/evmc.hpp>
#include <gsl/pointers>

#include <remote/kv.pb.h>
#include <silkworm/common/util.hpp>

namespace silkworm::rpc {

using StateChangeBatchCallback = std::function<void(const remote::StateChangeBatch&)>;

class StateChangeCollection {
  public:
    explicit StateChangeCollection() = default;

    void reset(uint64_t tx_id);

    void start_new_block(BlockNum block_height, const evmc::bytes32& block_hash, const std::vector<Bytes>&& tx_rlps, bool unwind);

    void change_account(const evmc::address& address, uint64_t incarnation, const Bytes& data);

    void delete_account(const evmc::address& address);

    void change_code(const evmc::address& address, uint64_t incarnation, const Bytes& code);

    void change_storage(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& location, const Bytes& data);

    void register_consumer(StateChangeBatchCallback consumer);

    void notify_batch(uint64_t pending_base_fee, uint64_t gas_limit);

    uint64_t tx_id() const { return tx_id_; }

  private:
    uint64_t tx_id_{0};
    remote::StateChangeBatch state_changes_;
    remote::StateChange* latest_change_{nullptr};
    std::map<evmc::address, std::size_t> account_change_index_;
    std::map<evmc::address, std::map<evmc::bytes32, std::size_t>> storage_change_index_;
    std::vector<StateChangeBatchCallback> batch_consumers_;
};

} // namespace silkworm::rpc

#endif // SILKWORM_RPC_STATE_CHANGE_COLLECTION_HPP_
