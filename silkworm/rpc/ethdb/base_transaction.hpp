/*
   Copyright 2024 The Silkworm Authors

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

#include <functional>

#include "kv/state_cache.hpp"
#include "transaction.hpp"

namespace silkworm::rpc::ethdb {

class BaseTransaction : public Transaction {
  public:
    explicit BaseTransaction(kv::StateCache* state_cache) : state_cache_{state_cache} {}

    void set_state_cache_enabled(bool cache_enabled) override;

    Task<KeyValue> get(const std::string& table, ByteView key) override;

    Task<silkworm::Bytes> get_one(const std::string& table, ByteView key) override;

    Task<std::optional<Bytes>> get_both_range(const std::string& table, ByteView key, ByteView subkey) override;

  private:
    Task<silkworm::Bytes> get_one_impl_no_cache(const std::string& table, ByteView key);
    Task<silkworm::Bytes> get_one_impl_with_cache(const std::string& table, ByteView key);

    using GetOneImpl = Task<silkworm::Bytes> (BaseTransaction::*)(const std::string&, ByteView);
    GetOneImpl get_one_impl_no_cache_{&BaseTransaction::get_one_impl_no_cache};
    GetOneImpl get_one_impl_with_cache_{&BaseTransaction::get_one_impl_with_cache};
    GetOneImpl get_one_impl_{get_one_impl_no_cache_};
    kv::StateCache* state_cache_;
};

}  // namespace silkworm::rpc::ethdb
