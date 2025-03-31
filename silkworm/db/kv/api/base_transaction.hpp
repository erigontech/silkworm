// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <functional>

#include "transaction.hpp"

namespace silkworm::db::kv::api {

class BaseTransaction : public Transaction {
  public:
    explicit BaseTransaction(StateCache* state_cache) : state_cache_{state_cache} {}

    StateCache* state_cache() override { return state_cache_; }

    bool is_local() const override { return false; }

    Task<KeyValue> get(const std::string& table, ByteView key) override;

    Task<Bytes> get_one(const std::string& table, ByteView key) override;

    Task<std::optional<Bytes>> get_both_range(const std::string& table, ByteView key, ByteView subkey) override;

  private:
    StateCache* state_cache_;
};

}  // namespace silkworm::db::kv::api
