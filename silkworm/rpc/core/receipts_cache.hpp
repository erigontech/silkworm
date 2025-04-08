// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstddef>
#include <memory>

#include <evmc/evmc.hpp>

#include <silkworm/core/common/lru_cache.hpp>
#include <silkworm/rpc/types/receipt.hpp>

namespace silkworm::rpc {

class ReceiptCache {
  public:
    explicit ReceiptCache(size_t capacity = 1024 * 1000, bool shared_cache = true)
        : receipt_cache_(capacity, shared_cache) {}

    std::optional<std::shared_ptr<Receipt>> get(const evmc::bytes32& key) {
        return receipt_cache_.get_as_copy(key);
    }

    void insert(const evmc::bytes32& key, const std::shared_ptr<Receipt>& block) {
        receipt_cache_.put(key, block);
    }

  private:
    LruCache<evmc::bytes32, std::shared_ptr<Receipt>> receipt_cache_;
};

class ReceiptsCache {
  public:
    explicit ReceiptsCache(size_t capacity = 1024, bool shared_cache = true)
        : receipts_cache_(capacity, shared_cache) {}

    std::optional<std::shared_ptr<Receipts>> get(const evmc::bytes32& key) {
        return receipts_cache_.get_as_copy(key);
    }

    void insert(const evmc::bytes32& key, const std::shared_ptr<Receipts>& receipt) {
        receipts_cache_.put(key, receipt);
    }

  private:
    LruCache<evmc::bytes32, std::shared_ptr<Receipts>> receipts_cache_;
};

}  // namespace silkworm::rpc
