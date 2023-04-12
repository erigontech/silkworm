// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "account.hpp"
#include "bloom_filter.hpp"
#include "hash_utils.hpp"
#include <cassert>
#include <optional>
#include <variant>
#include <vector>

namespace evmone::state
{
class State
{
    std::unordered_map<address, Account> m_accounts;

public:
    /// Inserts the new account at the address.
    /// There must not exist any account under this address before.
    Account& insert(const address& addr, Account account = {})
    {
        const auto r = m_accounts.insert({addr, std::move(account)});
        assert(r.second);
        return r.first->second;
    }

    /// Returns the pointer to the account at the address if the account exists. Null otherwise.
    Account* find(const address& addr) noexcept
    {
        const auto it = m_accounts.find(addr);
        if (it != m_accounts.end())
            return &it->second;
        return nullptr;
    }

    /// Gets the account at the address (the account must exist).
    Account& get(const address& addr) noexcept
    {
        auto acc = find(addr);
        assert(acc != nullptr);
        return *acc;
    }

    /// Gets an existing account or inserts new account.
    Account& get_or_insert(const address& addr, Account account = {})
    {
        if (const auto acc = find(addr); acc != nullptr)
            return *acc;
        return insert(addr, std::move(account));
    }

    /// Touches (as in EIP-161) an existing account or inserts new erasable account.
    Account& touch(const address& addr)
    {
        auto& acc = get_or_insert(addr);
        acc.erasable = true;
        return acc;
    }

    [[nodiscard]] auto& get_accounts() noexcept { return m_accounts; }

    [[nodiscard]] const auto& get_accounts() const noexcept { return m_accounts; }
};

struct BlockInfo
{
    int64_t number = 0;
    int64_t timestamp = 0;
    int64_t gas_limit = 0;
    address coinbase;
    bytes32 prev_randao;
    uint64_t base_fee = 0;
};

using AccessList = std::vector<std::pair<address, std::vector<bytes32>>>;

struct Transaction
{
    enum class Kind
    {
        legacy,
        eip1559
    };

    Kind kind = Kind::legacy;
    bytes data;
    int64_t gas_limit;
    intx::uint256 max_gas_price;
    intx::uint256 max_priority_gas_price;
    address sender;
    std::optional<address> to;
    intx::uint256 value;
    AccessList access_list;
    uint64_t chain_id = 0;
    uint64_t nonce = 0;
    intx::uint256 r;
    intx::uint256 s;
    uint8_t v = 0;
};

struct Log
{
    address addr;
    bytes data;
    std::vector<hash256> topics;
};

struct TransactionReceipt
{
    Transaction::Kind kind = Transaction::Kind::legacy;
    evmc_status_code status = EVMC_INTERNAL_ERROR;
    int64_t gas_used = 0;
    std::vector<Log> logs;
    BloomFilter logs_bloom_filter;
};

[[nodiscard]] std::variant<TransactionReceipt, std::error_code> transition(
    State& state, const BlockInfo& block, const Transaction& tx, evmc_revision rev, evmc::VM& vm);

/// Defines how to RLP-encode a Transaction.
[[nodiscard]] bytes rlp_encode(const Transaction& tx);

/// Defines how to RLP-encode a TransactionReceipt.
[[nodiscard]] bytes rlp_encode(const TransactionReceipt& receipt);

/// Defines how to RLP-encode a Log.
[[nodiscard]] bytes rlp_encode(const Log& log);

}  // namespace evmone::state
