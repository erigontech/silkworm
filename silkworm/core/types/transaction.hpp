// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>
#include <vector>

#include <intx/intx.hpp>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/concurrency/resettable_once_flag.hpp>
#include <silkworm/core/rlp/decode.hpp>
#include <silkworm/core/types/hash.hpp>

namespace silkworm {

// EIP-2930: Optional access lists
struct AccessListEntry {
    evmc::address account{};
    std::vector<evmc::bytes32> storage_keys{};

    friend bool operator==(const AccessListEntry&, const AccessListEntry&) = default;
};

class Transaction;

// EIP-7702 Authorization
struct Authorization {
    intx::uint256 chain_id;
    evmc::address address;
    uint64_t nonce{};
    uint8_t y_parity{};
    intx::uint256 r;
    intx::uint256 s;

    friend bool operator==(const Authorization&, const Authorization&) = default;
    std::optional<evmc::address> recover_authority(const Transaction& txn) const;
    intx::uint256 v() const;
};

namespace eip7702 {
    // EIP-7702 Set EOA account code
    constexpr uint8_t kDelegationBytes[] = {0xef, 0x01, 0x00};
    constexpr ByteView kDelegationPrefix{kDelegationBytes, std::size(kDelegationBytes)};
    constexpr bool is_code_delegated(ByteView code) noexcept {
        return code.starts_with(kDelegationPrefix);
    }
}  // namespace eip7702

// EIP-2718 transaction type
// https://github.com/ethereum/eth1.0-specs/tree/master/lists/signature-types
enum class TransactionType : uint8_t {
    kLegacy = 0,
    kAccessList = 1,  // EIP-2930
    kDynamicFee = 2,  // EIP-1559
    kBlob = 3,        // EIP-4844
    kSetCode = 4,     // EIP-7702

    // System transactions are used for internal protocol operations like storing parent beacon root (EIP-4788).
    // They do not pay the base fee.
    kSystem = 0xff,
};

struct UnsignedTransaction {
    TransactionType type{TransactionType::kLegacy};

    std::optional<intx::uint256> chain_id{std::nullopt};  // nullopt means a pre-EIP-155 transaction

    uint64_t nonce{0};
    intx::uint256 max_priority_fee_per_gas{0};  // EIP-1559
    intx::uint256 max_fee_per_gas{0};
    uint64_t gas_limit{0};
    std::optional<evmc::address> to{std::nullopt};
    intx::uint256 value{0};
    Bytes data{};

    std::vector<AccessListEntry> access_list{};  // EIP-2930

    // EIP-4844: Shard Blob Transactions
    intx::uint256 max_fee_per_blob_gas{0};
    std::vector<Hash> blob_versioned_hashes{};

    // EIP-7702
    std::vector<Authorization> authorizations;

    //! \brief Maximum possible cost of normal and data (EIP-4844) gas
    intx::uint512 maximum_gas_cost() const;

    intx::uint256 priority_fee_per_gas(const intx::uint256& base_fee_per_gas) const;  // EIP-1559
    intx::uint256 effective_gas_price(const intx::uint256& base_fee_per_gas) const;   // EIP-1559

    uint64_t total_blob_gas() const;  // EIP-4844

    void encode_for_signing(Bytes& into) const;

    friend bool operator==(const UnsignedTransaction&, const UnsignedTransaction&) = default;
};

class Transaction : public UnsignedTransaction {
  public:
    bool odd_y_parity{false};
    intx::uint256 r{0}, s{0};  // signature

    intx::uint256 v() const;  // EIP-155

    //! \brief Returns false if v is not acceptable (v != 27 && v != 28 && v < 35, see EIP-155)
    bool set_v(const intx::uint256& v);

    //! \brief Sender recovered from the signature.
    //! \see Yellow Paper, Appendix F "Signing Transactions",
    //! EIP-2: Homestead Hard-fork Changes and
    //! EIP-155: Simple replay attack protection.
    //! If recovery fails std::nullopt is returned.
    std::optional<evmc::address> sender() const;

    void set_sender(const evmc::address& sender);

    evmc::bytes32 hash() const;

    //! Reset the computed values
    void reset();

  private:
    mutable std::optional<evmc::address> sender_{std::nullopt};
    mutable ResettableOnceFlag sender_recovered_;

    // cached value for hash if already computed
    mutable evmc::bytes32 cached_hash_;
    mutable ResettableOnceFlag hash_computed_;
};

namespace rlp {
    void encode(Bytes& to, const AccessListEntry&);
    size_t length(const AccessListEntry&);

    void encode(Bytes& to, const Authorization&);
    size_t length(const Authorization&);
    void encode_for_signing(Bytes& to, const Authorization&);

    // According to EIP-2718, serialized transactions are prepended with 1 byte containing the type
    // (0x02 for EIP-1559 transactions); the same goes for receipts. This is true for signing and
    // transaction root calculation. However, in block body RLP serialized EIP-2718 transactions
    // are additionally wrapped into an RLP byte array (=string). (Refer to the geth implementation;
    // EIP-2718 is mute on block RLP.)
    void encode(Bytes& to, const Transaction& txn, bool wrap_eip2718_into_string = true);

    size_t length(const Transaction&, bool wrap_eip2718_into_string = true);

    DecodingResult decode(ByteView& from, AccessListEntry& to, Leftover mode = Leftover::kProhibit) noexcept;

    enum class Eip2718Wrapping {
        kNone,    // Serialized typed transactions must start with its type byte, e.g. 0x02
        kString,  // Serialized typed transactions must be additionally wrapped into an RLP string (=byte array)
        kBoth,    // Both options above are accepted
    };

    DecodingResult decode_transaction(ByteView& from, Transaction& to, Eip2718Wrapping accepted_typed_txn_wrapping,
                                      Leftover mode = Leftover::kProhibit) noexcept;

    inline DecodingResult decode(ByteView& from, Transaction& to, Leftover mode = Leftover::kProhibit) noexcept {
        return decode_transaction(from, to, Eip2718Wrapping::kString, mode);
    }

    DecodingResult decode_transaction_header_and_type(ByteView& from, Header& header, TransactionType& type) noexcept;
}  // namespace rlp

}  // namespace silkworm
