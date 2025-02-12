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

#include "transaction.hpp"

#include <bit>

#include <ethash/keccak.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/crypto/ecdsa.h>
#include <silkworm/core/protocol/param.hpp>
#include <silkworm/core/rlp/decode_vector.hpp>
#include <silkworm/core/rlp/encode_vector.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>

#include "y_parity_and_chain_id.hpp"

namespace silkworm {

void Authorization::recover_authority() {
    Bytes rlp{};
    rlp::encode_for_signing(rlp, *this);

    ethash::hash256 hash{keccak256(rlp)};

    uint8_t signature[kHashLength * 2 + 1];
    intx::be::unsafe::store(signature, r);
    intx::be::unsafe::store(signature + kHashLength, s);
    intx::be::unsafe::store(signature + 2 * kHashLength, y_parity);

    recovered_authority = evmc::address{};
    static secp256k1_context* context{secp256k1_context_create(SILKWORM_SECP256K1_CONTEXT_FLAGS)};
    if (!silkworm_recover_address(recovered_authority->bytes, hash.bytes, signature, y_parity, context)) {
        recovered_authority = std::nullopt;
    }
}

intx::uint256 Authorization::v() {
    return y_parity_and_chain_id_to_v(y_parity, chain_id);
}

// https://eips.ethereum.org/EIPS/eip-155
intx::uint256 Transaction::v() const { return y_parity_and_chain_id_to_v(odd_y_parity, chain_id); }

// https://eips.ethereum.org/EIPS/eip-155
bool Transaction::set_v(const intx::uint256& v) {
    const std::optional<YParityAndChainId> parity_and_id{v_to_y_parity_and_chain_id(v)};
    if (parity_and_id == std::nullopt) {
        return false;
    }
    odd_y_parity = parity_and_id->odd;
    chain_id = parity_and_id->chain_id;
    reset();
    return true;
}

evmc::bytes32 Transaction::hash() const {
    hash_computed_.call_once([this]() {
        Bytes rlp;
        rlp::encode(rlp, *this, /*wrap_eip2718_into_string=*/false);
        cached_hash_ = std::bit_cast<evmc_bytes32>(keccak256(rlp));
    });
    return cached_hash_;
}

namespace rlp {

    static Header header(const AccessListEntry& e) {
        return {.list = true, .payload_length = kAddressLength + 1 + length(e.storage_keys)};
    }

    size_t length(const AccessListEntry& e) {
        Header h{header(e)};
        return length_of_length(h.payload_length) + h.payload_length;
    }

    void encode(Bytes& to, const AccessListEntry& e) {
        encode_header(to, header(e));
        encode(to, e.account);
        encode(to, e.storage_keys);
    }

    static Header header(const Authorization& authorization) {
        Header header{.list = true};
        header.payload_length = length(authorization.chain_id);
        header.payload_length += kAddressLength + 1;  // address is kAddressLength and one byte for size prefix
        header.payload_length += length(authorization.nonce);
        header.payload_length += length(authorization.y_parity);
        header.payload_length += length(authorization.r);
        header.payload_length += length(authorization.s);

        return header;
    }

    size_t length(const Authorization& authorization) {
        Header h{header(authorization)};
        return length_of_length(h.payload_length) + h.payload_length;
    }

    void encode(Bytes& to, const Authorization& authorization) {
        encode_header(to, header(authorization));
        encode(to, authorization.chain_id);
        encode(to, authorization.address);
        encode(to, authorization.nonce);
        encode(to, authorization.y_parity);
        encode(to, authorization.r);
        encode(to, authorization.s);
    }

    void encode_for_signing(Bytes& to, const Authorization& authorization) {
        Header header{.list = true};
        header.payload_length = length(authorization.chain_id);
        header.payload_length += kAddressLength + 1;  // address is kAddressLength and one byte for size prefix
        header.payload_length += length(authorization.nonce);

        // See: Eip-7720 Set EOA account code
        constexpr unsigned char kMagic{0x05};

        to.push_back(kMagic);
        encode_header(to, header);
        encode(to, authorization.chain_id);
        encode(to, authorization.address);
        encode(to, authorization.nonce);
    }

    DecodingResult decode(ByteView& from, AccessListEntry& to, Leftover mode) noexcept {
        return decode(from, mode, to.account.bytes, to.storage_keys);
    }

    DecodingResult decode(ByteView& from, Authorization& to, Leftover mode) noexcept {
        return decode(from, mode, to.chain_id, to.address.bytes, to.nonce, to.y_parity, to.r, to.s);
    }

    static Header header_base(const UnsignedTransaction& txn) {
        Header h{.list = true};

        if (txn.type != TransactionType::kLegacy) {
            h.payload_length += length(txn.chain_id.value_or(0));
        }

        h.payload_length += length(txn.nonce);
        if (txn.type == TransactionType::kDynamicFee || txn.type == TransactionType::kBlob || txn.type == TransactionType::kSetCode) {
            h.payload_length += length(txn.max_priority_fee_per_gas);
        }
        h.payload_length += length(txn.max_fee_per_gas);
        h.payload_length += length(txn.gas_limit);
        h.payload_length += txn.to ? (kAddressLength + 1) : 1;
        h.payload_length += length(txn.value);
        h.payload_length += length(txn.data);

        if (txn.type != TransactionType::kLegacy) {
            h.payload_length += length(txn.access_list);
            if (txn.type == TransactionType::kBlob) {
                h.payload_length += length(txn.max_fee_per_blob_gas);
                h.payload_length += length(txn.blob_versioned_hashes);
            }
            if (txn.type == TransactionType::kSetCode) {
                h.payload_length += length(txn.authorizations);
            }
        }

        return h;
    }

    static Header header(const UnsignedTransaction& txn) {
        Header h{header_base(txn)};
        if (txn.type == TransactionType::kLegacy && txn.chain_id) {
            h.payload_length += length(*txn.chain_id) + 2;
        }
        return h;
    }

    static Header header(const Transaction& txn) {
        Header h{header_base(txn)};

        if (txn.type != TransactionType::kLegacy) {
            h.payload_length += length(txn.odd_y_parity);
        } else {
            h.payload_length += length(txn.v());
        }
        h.payload_length += length(txn.r);
        h.payload_length += length(txn.s);

        return h;
    }

    size_t length(const Transaction& txn, bool wrap_eip2718_into_string) {
        Header h{header(txn)};
        size_t rlp_len{length_of_length(h.payload_length) + h.payload_length};
        if (txn.type != TransactionType::kLegacy && wrap_eip2718_into_string) {
            return length_of_length(rlp_len + 1) + rlp_len + 1;
        }
        return rlp_len;
    }

    static void legacy_encode_base(Bytes& to, const UnsignedTransaction& txn) {
        encode(to, txn.nonce);
        encode(to, txn.max_fee_per_gas);
        encode(to, txn.gas_limit);
        if (txn.to) {
            encode(to, *txn.to);
        } else {
            to.push_back(kEmptyStringCode);
        }
        encode(to, txn.value);
        encode(to, txn.data);
    }

    static void eip2718_encode_for_signing(Bytes& to, const UnsignedTransaction& txn, const Header h,
                                           bool wrap_eip2718_into_string) {
        if (wrap_eip2718_into_string) {
            auto rlp_len{static_cast<size_t>(length_of_length(h.payload_length) + h.payload_length)};
            encode_header(to, {false, rlp_len + 1});
        }

        to.push_back(static_cast<uint8_t>(txn.type));

        encode_header(to, h);

        encode(to, txn.chain_id.value_or(0));

        encode(to, txn.nonce);
        if (txn.type != TransactionType::kAccessList) {
            encode(to, txn.max_priority_fee_per_gas);
        }
        encode(to, txn.max_fee_per_gas);
        encode(to, txn.gas_limit);
        if (txn.to) {
            encode(to, *txn.to);
        } else {
            to.push_back(kEmptyStringCode);
        }
        encode(to, txn.value);
        encode(to, txn.data);
        encode(to, txn.access_list);

        if (txn.type == TransactionType::kBlob) {
            encode(to, txn.max_fee_per_blob_gas);
            encode(to, txn.blob_versioned_hashes);
        }

        if (txn.type == TransactionType::kSetCode) {
            encode(to, txn.authorizations);
        }
    }

    void encode(Bytes& to, const Transaction& txn, bool wrap_eip2718_into_string) {
        if (txn.type == TransactionType::kLegacy) {
            encode_header(to, header(txn));
            legacy_encode_base(to, txn);
            encode(to, txn.v());
            encode(to, txn.r);
            encode(to, txn.s);
        } else {
            eip2718_encode_for_signing(to, txn, header(txn), wrap_eip2718_into_string);
            encode(to, txn.odd_y_parity);
            encode(to, txn.r);
            encode(to, txn.s);
        }
    }

    static DecodingResult legacy_decode_items(ByteView& from, Transaction& to) noexcept {
        if (DecodingResult res{decode_items(from, to.nonce, to.max_priority_fee_per_gas)}; !res) {
            return res;
        }
        to.max_fee_per_gas = to.max_priority_fee_per_gas;

        if (DecodingResult res{decode(from, to.gas_limit, Leftover::kAllow)}; !res) {
            return res;
        }

        if (from[0] == kEmptyStringCode) {
            to.to = std::nullopt;
            from.remove_prefix(1);
        } else {
            to.to = evmc::address{};
            if (DecodingResult res{decode(from, to.to->bytes, Leftover::kAllow)}; !res) {
                return res;
            }
        }

        intx::uint256 v;
        if (DecodingResult res{decode_items(from, to.value, to.data, v)}; !res) {
            return res;
        }
        if (!to.set_v(v)) {
            return tl::unexpected{DecodingError::kInvalidVInSignature};
        }

        return decode_items(from, to.r, to.s);
    }

    static DecodingResult eip2718_decode(ByteView& from, Transaction& to) noexcept {
        if (to.type != TransactionType::kAccessList &&
            to.type != TransactionType::kDynamicFee &&
            to.type != TransactionType::kBlob &&
            to.type != TransactionType::kSetCode) {
            return tl::unexpected{DecodingError::kUnsupportedTransactionType};
        }

        const auto h{decode_header(from)};
        if (!h) {
            return tl::unexpected{h.error()};
        }
        if (!h->list) {
            return tl::unexpected{DecodingError::kUnexpectedString};
        }

        intx::uint256 chain_id;
        if (DecodingResult res{decode(from, chain_id, Leftover::kAllow)}; !res) {
            return res;
        }
        to.chain_id = chain_id;

        if (DecodingResult res{decode_items(from, to.nonce, to.max_priority_fee_per_gas)}; !res) {
            return res;
        }

        if (to.type == TransactionType::kAccessList) {
            to.max_fee_per_gas = to.max_priority_fee_per_gas;
        } else if (DecodingResult res{decode(from, to.max_fee_per_gas, Leftover::kAllow)}; !res) {
            return res;
        }

        if (DecodingResult res{decode(from, to.gas_limit, Leftover::kAllow)}; !res) {
            return res;
        }

        if (from[0] == kEmptyStringCode) {
            to.to = std::nullopt;
            from.remove_prefix(1);
        } else {
            to.to = evmc::address{};
            if (DecodingResult res{decode(from, to.to->bytes, Leftover::kAllow)}; !res) {
                return res;
            }
        }

        if (DecodingResult res{decode_items(from, to.value, to.data, to.access_list)}; !res) {
            return res;
        }

        if (to.type != TransactionType::kBlob) {
            to.max_fee_per_blob_gas = 0;
            to.blob_versioned_hashes.clear();
        } else if (DecodingResult res{decode_items(from, to.max_fee_per_blob_gas, to.blob_versioned_hashes)}; !res) {
            return res;
        }

        if (to.type == TransactionType::kSetCode) {
            if (DecodingResult res{decode(from, to.authorizations, Leftover::kAllow)}; !res) {
                return res;
            }
        }

        return decode_items(from, to.odd_y_parity, to.r, to.s);
    }

    DecodingResult decode_transaction(ByteView& from, Transaction& to, Eip2718Wrapping accepted_typed_txn_wrapping,
                                      Leftover mode) noexcept {
        to.reset();

        if (from.empty()) {
            return tl::unexpected{DecodingError::kInputTooShort};
        }

        if (0 < from[0] && from[0] < kEmptyStringCode) {  // Raw serialization of a typed transaction
            if (accepted_typed_txn_wrapping == Eip2718Wrapping::kString) {
                return tl::unexpected{DecodingError::kUnexpectedEip2718Serialization};
            }

            to.type = static_cast<TransactionType>(from[0]);
            from.remove_prefix(1);

            return eip2718_decode(from, to);
        }

        const auto h{decode_header(from)};
        if (!h) {
            return tl::unexpected{h.error()};
        }

        if (h->list) {  // Legacy transaction
            to.type = TransactionType::kLegacy;
            to.access_list.clear();
            to.max_fee_per_blob_gas = 0;
            to.blob_versioned_hashes.clear();

            const uint64_t leftover{from.length() - h->payload_length};
            if (mode != Leftover::kAllow && leftover) {
                return tl::unexpected{DecodingError::kInputTooLong};
            }
            if (DecodingResult res{legacy_decode_items(from, to)}; !res) {
                return res;
            }
            if (from.length() != leftover) {
                return tl::unexpected{DecodingError::kUnexpectedListElements};
            }
            return {};
        }

        // String-wrapped typed transaction

        if (accepted_typed_txn_wrapping == Eip2718Wrapping::kNone) {
            return tl::unexpected{DecodingError::kUnexpectedEip2718Serialization};
        }

        if (h->payload_length == 0) {
            return tl::unexpected{DecodingError::kInputTooShort};
        }

        to.type = static_cast<TransactionType>(from[0]);
        from.remove_prefix(1);

        ByteView eip2718_view{from.substr(0, h->payload_length - 1)};

        if (DecodingResult res{eip2718_decode(eip2718_view, to)}; !res) {
            return res;
        }

        if (!eip2718_view.empty()) {
            return tl::unexpected{DecodingError::kUnexpectedListElements};
        }

        from.remove_prefix(h->payload_length - 1);
        if (mode != Leftover::kAllow && !from.empty()) {
            return tl::unexpected{DecodingError::kInputTooLong};
        }
        return {};
    }

    DecodingResult decode_transaction_header_and_type(ByteView& from, Header& header, TransactionType& type) noexcept {
        if (from.empty()) {
            return tl::unexpected{DecodingError::kInputTooShort};
        }

        const auto header_res{decode_header(from)};
        if (!header_res) {
            return tl::unexpected{header_res.error()};
        }
        header = *header_res;

        if (header.list) {  // Legacy transaction
            type = TransactionType::kLegacy;
            return {};
        }

        // String-wrapped typed transaction
        if (header.payload_length == 0) {
            return tl::unexpected{DecodingError::kInputTooShort};
        }

        type = static_cast<TransactionType>(from[0]);
        from.remove_prefix(1);
        return {};
    }

}  // namespace rlp

void UnsignedTransaction::encode_for_signing(Bytes& into) const {
    if (type == TransactionType::kLegacy) {
        rlp::encode_header(into, rlp::header(*this));
        rlp::legacy_encode_base(into, *this);
        if (chain_id) {
            rlp::encode(into, *chain_id);
            rlp::encode(into, 0u);
            rlp::encode(into, 0u);
        }
    } else {
        rlp::eip2718_encode_for_signing(into, *this, rlp::header(*this), /*wrap_eip2718_into_string=*/false);
    }
}

std::optional<evmc::address> Transaction::sender() const {
    sender_recovered_.call_once([this]() {
        Bytes rlp{};
        encode_for_signing(rlp);
        ethash::hash256 hash{keccak256(rlp)};

        uint8_t signature[kHashLength * 2];
        intx::be::unsafe::store(signature, r);
        intx::be::unsafe::store(signature + kHashLength, s);

        sender_ = evmc::address{};
        static secp256k1_context* context{secp256k1_context_create(SILKWORM_SECP256K1_CONTEXT_FLAGS)};
        if (!silkworm_recover_address(sender_->bytes, hash.bytes, signature, odd_y_parity, context)) {
            sender_ = std::nullopt;
        }
    });
    return sender_;
}

void Transaction::set_sender(const evmc::address& sender) {
    sender_recovered_.reset();
    sender_recovered_.call_once([&]() {
        sender_ = sender;
    });
}

void Transaction::reset() {
    sender_recovered_.reset();
    hash_computed_.reset();
}

intx::uint512 UnsignedTransaction::maximum_gas_cost() const {
    // See https://github.com/ethereum/EIPs/pull/3594
    intx::uint512 max_gas_cost{intx::umul(intx::uint256{gas_limit}, max_fee_per_gas)};
    // and https://eips.ethereum.org/EIPS/eip-4844#gas-accounting
    max_gas_cost += intx::umul(intx::uint256{total_blob_gas()}, max_fee_per_blob_gas);
    return max_gas_cost;
}

intx::uint256 UnsignedTransaction::priority_fee_per_gas(const intx::uint256& base_fee_per_gas) const {
    SILKWORM_ASSERT(max_fee_per_gas >= base_fee_per_gas);
    return std::min(max_priority_fee_per_gas, max_fee_per_gas - base_fee_per_gas);
}

intx::uint256 UnsignedTransaction::effective_gas_price(const intx::uint256& base_fee_per_gas) const {
    if (type == TransactionType::kSystem) {
        return 0;
    }
    return priority_fee_per_gas(base_fee_per_gas) + base_fee_per_gas;
}

uint64_t UnsignedTransaction::total_blob_gas() const {
    return protocol::kGasPerBlob * blob_versioned_hashes.size();
}

}  // namespace silkworm
