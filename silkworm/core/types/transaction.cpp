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

#include <cassert>

#include <ethash/keccak.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/crypto/ecdsa.h>
#include <silkworm/core/rlp/encode_vector.hpp>

#include "y_parity_and_chain_id.hpp"

namespace silkworm {

bool operator==(const Transaction& a, const Transaction& b) {
    // from is omitted since it's derived from the signature
    return a.type == b.type && a.nonce == b.nonce && a.max_priority_fee_per_gas == b.max_priority_fee_per_gas &&
           a.max_fee_per_gas == b.max_fee_per_gas && a.gas_limit == b.gas_limit && a.to == b.to && a.value == b.value &&
           a.data == b.data && a.odd_y_parity == b.odd_y_parity && a.chain_id == b.chain_id && a.r == b.r &&
           a.s == b.s && a.access_list == b.access_list;
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
    return true;
}

namespace rlp {

    static Header rlp_header(const AccessListEntry& e) {
        Header h{true, kAddressLength + 1};
        h.payload_length += length(e.storage_keys);
        return h;
    }

    size_t length(const AccessListEntry& e) {
        Header rlp_head{rlp_header(e)};
        return length_of_length(rlp_head.payload_length) + rlp_head.payload_length;
    }

    void encode(Bytes& to, const AccessListEntry& e) {
        encode_header(to, rlp_header(e));
        encode(to, e.account.bytes);
        encode(to, e.storage_keys);
    }

    template <>
    DecodingResult decode(ByteView& from, AccessListEntry& to) noexcept {
        const auto rlp_head{decode_header(from)};
        if (!rlp_head) {
            return tl::unexpected{rlp_head.error()};
        }
        if (!rlp_head->list) {
            return tl::unexpected{DecodingError::kUnexpectedString};
        }
        uint64_t leftover{from.length() - rlp_head->payload_length};

        if (DecodingResult res{decode(from, to.account.bytes)}; !res) {
            return res;
        }
        if (DecodingResult res{decode(from, to.storage_keys)}; !res) {
            return res;
        }

        if (from.length() != leftover) {
            return tl::unexpected{DecodingError::kListLengthMismatch};
        }
        return {};
    }

    static Header rlp_header(const Transaction& txn, bool for_signing) {
        Header h{true, 0};

        if (txn.type != Transaction::Type::kLegacy) {
            h.payload_length += length(txn.chain_id.value_or(0));
        }

        h.payload_length += length(txn.nonce);
        if (txn.type == Transaction::Type::kEip1559) {
            h.payload_length += length(txn.max_priority_fee_per_gas);
        }
        h.payload_length += length(txn.max_fee_per_gas);
        h.payload_length += length(txn.gas_limit);
        h.payload_length += txn.to ? (kAddressLength + 1) : 1;
        h.payload_length += length(txn.value);
        h.payload_length += length(txn.data);

        if (txn.type != Transaction::Type::kLegacy) {
            assert(txn.type == Transaction::Type::kEip2930 || txn.type == Transaction::Type::kEip1559);
            h.payload_length += length(txn.access_list);
        }

        if (!for_signing) {
            if (txn.type != Transaction::Type::kLegacy) {
                h.payload_length += length(txn.odd_y_parity);
            } else {
                h.payload_length += length(txn.v());
            }
            h.payload_length += length(txn.r);
            h.payload_length += length(txn.s);
        } else if (txn.type == Transaction::Type::kLegacy && txn.chain_id) {
            h.payload_length += length(*txn.chain_id) + 2;
        }

        return h;
    }

    size_t length(const Transaction& txn) {
        Header rlp_head{rlp_header(txn, /*for_signing=*/false)};
        auto rlp_len{static_cast<size_t>(length_of_length(rlp_head.payload_length) + rlp_head.payload_length)};
        if (txn.type != Transaction::Type::kLegacy) {
            // EIP-2718 transactions are wrapped into byte array in block RLP
            return length_of_length(rlp_len + 1) + rlp_len + 1;
        } else {
            return rlp_len;
        }
    }

    static void legacy_encode(Bytes& to, const Transaction& txn, bool for_signing) {
        encode_header(to, rlp_header(txn, for_signing));

        encode(to, txn.nonce);
        encode(to, txn.max_fee_per_gas);
        encode(to, txn.gas_limit);
        if (txn.to) {
            encode(to, txn.to->bytes);
        } else {
            to.push_back(kEmptyStringCode);
        }
        encode(to, txn.value);
        encode(to, txn.data);

        if (!for_signing) {
            encode(to, txn.v());
            encode(to, txn.r);
            encode(to, txn.s);
        } else if (txn.chain_id) {
            encode(to, *txn.chain_id);
            encode(to, 0u);
            encode(to, 0u);
        }
    }

    static void eip2718_encode(Bytes& to, const Transaction& txn, bool for_signing, bool wrap_into_array) {
        assert(txn.type == Transaction::Type::kEip2930 || txn.type == Transaction::Type::kEip1559);

        Header rlp_head{rlp_header(txn, for_signing)};

        if (wrap_into_array) {
            auto rlp_len{static_cast<size_t>(length_of_length(rlp_head.payload_length) + rlp_head.payload_length)};
            encode_header(to, {false, rlp_len + 1});
        }

        to.push_back(static_cast<uint8_t>(txn.type));

        encode_header(to, rlp_head);

        encode(to, txn.chain_id.value_or(0));

        encode(to, txn.nonce);
        if (txn.type == Transaction::Type::kEip1559) {
            encode(to, txn.max_priority_fee_per_gas);
        }
        encode(to, txn.max_fee_per_gas);
        encode(to, txn.gas_limit);
        if (txn.to) {
            encode(to, txn.to->bytes);
        } else {
            to.push_back(kEmptyStringCode);
        }
        encode(to, txn.value);
        encode(to, txn.data);
        encode(to, txn.access_list);

        if (!for_signing) {
            encode(to, txn.odd_y_parity);
            encode(to, txn.r);
            encode(to, txn.s);
        }
    }

    void encode(Bytes& to, const Transaction& txn, bool for_signing, bool wrap_eip2718_into_string) {
        if (txn.type == Transaction::Type::kLegacy) {
            legacy_encode(to, txn, for_signing);
        } else {
            eip2718_encode(to, txn, for_signing, wrap_eip2718_into_string);
        }
    }

    static DecodingResult legacy_decode(ByteView& from, Transaction& to) noexcept {
        if (DecodingResult res{decode(from, to.nonce)}; !res) {
            return res;
        }

        if (DecodingResult res{decode(from, to.max_priority_fee_per_gas)}; !res) {
            return res;
        }
        to.max_fee_per_gas = to.max_priority_fee_per_gas;

        if (DecodingResult res{decode(from, to.gas_limit)}; !res) {
            return res;
        }

        if (from[0] == kEmptyStringCode) {
            to.to = std::nullopt;
            from.remove_prefix(1);
        } else {
            to.to = evmc::address{};
            if (DecodingResult res{decode(from, to.to->bytes)}; !res) {
                return res;
            }
        }

        if (DecodingResult res{decode(from, to.value)}; !res) {
            return res;
        }
        if (DecodingResult res{decode(from, to.data)}; !res) {
            return res;
        }

        intx::uint256 v;
        if (DecodingResult res{decode(from, v)}; !res) {
            return res;
        }
        if (!to.set_v(v)) {
            return tl::unexpected{DecodingError::kInvalidVInSignature};
        }

        if (DecodingResult res{decode(from, to.r)}; !res) {
            return res;
        }
        if (DecodingResult res{decode(from, to.s)}; !res) {
            return res;
        }

        to.access_list.clear();

        return {};
    }

    static DecodingResult eip2718_decode(ByteView& from, Transaction& to) noexcept {
        if (to.type != Transaction::Type::kEip2930 && to.type != Transaction::Type::kEip1559) {
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
        if (DecodingResult res{decode(from, chain_id)}; !res) {
            return res;
        }
        to.chain_id = chain_id;

        if (DecodingResult res{decode(from, to.nonce)}; !res) {
            return res;
        }

        if (DecodingResult res{decode(from, to.max_priority_fee_per_gas)}; !res) {
            return res;
        }
        if (to.type == Transaction::Type::kEip2930) {
            to.max_fee_per_gas = to.max_priority_fee_per_gas;
        } else if (DecodingResult res{decode(from, to.max_fee_per_gas)}; !res) {
            return res;
        }

        if (DecodingResult res{decode(from, to.gas_limit)}; !res) {
            return res;
        }

        if (from[0] == kEmptyStringCode) {
            to.to = std::nullopt;
            from.remove_prefix(1);
        } else {
            to.to = evmc::address{};
            if (DecodingResult res{decode(from, to.to->bytes)}; !res) {
                return res;
            }
        }

        if (DecodingResult res{decode(from, to.value)}; !res) {
            return res;
        }
        if (DecodingResult res{decode(from, to.data)}; !res) {
            return res;
        }
        if (DecodingResult res{decode(from, to.access_list)}; !res) {
            return res;
        }
        if (DecodingResult res{decode(from, to.odd_y_parity)}; !res) {
            return res;
        }
        if (DecodingResult res{decode(from, to.r)}; !res) {
            return res;
        }
        if (DecodingResult res{decode(from, to.s)}; !res) {
            return res;
        }

        return {};
    }

    DecodingResult decode_transaction(ByteView& from, Transaction& to, Eip2718Wrapping allowed) noexcept {
        to.from.reset();

        if (from.empty()) {
            return tl::unexpected{DecodingError::kInputTooShort};
        }

        if (0 < from[0] && from[0] < kEmptyStringCode) {  // Raw serialization of a typed transaction
            if (allowed == Eip2718Wrapping::kString) {
                return tl::unexpected{DecodingError::kUnexpectedEip2718Serialization};
            }

            to.type = static_cast<Transaction::Type>(from[0]);
            from.remove_prefix(1);

            return eip2718_decode(from, to);
        }

        const auto h{decode_header(from)};
        if (!h) {
            return tl::unexpected{h.error()};
        }

        if (h->list) {  // Legacy transaction
            to.type = Transaction::Type::kLegacy;
            uint64_t leftover{from.length() - h->payload_length};
            if (DecodingResult res{legacy_decode(from, to)}; !res) {
                return res;
            }
            if (from.length() != leftover) {
                return tl::unexpected{DecodingError::kListLengthMismatch};
            }
            return {};
        }

        // String-wrapped typed transaction

        if (allowed == Eip2718Wrapping::kNone) {
            return tl::unexpected{DecodingError::kUnexpectedEip2718Serialization};
        }

        if (h->payload_length == 0) {
            return tl::unexpected{DecodingError::kInputTooShort};
        }

        to.type = static_cast<Transaction::Type>(from[0]);
        from.remove_prefix(1);

        ByteView eip2718_view{from.substr(0, h->payload_length - 1)};

        if (DecodingResult res{eip2718_decode(eip2718_view, to)}; !res) {
            return res;
        }

        if (!eip2718_view.empty()) {
            return tl::unexpected{DecodingError::kListLengthMismatch};
        }

        from.remove_prefix(h->payload_length - 1);
        return {};
    }

    DecodingResult decode_transaction_header_and_type(ByteView& from, Header& header, Transaction::Type& type) noexcept {
        if (from.empty()) {
            return tl::unexpected{DecodingError::kInputTooShort};
        }

        const auto header_res{decode_header(from)};
        if (!header_res) {
            return tl::unexpected{header_res.error()};
        }
        header = *header_res;

        if (header.list) {  // Legacy transaction
            type = Transaction::Type::kLegacy;
            return {};
        }

        // String-wrapped typed transaction
        if (header.payload_length == 0) {
            return tl::unexpected{DecodingError::kInputTooShort};
        }

        type = static_cast<Transaction::Type>(from[0]);
        from.remove_prefix(1);
        return {};
    }

}  // namespace rlp

void Transaction::recover_sender() {
    if (from.has_value()) {
        return;
    }
    Bytes rlp{};
    rlp::encode(rlp, *this, /*for_signing=*/true, /*wrap_eip2718_into_string=*/false);
    ethash::hash256 hash{keccak256(rlp)};

    uint8_t signature[kHashLength * 2];
    intx::be::unsafe::store(signature, r);
    intx::be::unsafe::store(signature + kHashLength, s);

    from = evmc::address{};
    static secp256k1_context* context{secp256k1_context_create(SILKWORM_SECP256K1_CONTEXT_FLAGS)};
    if (!silkworm_recover_address(from->bytes, hash.bytes, signature, odd_y_parity, context)) {
        from = std::nullopt;
    }
}

intx::uint256 Transaction::priority_fee_per_gas(const intx::uint256& base_fee_per_gas) const {
    assert(max_fee_per_gas >= base_fee_per_gas);
    return std::min(max_priority_fee_per_gas, max_fee_per_gas - base_fee_per_gas);
}

intx::uint256 Transaction::effective_gas_price(const intx::uint256& base_fee_per_gas) const {
    return priority_fee_per_gas(base_fee_per_gas) + base_fee_per_gas;
}

}  // namespace silkworm
