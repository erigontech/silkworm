/*
   Copyright 2020-2021 The Silkworm Authors

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
#include <cstring>

#include <ethash/keccak.hpp>

#include <silkworm/common/util.hpp>
#include <silkworm/crypto/ecdsa.hpp>
#include <silkworm/rlp/encode.hpp>

namespace silkworm {

bool operator==(const AccessListEntry& a, const AccessListEntry& b) {
    return a.account == b.account && a.storage_keys == b.storage_keys;
}

bool operator==(const Transaction& a, const Transaction& b) {
    // from is omitted since it's derived from the signature
    return a.type == b.type && a.nonce == b.nonce && a.max_priority_fee_per_gas == b.max_priority_fee_per_gas &&
           a.max_fee_per_gas == b.max_fee_per_gas && a.gas_limit == b.gas_limit && a.to == b.to && a.value == b.value &&
           a.data == b.data && a.odd_y_parity == b.odd_y_parity && a.chain_id == b.chain_id && a.r == b.r &&
           a.s == b.s && a.access_list == b.access_list;
}

// https://eips.ethereum.org/EIPS/eip-155
intx::uint256 Transaction::v() const { return ecdsa::y_parity_and_chain_id_to_v(odd_y_parity, chain_id); }

// https://eips.ethereum.org/EIPS/eip-155
void Transaction::set_v(const intx::uint256& v) {
    ecdsa::YParityAndChainId y{ecdsa::v_to_y_parity_and_chain_id(v)};
    odd_y_parity = y.odd;
    chain_id = y.chain_id;
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
        auto [rlp_head, err]{decode_header(from)};
        if (err != DecodingResult::kOk) {
            return err;
        }
        if (!rlp_head.list) {
            return DecodingResult::kUnexpectedString;
        }
        uint64_t leftover{from.length() - rlp_head.payload_length};

        if (DecodingResult err{decode(from, to.account.bytes)}; err != DecodingResult::kOk) {
            return err;
        }
        if (DecodingResult err{decode_vector(from, to.storage_keys)}; err != DecodingResult::kOk) {
            return err;
        }

        return from.length() == leftover ? DecodingResult::kOk : DecodingResult::kListLengthMismatch;
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
            encode(to, 0);
            encode(to, 0);
        };
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
        };
    }

    void encode(Bytes& to, const Transaction& txn, bool for_signing, bool wrap_eip2718_into_array) {
        if (txn.type == Transaction::Type::kLegacy) {
            legacy_encode(to, txn, for_signing);
        } else {
            eip2718_encode(to, txn, for_signing, wrap_eip2718_into_array);
        }
    }

    void encode(Bytes& to, const Transaction& txn) {
        encode(to, txn, /*for_signing=*/false, /*wrap_eip2718_as_array=*/true);
    }

    static DecodingResult legacy_decode(ByteView& from, Transaction& to) noexcept {
        if (DecodingResult err{decode(from, to.nonce)}; err != DecodingResult::kOk) {
            return err;
        }

        if (DecodingResult err{decode(from, to.max_priority_fee_per_gas)}; err != DecodingResult::kOk) {
            return err;
        }
        to.max_fee_per_gas = to.max_priority_fee_per_gas;

        if (DecodingResult err{decode(from, to.gas_limit)}; err != DecodingResult::kOk) {
            return err;
        }

        if (from[0] == kEmptyStringCode) {
            to.to = std::nullopt;
            from.remove_prefix(1);
        } else {
            to.to = evmc::address{};
            if (DecodingResult err{decode(from, to.to->bytes)}; err != DecodingResult::kOk) {
                return err;
            }
        }

        if (DecodingResult err{decode(from, to.value)}; err != DecodingResult::kOk) {
            return err;
        }
        if (DecodingResult err{decode(from, to.data)}; err != DecodingResult::kOk) {
            return err;
        }

        intx::uint256 v;
        if (DecodingResult err{decode(from, v)}; err != DecodingResult::kOk) {
            return err;
        }
        to.set_v(v);

        if (DecodingResult err{decode(from, to.r)}; err != DecodingResult::kOk) {
            return err;
        }
        if (DecodingResult err{decode(from, to.s)}; err != DecodingResult::kOk) {
            return err;
        }

        return DecodingResult::kOk;
    }

    static DecodingResult eip2718_decode(ByteView& from, Transaction& to) noexcept {
        assert(to.type == Transaction::Type::kEip2930 || to.type == Transaction::Type::kEip1559);

        auto [h, err]{decode_header(from)};
        if (err != DecodingResult::kOk) {
            return err;
        }
        if (!h.list) {
            return DecodingResult::kUnexpectedString;
        }

        intx::uint256 chain_id;
        if (DecodingResult err{decode(from, chain_id)}; err != DecodingResult::kOk) {
            return err;
        }
        to.chain_id = chain_id;

        if (DecodingResult err{decode(from, to.nonce)}; err != DecodingResult::kOk) {
            return err;
        }

        if (DecodingResult err{decode(from, to.max_priority_fee_per_gas)}; err != DecodingResult::kOk) {
            return err;
        }
        if (to.type == Transaction::Type::kEip2930) {
            to.max_fee_per_gas = to.max_priority_fee_per_gas;
        } else if (DecodingResult err{decode(from, to.max_fee_per_gas)}; err != DecodingResult::kOk) {
            return err;
        }

        if (DecodingResult err{decode(from, to.gas_limit)}; err != DecodingResult::kOk) {
            return err;
        }

        if (from[0] == kEmptyStringCode) {
            to.to = std::nullopt;
            from.remove_prefix(1);
        } else {
            to.to = evmc::address{};
            if (DecodingResult err{decode(from, to.to->bytes)}; err != DecodingResult::kOk) {
                return err;
            }
        }

        if (DecodingResult err{decode(from, to.value)}; err != DecodingResult::kOk) {
            return err;
        }
        if (DecodingResult err{decode(from, to.data)}; err != DecodingResult::kOk) {
            return err;
        }
        if (DecodingResult err{decode_vector(from, to.access_list)}; err != DecodingResult::kOk) {
            return err;
        }
        if (DecodingResult err{decode(from, to.odd_y_parity)}; err != DecodingResult::kOk) {
            return err;
        }
        if (DecodingResult err{decode(from, to.r)}; err != DecodingResult::kOk) {
            return err;
        }
        if (DecodingResult err{decode(from, to.s)}; err != DecodingResult::kOk) {
            return err;
        }

        return DecodingResult::kOk;
    }

    template <>
    DecodingResult decode(ByteView& from, Transaction& to) noexcept {
        auto [h, err]{decode_header(from)};
        if (err != DecodingResult::kOk) {
            return err;
        }

        if (h.list) {
            to.type = Transaction::Type::kLegacy;
            uint64_t leftover{from.length() - h.payload_length};
            if (DecodingResult err{legacy_decode(from, to)}; err != DecodingResult::kOk) {
                return err;
            }
            return from.length() == leftover ? DecodingResult::kOk : DecodingResult::kListLengthMismatch;
        }

        if (h.payload_length == 0) {
            return DecodingResult::kInputTooShort;
        }

        to.type = static_cast<Transaction::Type>(from[0]);
        from.remove_prefix(1);

        if (to.type != Transaction::Type::kEip2930 && to.type != Transaction::Type::kEip1559) {
            return DecodingResult::kUnsupportedTransactionType;
        }

        ByteView eip2718_view{from.substr(0, h.payload_length - 1)};

        if (DecodingResult err{eip2718_decode(eip2718_view, to)}; err != DecodingResult::kOk) {
            return err;
        }

        if (!eip2718_view.empty()) {
            return DecodingResult::kListLengthMismatch;
        }

        from.remove_prefix(h.payload_length - 1);
        return DecodingResult::kOk;
    }

}  // namespace rlp

void Transaction::recover_sender() {
    from.reset();

    Bytes rlp{};
    rlp::encode(rlp, *this, /*for_signing=*/true, /*wrap_eip2718_into_array=*/false);
    ethash::hash256 hash{keccak256(rlp)};

    uint8_t signature[32 * 2];
    intx::be::unsafe::store(signature, r);
    intx::be::unsafe::store(signature + 32, s);

    std::optional<Bytes> recovered{ecdsa::recover(full_view(hash.bytes), full_view(signature), odd_y_parity)};
    if (recovered) {
        hash = ethash::keccak256(recovered->data() + 1, recovered->length() - 1);
        from = evmc::address{};
        std::memcpy(from->bytes, &hash.bytes[12], 32 - 12);
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
