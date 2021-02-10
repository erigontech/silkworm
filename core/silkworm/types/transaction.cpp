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

#include <cstring>
#include <ethash/keccak.hpp>
#include <silkworm/common/util.hpp>
#include <silkworm/crypto/ecdsa.hpp>
#include <silkworm/rlp/encode.hpp>
namespace silkworm {

bool operator==(const Transaction& a, const Transaction& b) {
    return a.nonce == b.nonce && a.gas_price == b.gas_price && a.gas_limit == b.gas_limit && a.to == b.to &&
           a.value == b.value && a.data == b.data && a.v == b.v && a.r == b.r && a.s == b.s;
}

namespace rlp {

    static Header rlp_header(const Transaction& txn, bool for_signing, std::optional<uint64_t> eip155_chain_id) {
        Header h{true, 0};
        h.payload_length += length(txn.nonce);
        h.payload_length += length(txn.gas_price);
        h.payload_length += length(txn.gas_limit);
        h.payload_length += txn.to ? (kAddressLength + 1) : 1;
        h.payload_length += length(txn.value);
        h.payload_length += length(txn.data);
        if (!for_signing) {
            h.payload_length += length(txn.v);
            h.payload_length += length(txn.r);
            h.payload_length += length(txn.s);
        } else if (eip155_chain_id) {
            h.payload_length += length(*eip155_chain_id) + 2;
        }
        return h;
    }

    size_t length(const Transaction& txn) {
        Header rlp_head = rlp_header(txn, /*for_signing=*/false, {});
        return length_of_length(rlp_head.payload_length) + rlp_head.payload_length;
    }

    void encode(Bytes& to, const Transaction& txn, bool for_signing, std::optional<uint64_t> eip155_chain_id) {
        encode_header(to, rlp_header(txn, for_signing, eip155_chain_id));
        encode(to, txn.nonce);
        encode(to, txn.gas_price);
        encode(to, txn.gas_limit);
        if (txn.to) {
            encode(to, txn.to->bytes);
        } else {
            to.push_back(kEmptyStringCode);
        }
        encode(to, txn.value);
        encode(to, txn.data);
        if (!for_signing) {
            encode(to, txn.v);
            encode(to, txn.r);
            encode(to, txn.s);
        } else if (eip155_chain_id) {
            encode(to, *eip155_chain_id);
            encode(to, 0);
            encode(to, 0);
        };
    }

    void encode(Bytes& to, const Transaction& txn) { encode(to, txn, /*for_signing=*/false, {}); }

    template <>
    DecodingResult decode(ByteView& from, Transaction& to) noexcept {
        auto [h, err]{decode_header(from)};
        if (err != DecodingResult::kOk) {
            return err;
        }
        if (!h.list) {
            return DecodingResult::kUnexpectedString;
        }
        uint64_t leftover{from.length() - h.payload_length};

        if (DecodingResult err{decode(from, to.nonce)}; err != DecodingResult::kOk) {
            return err;
        }
        if (DecodingResult err{decode(from, to.gas_price)}; err != DecodingResult::kOk) {
            return err;
        }
        if (DecodingResult err{decode(from, to.gas_limit)}; err != DecodingResult::kOk) {
            return err;
        }

        if (from[0] == kEmptyStringCode) {
            to.to = {};
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
        if (DecodingResult err{decode(from, to.v)}; err != DecodingResult::kOk) {
            return err;
        }
        if (DecodingResult err{decode(from, to.r)}; err != DecodingResult::kOk) {
            return err;
        }
        if (DecodingResult err{decode(from, to.s)}; err != DecodingResult::kOk) {
            return err;
        }

        return from.length() == leftover ? DecodingResult::kOk : DecodingResult::kListLengthMismatch;
    }

}  // namespace rlp

void Transaction::recover_sender(bool homestead, std::optional<uint64_t> eip155_chain_id) {
    from.reset();

    if (!silkworm::ecdsa::is_valid_signature(r, s, homestead)) {
        return;
    }

    ecdsa::RecoveryId x{ecdsa::get_signature_recovery_id(v)};
    if (x.eip155_chain_id && x.eip155_chain_id != eip155_chain_id) {
        return;
    }

    Bytes rlp{};
    bool for_signing{true};
    if (x.eip155_chain_id) {
        rlp::encode(rlp, *this, for_signing, eip155_chain_id);
    } else {
        rlp::encode(rlp, *this, for_signing, {});
    }
    ethash::hash256 hash{keccak256(rlp)};

    uint8_t signature[32 * 2];
    intx::be::unsafe::store(signature, r);
    intx::be::unsafe::store(signature + 32, s);

    std::optional<Bytes> recovered{ecdsa::recover(full_view(hash.bytes), full_view(signature), x.recovery_id)};
    if (recovered) {
        hash = ethash::keccak256(recovered->data() + 1, recovered->length() - 1);
        from = evmc::address{};
        std::memcpy(from->bytes, &hash.bytes[12], 32 - 12);
    }
}
}  // namespace silkworm
