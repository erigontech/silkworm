// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "block.hpp"

#include <bit>

#include <silkworm/core/protocol/param.hpp>
#include <silkworm/core/rlp/decode_vector.hpp>
#include <silkworm/core/rlp/encode_vector.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>

namespace silkworm {

evmc::bytes32 BlockHeader::hash(bool for_sealing, bool exclude_extra_data_sig) const {
    Bytes rlp;
    rlp::encode(rlp, *this, for_sealing, exclude_extra_data_sig);
    return std::bit_cast<evmc_bytes32>(keccak256(rlp));
}

ethash::hash256 BlockHeader::boundary() const {
    using intx::operator""_u256;
    static const intx::uint320 kDividend = intx::uint320{1} << 256;
    intx::uint256 result =
        (difficulty > 1u)
            ? intx::uint256{kDividend / difficulty}
            : 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_u256;
    return intx::be::store<ethash::hash256>(result);
}

// Approximates factor*e^(numerator/denominator) using Taylor expansion.
// See https://eips.ethereum.org/EIPS/eip-4844#helpers
static intx::uint256 fake_exponential(const intx::uint256& factor,
                                      const intx::uint256& numerator,
                                      const intx::uint256& denominator) {
    intx::uint256 output{0};
    intx::uint256 numerator_accum{factor * denominator};
    for (unsigned i{1}; numerator_accum > 0; ++i) {
        output += numerator_accum;
        numerator_accum = (numerator_accum * numerator) / (denominator * i);
    }
    return output / denominator;
}

intx::uint256 calc_blob_gas_price(uint64_t excess_blob_gas, evmc_revision revision) {
    // EIP-7691: Blob throughput increase
    const auto price_update_fraction = revision >= EVMC_PRAGUE ? protocol::kBlobGasPriceUpdateFractionPrague : protocol::kBlobGasPriceUpdateFraction;
    return fake_exponential(
        protocol::kMinBlobGasPrice,
        excess_blob_gas,
        price_update_fraction);
}

std::optional<intx::uint256> BlockHeader::blob_gas_price() const {
    if (!excess_blob_gas) {
        return std::nullopt;
    }
    const auto revision = requests_hash ? EVMC_PRAGUE : EVMC_CANCUN;
    return calc_blob_gas_price(*excess_blob_gas, revision);
}

namespace rlp {

    static Header rlp_header(const BlockHeader& header, bool for_sealing = false, bool exclude_extra_data_sig = false) {
        Header rlp_head{.list = true};
        rlp_head.payload_length += kHashLength + 1;                                        // parent_hash
        rlp_head.payload_length += kHashLength + 1;                                        // ommers_hash
        rlp_head.payload_length += kAddressLength + 1;                                     // beneficiary
        rlp_head.payload_length += kHashLength + 1;                                        // state_root
        rlp_head.payload_length += kHashLength + 1;                                        // transactions_root
        rlp_head.payload_length += kHashLength + 1;                                        // receipts_root
        rlp_head.payload_length += kBloomByteLength + length_of_length(kBloomByteLength);  // logs_bloom
        rlp_head.payload_length += length(header.difficulty);                              // difficulty
        rlp_head.payload_length += length(header.number);                                  // block height
        rlp_head.payload_length += length(header.gas_limit);                               // gas_limit
        rlp_head.payload_length += length(header.gas_used);                                // gas_used
        rlp_head.payload_length += length(header.timestamp);                               // timestamp
        if (exclude_extra_data_sig) {
            const auto extra_data_no_signature = header.extra_data.substr(0, header.extra_data.length() - protocol::kExtraSealSize);
            rlp_head.payload_length += length(extra_data_no_signature);  // extra_data -signature
        } else {
            rlp_head.payload_length += length(header.extra_data);  // extra_data
        }
        if (!for_sealing) {
            rlp_head.payload_length += kHashLength + 1;  // prev_randao
            rlp_head.payload_length += 8 + 1;            // nonce
        }
        if (header.base_fee_per_gas) {
            rlp_head.payload_length += length(*header.base_fee_per_gas);
        }
        if (header.withdrawals_root) {
            rlp_head.payload_length += kHashLength + 1;
        }
        if (header.blob_gas_used) {
            rlp_head.payload_length += length(*header.blob_gas_used);
        }
        if (header.excess_blob_gas) {
            rlp_head.payload_length += length(*header.excess_blob_gas);
        }
        if (header.parent_beacon_block_root) {
            rlp_head.payload_length += kHashLength + 1;
        }
        if (header.requests_hash) {
            rlp_head.payload_length += kHashLength + 1;
        }

        return rlp_head;
    }

    size_t length(const BlockHeader& header) {
        const Header rlp_head{rlp_header(header)};
        return length_of_length(rlp_head.payload_length) + rlp_head.payload_length;
    }

    void encode(Bytes& to, const BlockHeader& header, bool for_sealing, bool exclude_extra_data_sig) {
        encode_header(to, rlp_header(header, for_sealing, exclude_extra_data_sig));
        encode(to, header.parent_hash);
        encode(to, header.ommers_hash);
        encode(to, header.beneficiary);
        encode(to, header.state_root);
        encode(to, header.transactions_root);
        encode(to, header.receipts_root);
        encode(to, header.logs_bloom);
        encode(to, header.difficulty);
        encode(to, header.number);
        encode(to, header.gas_limit);
        encode(to, header.gas_used);
        encode(to, header.timestamp);
        if (exclude_extra_data_sig) {
            SILKWORM_ASSERT(header.extra_data.length() >= protocol::kExtraSealSize);
            const ByteView extra_data_no_signature{header.extra_data.data(), header.extra_data.length() - protocol::kExtraSealSize};
            encode(to, extra_data_no_signature);
        } else {
            encode(to, header.extra_data);
        }
        if (!for_sealing) {
            encode(to, header.prev_randao);
            encode(to, header.nonce);
        }
        if (header.base_fee_per_gas) {
            encode(to, *header.base_fee_per_gas);
        }
        if (header.withdrawals_root) {
            encode(to, *header.withdrawals_root);
        }
        if (header.blob_gas_used) {
            encode(to, *header.blob_gas_used);
        }
        if (header.excess_blob_gas) {
            encode(to, *header.excess_blob_gas);
        }
        if (header.parent_beacon_block_root) {
            encode(to, *header.parent_beacon_block_root);
        }
        if (header.requests_hash) {
            encode(to, *header.requests_hash);
        }
    }

    DecodingResult decode(ByteView& from, BlockHeader& to, Leftover mode) noexcept {
        const auto rlp_head{decode_header(from)};
        if (!rlp_head) {
            return tl::unexpected{rlp_head.error()};
        }
        if (!rlp_head->list) {
            return tl::unexpected{DecodingError::kUnexpectedString};
        }
        const uint64_t leftover{from.length() - rlp_head->payload_length};
        if (mode != Leftover::kAllow && leftover) {
            return tl::unexpected{DecodingError::kInputTooLong};
        }

        if (DecodingResult res{decode_items(from,
                                            to.parent_hash.bytes,
                                            to.ommers_hash.bytes,
                                            to.beneficiary.bytes,
                                            to.state_root.bytes,
                                            to.transactions_root.bytes,
                                            to.receipts_root.bytes,
                                            to.logs_bloom,
                                            to.difficulty,
                                            to.number,
                                            to.gas_limit,
                                            to.gas_used,
                                            to.timestamp,
                                            to.extra_data,
                                            to.prev_randao.bytes,
                                            to.nonce)};
            !res) {
            return res;
        }

        if (from.length() > leftover) {
            to.base_fee_per_gas = 0;
            if (DecodingResult res{decode(from, *to.base_fee_per_gas, Leftover::kAllow)}; !res) {
                return res;
            }
        } else {
            to.base_fee_per_gas = std::nullopt;
        }

        if (from.length() > leftover) {
            to.withdrawals_root = evmc::bytes32{};
            if (DecodingResult res{decode(from, *to.withdrawals_root, Leftover::kAllow)}; !res) {
                return res;
            }
        } else {
            to.withdrawals_root = std::nullopt;
        }

        if (from.length() > leftover) {
            to.blob_gas_used = 0;
            to.excess_blob_gas = 0;
            to.parent_beacon_block_root = evmc::bytes32{};
            if (DecodingResult res{decode_items(from, *to.blob_gas_used, *to.excess_blob_gas,
                                                *to.parent_beacon_block_root)};
                !res) {
                return res;
            }
        } else {
            to.blob_gas_used = std::nullopt;
            to.excess_blob_gas = std::nullopt;
            to.parent_beacon_block_root = std::nullopt;
        }

        if (from.length() > leftover) {
            to.requests_hash = evmc::bytes32{};
            if (DecodingResult res{decode(from, *to.requests_hash, Leftover::kAllow)}; !res) {
                return res;
            }
        } else {
            to.requests_hash = std::nullopt;
        }

        if (from.length() != leftover) {
            return tl::unexpected{DecodingError::kUnexpectedListElements};
        }
        return {};
    }

    static Header rlp_header_body(const BlockBody& b) {
        Header rlp_head{.list = true};
        rlp_head.payload_length += length(b.transactions);
        rlp_head.payload_length += length(b.ommers);
        if (b.withdrawals) {
            rlp_head.payload_length += length(*b.withdrawals);
        }
        return rlp_head;
    }

    size_t length(const BlockBody& block_body) {
        const Header rlp_head{rlp_header_body(block_body)};
        return length_of_length(rlp_head.payload_length) + rlp_head.payload_length;
    }

    void encode(Bytes& to, const BlockBody& block_body) {
        encode_header(to, rlp_header_body(block_body));
        encode(to, block_body.transactions);
        encode(to, block_body.ommers);
        if (block_body.withdrawals) {
            encode(to, *block_body.withdrawals);
        }
    }

    DecodingResult decode(ByteView& from, BlockBody& to, Leftover mode) noexcept {
        const auto rlp_head{decode_header(from)};
        if (!rlp_head) {
            return tl::unexpected{rlp_head.error()};
        }
        if (!rlp_head->list) {
            return tl::unexpected{DecodingError::kUnexpectedString};
        }
        const uint64_t leftover{from.length() - rlp_head->payload_length};
        if (mode != Leftover::kAllow && leftover) {
            return tl::unexpected{DecodingError::kInputTooLong};
        }

        if (DecodingResult res{decode_items(from, to.transactions, to.ommers)}; !res) {
            return res;
        }

        to.withdrawals = std::nullopt;
        if (from.length() > leftover) {
            std::vector<Withdrawal> withdrawals;
            if (DecodingResult res{decode(from, withdrawals, Leftover::kAllow)}; !res) {
                return res;
            }
            to.withdrawals = withdrawals;
        }

        if (from.length() != leftover) {
            return tl::unexpected{DecodingError::kUnexpectedListElements};
        }
        return {};
    }

    DecodingResult decode(ByteView& from, Block& to, Leftover mode) noexcept {
        const auto rlp_head{decode_header(from)};
        if (!rlp_head) {
            return tl::unexpected{rlp_head.error()};
        }
        if (!rlp_head->list) {
            return tl::unexpected{DecodingError::kUnexpectedString};
        }
        const uint64_t leftover{from.length() - rlp_head->payload_length};
        if (mode != Leftover::kAllow && leftover) {
            return tl::unexpected{DecodingError::kInputTooLong};
        }

        if (DecodingResult res{decode_items(from, to.header, to.transactions, to.ommers)}; !res) {
            return res;
        }

        to.withdrawals = std::nullopt;
        if (from.length() > leftover) {
            std::vector<Withdrawal> withdrawals;
            if (DecodingResult res{decode(from, withdrawals, Leftover::kAllow)}; !res) {
                return res;
            }
            to.withdrawals = withdrawals;
        }

        if (from.length() != leftover) {
            return tl::unexpected{DecodingError::kUnexpectedListElements};
        }
        return {};
    }

    static Header rlp_header(const Block& b) {
        Header rlp_head{rlp_header_body(b)};
        rlp_head.payload_length += length(b.header);
        return rlp_head;
    }

    size_t length(const Block& block) {
        const Header rlp_head{rlp_header(block)};
        return length_of_length(rlp_head.payload_length) + rlp_head.payload_length;
    }

    void encode(Bytes& to, const Block& block) {
        encode_header(to, rlp_header(block));
        encode(to, block.header);
        encode(to, block.transactions);
        encode(to, block.ommers);
        if (block.withdrawals) {
            encode(to, *block.withdrawals);
        }
    }

}  // namespace rlp
}  // namespace silkworm
