/*
   Copyright 2023 The Silkworm Authors

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

#include "bor_rule_set.hpp"

#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/crypto/ecdsa.h>
#include <silkworm/core/types/evmc_bytes32.hpp>

#include "param.hpp"

namespace silkworm::protocol {

static bool is_sprint_start(BlockNum number, uint64_t sprint_size) {
    // N.B. Works fine for the specific Polygon sprint size config, but is flawed in general
    // (e.g. it wouldn't work for {0->5, 10->3})
    return number % sprint_size == 0;
}

ValidationResult BorRuleSet::validate_block_header(const BlockHeader& header, const BlockState& state,
                                                   bool with_future_timestamp_check) {
    if (!is_zero(header.prev_randao)) {
        return ValidationResult::kInvalidMixDigest;
    }

    ValidationResult res{BaseRuleSet::validate_block_header(header, state, with_future_timestamp_check)};
    if (res != ValidationResult::kOk) {
        return res;
    }

    const std::optional<BlockHeader> parent{get_parent_header(state, header)};
    const uint64_t* period{bor::config_value_lookup(config().period, header.number)};
    SILKWORM_ASSERT(period);
    if (parent->timestamp + *period > header.timestamp) {
        return ValidationResult::kInvalidTimestamp;
    }

    // TODO(yperbasis): verify validators
    // https://github.com/maticnetwork/bor/blob/v1.1.0-beta4/consensus/bor/bor.go#L465

    return ValidationResult::kOk;
}

// validate_extra_data validates that the extra-data contains both the vanity and signature.
// header.Extra = header.Vanity + header.ProducerBytes (optional) + header.Seal
ValidationResult BorRuleSet::validate_extra_data(const BlockHeader& header) const {
    static constexpr size_t kExtraVanityLength{32};
    static constexpr size_t kValidatorHeaderLength{kAddressLength + 20};  // address + power

    // See https://github.com/maticnetwork/bor/blob/v1.0.6/consensus/bor/bor.go#L393
    if (header.extra_data.length() < kExtraVanityLength) {
        return ValidationResult::kMissingVanity;
    }
    if (header.extra_data.length() < kExtraVanityLength + kExtraSealSize) {
        return ValidationResult::kMissingSignature;
    }

    // The end of a sprint at block n == the start of next sprint at block n+1
    // See https://github.com/maticnetwork/bor/blob/v1.0.6/consensus/bor/bor.go#L351
    const bool is_sprint_end{is_sprint_start(header.number + 1, config().sprint_size(header.number))};

    // Ensure that the extra-data contains a signer list on checkpoint, but none otherwise
    const size_t signers_length{header.extra_data.length() - (kExtraVanityLength + kExtraSealSize)};
    if (!is_sprint_end && signers_length != 0) {
        return ValidationResult::kExtraValidators;
    }
    if (is_sprint_end && signers_length % kValidatorHeaderLength != 0) {
        return ValidationResult::kInvalidSpanValidators;
    }

    return ValidationResult::kOk;
}

static std::optional<evmc::address> ecrecover(const BlockHeader& header, const BlockNum jaipur_block) {
    evmc::bytes32 seal_hash{header.hash(/*for_sealing=*/false, /*exclude_extra_data_sig=*/true)};
    if (header.base_fee_per_gas && header.number < jaipur_block) {
        // See https://github.com/maticnetwork/bor/pull/269
        BlockHeader copy{header};
        copy.base_fee_per_gas = std::nullopt;
        seal_hash = copy.hash(/*for_sealing=*/false, /*exclude_extra_data_sig=*/true);
    }

    ByteView signature{&header.extra_data[header.extra_data.length() - kExtraSealSize], kExtraSealSize - 1};
    uint8_t recovery_id{header.extra_data[header.extra_data.length() - 1]};

    static secp256k1_context* context{secp256k1_context_create(SILKWORM_SECP256K1_CONTEXT_FLAGS)};
    evmc::address beneficiary;
    if (!silkworm_recover_address(beneficiary.bytes, seal_hash.bytes, signature.data(), recovery_id, context)) {
        return std::nullopt;
    }
    return beneficiary;
}

static void rewrite_code_if_needed(const SmallMap<BlockNum, SmallMap<evmc::address, std::string_view>>& rewrite_code,
                                   IntraBlockState& state, BlockNum block_num) {
    const SmallMap<evmc::address, std::string_view>* rewrites{rewrite_code.find(block_num)};
    if (!rewrites) {
        return;
    }
    for (const auto& [address, code] : *rewrites) {
        state.set_code(address, string_view_to_byte_view(code));
    }
}

void BorRuleSet::finalize(IntraBlockState& state, const Block& block) {
    const BlockNum header_number{block.header.number};
    if (is_sprint_start(header_number, config().sprint_size(header_number))) {
        // TODO(yperbasis): implement
        // https://github.com/maticnetwork/bor/blob/v1.2.0/consensus/bor/bor.go#L827
    }

    rewrite_code_if_needed(config().rewrite_code, state, header_number);
}

ValidationResult BorRuleSet::validate_difficulty_and_seal(const BlockHeader& header, const BlockHeader&) {
    if (!ecrecover(header, config().jaipur_block)) {
        return ValidationResult::kInvalidSignature;
    }

    // TODO(yperbasis): implement
    // https://github.com/maticnetwork/bor/blob/v1.1.0-beta4/consensus/bor/bor.go#L654

    return ValidationResult::kOk;
}

evmc::address BorRuleSet::get_beneficiary(const BlockHeader& header) {
    return *ecrecover(header, config().jaipur_block);
}

// See https://github.com/maticnetwork/bor/blob/v1.0.6/core/bor_fee_log.go
void BorRuleSet::add_fee_transfer_log(IntraBlockState& state, const intx::uint256& amount, const evmc::address& sender,
                                      const intx::uint256& sender_initial_balance, const evmc::address& recipient,
                                      const intx::uint256& recipient_initial_balance) {
    SILKWORM_ASSERT(amount <= sender_initial_balance);

    static constexpr evmc::address kFeeAddress{0x0000000000000000000000000000000000001010_address};
    static constexpr evmc::bytes32 kTransferFeeLogSig{
        0x4dfe1bbbcf077ddc3e01291eea2d5c70c2b422b415d95645b9adcfd678cb1d63_bytes32};

    SILKWORM_THREAD_LOCAL Log log{
        .address = kFeeAddress,
        .topics = {
            kTransferFeeLogSig,
            to_bytes32(kFeeAddress.bytes),
            {},
            {},
        },
        .data = Bytes(32 * 5, 0),
    };

    log.topics[2] = to_bytes32(sender.bytes);
    log.topics[3] = to_bytes32(recipient.bytes);

    intx::be::unsafe::store(&log.data[32 * 0], amount);
    intx::be::unsafe::store(&log.data[32 * 1], sender_initial_balance);
    intx::be::unsafe::store(&log.data[32 * 2], recipient_initial_balance);
    intx::be::unsafe::store(&log.data[32 * 3], sender_initial_balance - amount);
    intx::be::unsafe::store(&log.data[32 * 4], recipient_initial_balance + amount);

    state.add_log(log);
}

const bor::Config& BorRuleSet::config() const {
    return std::get<bor::Config>(chain_config_.rule_set_config);
}

}  // namespace silkworm::protocol
