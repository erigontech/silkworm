// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "bor_rule_set.hpp"

#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/crypto/ecdsa.h>
#include <silkworm/core/types/evmc_bytes32.hpp>

#include "param.hpp"

namespace silkworm::protocol {

static bool is_sprint_start(BlockNum block_num, uint64_t sprint_size) {
    // N.B. Works fine for the specific Polygon sprint size config, but is flawed in general
    // (e.g. it wouldn't work for {0->5, 10->3})
    return block_num % sprint_size == 0;
}

ValidationResult BorRuleSet::validate_block_header(const BlockHeader& header, const BlockState& state,
                                                   bool with_future_timestamp_check) {
    if (!is_zero(header.prev_randao)) {
        return ValidationResult::kInvalidMixDigest;
    }

    ValidationResult res{RuleSet::validate_block_header(header, state, with_future_timestamp_check)};
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
    if (header.extra_data.size() < kExtraVanityLength) {
        return ValidationResult::kMissingVanity;
    }
    if (header.extra_data.size() < kExtraVanityLength + kExtraSealSize) {
        return ValidationResult::kMissingSignature;
    }

    // The end of a sprint at block n == the start of next sprint at block n+1
    // See https://github.com/maticnetwork/bor/blob/v1.0.6/consensus/bor/bor.go#L351
    const bool is_sprint_end{is_sprint_start(header.number + 1, config().sprint_size(header.number))};

    // Ensure that the extra-data contains a signer list on checkpoint, but none otherwise
    const size_t signers_length{header.extra_data.size() - (kExtraVanityLength + kExtraSealSize)};
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

    ByteView signature{&header.extra_data[header.extra_data.size() - kExtraSealSize], kExtraSealSize - 1};
    uint8_t recovery_id{header.extra_data[header.extra_data.size() - 1]};

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

ValidationResult BorRuleSet::finalize(IntraBlockState& state, const Block& block, EVM&, const std::vector<Log>&) {
    const BlockNum header_number{block.header.number};
    if (is_sprint_start(header_number, config().sprint_size(header_number))) {
        // TODO(yperbasis): implement
        // https://github.com/maticnetwork/bor/blob/v1.2.0/consensus/bor/bor.go#L827
    }

    rewrite_code_if_needed(config().rewrite_code, state, header_number);

    return ValidationResult::kOk;
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

namespace {
    // See https://github.com/maticnetwork/bor/blob/v1.3.7/core/bor_fee_log.go
    void add_transfer_log(IntraBlockState& state, const evmc::bytes32& event_sig, const evmc::address& sender,
                          const evmc::address& recipient, const intx::uint256& amount,
                          const intx::uint256& input1, const intx::uint256& input2,
                          const intx::uint256& output1, const intx::uint256& output2) {
        if (amount == 0) {
            return;
        }
        static constexpr evmc::address kFeeAddress{0x0000000000000000000000000000000000001010_address};
        SILKWORM_THREAD_LOCAL Log log{
            .address = kFeeAddress,
            .topics = {
                {},
                to_bytes32(kFeeAddress.bytes),
                {},
                {},
            },
            .data = Bytes(32 * 5, 0),
        };
        log.topics[0] = event_sig;
        log.topics[2] = to_bytes32(sender.bytes);
        log.topics[3] = to_bytes32(recipient.bytes);

        intx::be::unsafe::store(&log.data[32 * 0], amount);
        intx::be::unsafe::store(&log.data[32 * 1], input1);
        intx::be::unsafe::store(&log.data[32 * 2], input2);
        intx::be::unsafe::store(&log.data[32 * 3], output1);
        intx::be::unsafe::store(&log.data[32 * 4], output2);

        state.add_log(log);
    }

    void bor_transfer(IntraBlockState& state, const evmc::address& sender, const evmc::address& recipient,
                      const intx::uint256& amount, bool bailout) {
        static constexpr evmc::bytes32 kTransferLogSig{
            0xe6497e3ee548a3372136af2fcb0696db31fc6cf20260707645068bd3fe97f3c4_bytes32};
        intx::uint256 sender_initial_balance{state.get_balance(sender)};
        intx::uint256 recipient_initial_balance{state.get_balance(recipient)};
        // TODO(yperbasis) why is the bailout condition different from that of Erigon?
        if (!bailout || sender_initial_balance >= amount) {
            state.subtract_from_balance(sender, amount);
        }
        state.add_to_balance(recipient, amount);
        intx::uint256 output1{state.get_balance(sender)};
        intx::uint256 output2{state.get_balance(recipient)};
        add_transfer_log(state, kTransferLogSig, sender, recipient, amount, sender_initial_balance,
                         recipient_initial_balance, output1, output2);
    }
}  // namespace

void BorRuleSet::add_fee_transfer_log(IntraBlockState& state, const intx::uint256& amount, const evmc::address& sender,
                                      const intx::uint256& sender_initial_balance, const evmc::address& recipient,
                                      const intx::uint256& recipient_initial_balance) {
    static constexpr evmc::bytes32 kTransferFeeLogSig{
        0x4dfe1bbbcf077ddc3e01291eea2d5c70c2b422b415d95645b9adcfd678cb1d63_bytes32};
    SILKWORM_ASSERT(amount <= sender_initial_balance);
    add_transfer_log(state, kTransferFeeLogSig, sender, recipient, amount,
                     sender_initial_balance, recipient_initial_balance,
                     sender_initial_balance - amount, recipient_initial_balance + amount);
}

TransferFunc* BorRuleSet::transfer_func() const {
    return bor_transfer;
}

const bor::Config& BorRuleSet::config() const {
    return std::get<bor::Config>(chain_config_->rule_set_config);
}

}  // namespace silkworm::protocol
