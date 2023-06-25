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

#include "execution_engine.hpp"

#include <iostream>

#include <boost/asio/io_context.hpp>
#include <catch2/catch.hpp>

#include <silkworm/core/common/cast.hpp>
#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/protocol/ethash_rule_set.hpp>
#include <silkworm/core/protocol/validation.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/infra/common/environment.hpp>
#include <silkworm/infra/common/secp256k1_context.hpp>
#include <silkworm/infra/test/log.hpp>
#include <silkworm/node/common/preverified_hashes.hpp>
#include <silkworm/node/db/access_layer.hpp>
#include <silkworm/node/db/buffer.hpp>
#include <silkworm/node/db/genesis.hpp>
#include <silkworm/node/db/stages.hpp>
#include <silkworm/node/test/context.hpp>
#include <silkworm/sentry/common/ecc_key_pair.hpp>

namespace silkworm {

namespace asio = boost::asio;
using namespace stagedsync;
using namespace intx;            // for literals
using namespace sentry::common;  // for ecc_key_pair

static std::shared_ptr<Block> generateSampleBlock(const BlockHeader& parent, const ChainConfig& config) {
    auto block = std::make_shared<Block>();
    auto parent_hash = parent.hash();

    uint64_t pseudo_random_gas_limit = parent.gas_limit + parent.number;
    if (pseudo_random_gas_limit > parent.gas_limit / 1024) pseudo_random_gas_limit = parent.gas_limit;

    // BlockHeader
    block->header.number = parent.number + 1;
    block->header.parent_hash = parent_hash;
    block->header.beneficiary = 0xc8ebccc5f5689fa8659d83713341e5ad19349448_address;
    block->header.state_root = kEmptyRoot;
    block->header.receipts_root = kEmptyRoot;
    block->header.gas_limit = pseudo_random_gas_limit;
    block->header.gas_used = 0;
    block->header.timestamp = parent.timestamp + 12;
    block->header.extra_data = {};
    block->header.difficulty = protocol::EthashRuleSet::difficulty(
        block->header.number, block->header.timestamp, parent.difficulty, parent.timestamp, false /*parent has uncles*/, config);

    // BlockBody: transactions
    block->transactions.resize(1);
    block->transactions[0].nonce = parent.number;
    block->transactions[0].max_priority_fee_per_gas = 50 * kGiga;
    block->transactions[0].max_fee_per_gas = 50 * kGiga;
    block->transactions[0].gas_limit = 90'000;
    block->transactions[0].to = 0xe5ef458d37212a06e3f59d40c454e76150ae7c32_address;
    block->transactions[0].value = 1'027'501'080 * kGiga;
    block->transactions[0].data = {};
    CHECK(block->transactions[0].set_v(27));
    block->transactions[0].r = 0x48b55bfa915ac795c431978d8a6a992b628d557da5ff759b307d495a36649353_u256;
    block->transactions[0].s = 0x1fffd310ac743f371de3b9f7f9cb56c0b28ad43601b4ab949f53faa07bd2c804_u256;

    block->header.transactions_root = protocol::compute_transaction_root(*block);

    return block;
}

static std::shared_ptr<Block> generateSampleBlockWithOmmers(const BlockHeader& parent, const BlockHeader& ommer_parent, const ChainConfig& config) {
    auto block = generateSampleBlock(parent, config);

    uint64_t pseudo_random_gas_limit = ommer_parent.gas_limit + ommer_parent.number;
    if (pseudo_random_gas_limit > ommer_parent.gas_limit / 1024) pseudo_random_gas_limit = ommer_parent.gas_limit;

    // BlockBody: ommers
    block->ommers.resize(1);
    block->ommers[0].parent_hash = ommer_parent.hash();
    block->ommers[0].ommers_hash = kEmptyListHash;
    block->ommers[0].beneficiary = 0x0c729be7c39543c3d549282a40395299d987cec2_address;
    block->ommers[0].state_root = 0xc2bcdfd012534fa0b19ffba5fae6fc81edd390e9b7d5007d1e92e8e835286e9d_bytes32;
    block->ommers[0].transactions_root = kEmptyRoot;
    block->ommers[0].receipts_root = kEmptyRoot;
    block->ommers[0].number = ommer_parent.number + 1;
    block->ommers[0].gas_limit = pseudo_random_gas_limit;
    block->ommers[0].gas_used = 0;
    block->ommers[0].timestamp = 1455404305;
    block->ommers[0].prev_randao = 0xf0a53dfdd6c2f2a661e718ef29092de60d81d45f84044bec7bf4b36630b2bc08_bytes32;
    block->ommers[0].nonce[7] = 35;
    block->ommers[0].difficulty = protocol::EthashRuleSet::difficulty(
        block->ommers[0].number, block->ommers[0].timestamp, ommer_parent.difficulty, ommer_parent.timestamp, true /*parent has uncles*/, config);

    block->header.ommers_hash = protocol::compute_ommers_hash(*block);

    return block;
}

class ExecutionEngine_ForTest : public stagedsync::ExecutionEngine {
  public:
    using stagedsync::ExecutionEngine::ExecutionEngine;
    using stagedsync::ExecutionEngine::forks_;
    using stagedsync::ExecutionEngine::main_chain_;
};

TEST_CASE("ExecutionEngine") {
    test::SetLogVerbosityGuard log_guard(log::Level::kNone);

    asio::io_context io;
    asio::executor_work_guard<decltype(io.get_executor())> work{io.get_executor()};

    test::Context context;
    context.add_genesis_data();
    context.commit_txn();

    ChainConfig& chain_config = *context.node_settings().chain_config;
    chain_config.protocol_rule_set = protocol::RuleSetType::kNoProof;  // skip seal validation

    PreverifiedHashes::current.clear();  // disable preverified hashes

    db::RWAccess db_access{context.env()};
    ExecutionEngine_ForTest exec_engine{io, context.node_settings(), db_access};
    exec_engine.open();

    auto& tx = exec_engine.main_chain_.tx();  // mdbx refuses to open a ROTxn when there is a RWTxn in the same thread

    auto header0_hash = db::read_canonical_hash(tx, 0);
    REQUIRE(header0_hash.has_value());

    auto header0 = db::read_canonical_header(tx, 0);
    REQUIRE(header0.has_value());

    BlockId block0_id{0, *header0_hash};

    /* status:
     *         h0
     * input:
     *         h0 <----- h1
     */

    SECTION("one invalid body after the genesis") {
        Environment::set_stop_before_stage(db::stages::kSendersKey);  // only headers, block hashes and bodies

        auto block1 = std::make_shared<Block>();
        block1->header.number = 1;
        block1->header.difficulty = 17'171'480'576;  // a random value
        block1->header.parent_hash = *header0_hash;
        // auto header1_hash = block1.header.hash();
        block1->ommers.push_back(BlockHeader{});  // generate error InvalidOmmerHeader
        auto header1_hash = block1->header.hash();

        // getting initial status
        auto initial_progress = exec_engine.block_progress();
        CHECK(initial_progress == 0);
        auto last_fcu_at_start_time = exec_engine.last_fork_choice();
        CHECK(last_fcu_at_start_time == block0_id);

        // inserting headers & bodies
        exec_engine.insert_block(block1);

        // check db
        BlockBody saved_body;
        bool present = db::read_body(tx, header1_hash, block1->header.number, saved_body);
        CHECK(present);

        auto progress = exec_engine.block_progress();
        CHECK(progress == 1);

        // verifying the chain
        auto verification = exec_engine.verify_chain(header1_hash).get();

        CHECK(db::stages::read_stage_progress(tx, db::stages::kHeadersKey) == 1);
        CHECK(db::stages::read_stage_progress(tx, db::stages::kBlockHashesKey) == 1);
        CHECK(db::stages::read_stage_progress(tx, db::stages::kBlockBodiesKey) == 1);
        CHECK(db::stages::read_stage_progress(tx, db::stages::kSendersKey) == 0);
        CHECK(db::stages::read_stage_progress(tx, db::stages::kExecutionKey) == 0);

        CHECK(!holds_alternative<ValidationError>(verification));
        REQUIRE(holds_alternative<InvalidChain>(verification));
        auto invalid_chain = std::get<InvalidChain>(verification);

        CHECK(invalid_chain.unwind_point == BlockId{0, *header0_hash});
        CHECK(invalid_chain.bad_block.has_value());
        CHECK(invalid_chain.bad_block.value() == header1_hash);
        CHECK(invalid_chain.bad_headers.size() == 1);
        CHECK(*(invalid_chain.bad_headers.begin()) == header1_hash);

        // check status
        auto final_progress = exec_engine.block_progress();
        CHECK(final_progress == block1->header.number);
        CHECK(exec_engine.last_fork_choice() == last_fcu_at_start_time);  // not changed

        auto present_in_canonical = exec_engine.is_canonical(header1_hash);
        CHECK(!present_in_canonical);

        // reverting the chain
        bool updated = exec_engine.notify_fork_choice_update(*header0_hash);
        CHECK(updated);

        CHECK(exec_engine.last_fork_choice() == last_fcu_at_start_time);  // not changed

        present_in_canonical = exec_engine.is_canonical(header1_hash);
        CHECK(!present_in_canonical);
    }

    SECTION("one valid body after the genesis") {
        Environment::set_stop_before_stage(db::stages::kSendersKey);  // only headers, block hashes and bodies

        std::string raw_header1 =
            "f90211a0d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3a01dcc4de8dec75d7aab85b567b6ccd41a"
            "d312451b948a7413f0a142fd40d493479405a56e2d52c817161883f50c441c3228cfe54d9fa0d67e4d450343046425ae4271474353"
            "857ab860dbc0a1dde64b41b5cd3a532bf3a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e8"
            "1f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b901000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000008503ff80000001821388808455ba422499476574682f76312e302e302f"
            "6c696e75782f676f312e342e32a0969b900de27b6ac6a67742365dd65f55a0526c41fd18e1b16f1a1215c2e66f5988539bd4979fef"
            "1ec4";
        std::optional<Bytes> encoded_header1 = from_hex(raw_header1);

        auto block1 = std::make_shared<Block>();
        ByteView encoded_view = encoded_header1.value();
        auto decoding_result = rlp::decode(encoded_view, block1->header);
        // Note: block1 has zero transactions and zero ommers on mainnet
        REQUIRE(decoding_result);
        auto block1_hash = block1->header.hash();
        BlockId block1_id{1, block1_hash};

        // getting initial status
        auto initial_progress = exec_engine.block_progress();
        CHECK(initial_progress == 0);
        auto last_fcu_at_start_time = exec_engine.last_fork_choice();
        CHECK(last_fcu_at_start_time == block0_id);

        // inserting & verifying the block
        exec_engine.insert_block(block1);
        auto verification = exec_engine.verify_chain(block1_hash).get();

        REQUIRE(holds_alternative<ValidChain>(verification));
        auto valid_chain = std::get<ValidChain>(verification);
        CHECK(valid_chain.current_head == block1_id);

        // check status
        auto final_progress = exec_engine.block_progress();
        CHECK(final_progress == block1->header.number);
        CHECK(exec_engine.last_fork_choice() == last_fcu_at_start_time);  // not changed

        // check db content
        BlockBody saved_body;
        bool present = db::read_body(tx, block1_hash, block1->header.number, saved_body);
        CHECK(present);

        auto present_in_canonical = exec_engine.is_canonical(block1_hash);
        CHECK(!present_in_canonical);  // the current head is not yet accepted

        // confirming the chain
        exec_engine.notify_fork_choice_update(block1_hash, header0_hash);

        // checking the status
        CHECK(exec_engine.last_fork_choice() == block1_id);
        CHECK(exec_engine.last_finalized_block() == block0_id);

        present_in_canonical = exec_engine.is_canonical(block1_hash);
        CHECK(present_in_canonical);
    }

    SECTION("a block that creates a fork") {
        Environment::set_stop_before_stage(db::stages::kSendersKey);  // only headers, block hashes and bodies

        // generating a chain
        auto block1 = generateSampleBlock(*header0, chain_config);
        auto block1_hash = block1->header.hash();

        auto block2 = generateSampleBlock(block1->header, chain_config);
        auto block2_hash = block2->header.hash();

        auto block3 = generateSampleBlock(block2->header, chain_config);
        auto block3_hash = block3->header.hash();

        // inserting & verifying the block
        exec_engine.insert_block(block1);
        exec_engine.insert_block(block2);
        exec_engine.insert_block(block3);
        auto verification = exec_engine.verify_chain(block3_hash).get();

        REQUIRE(holds_alternative<ValidChain>(verification));
        auto valid_chain = std::get<ValidChain>(verification);
        CHECK(valid_chain.current_head == BlockId{3, block3_hash});

        // confirming the chain
        auto fcu_updated = exec_engine.notify_fork_choice_update(block3_hash, block1_hash);
        CHECK(fcu_updated);

        CHECK(exec_engine.last_fork_choice() == BlockId{3, block3_hash});
        CHECK(exec_engine.last_finalized_block() == BlockId{1, block1_hash});

        CHECK(exec_engine.get_canonical_hash(2) == block2_hash);
        CHECK(exec_engine.get_canonical_header(2).has_value());
        CHECK(exec_engine.get_canonical_hash(3) == block3_hash);
        CHECK(exec_engine.get_canonical_header(3).has_value());

        auto [head_height, head_hash] = db::read_canonical_head(tx);
        CHECK(head_height == 3);
        CHECK(head_hash == block3_hash);

        // creating and reintegrating a fork
        auto block4 = generateSampleBlock(block3->header, chain_config);
        auto block4_hash = block4->header.hash();
        {
            // inserting & verifying the block
            exec_engine.insert_block(block4);
            verification = exec_engine.verify_chain(block4_hash).get();

            REQUIRE(holds_alternative<ValidChain>(verification));
            valid_chain = std::get<ValidChain>(verification);
            CHECK(valid_chain.current_head == BlockId{4, block4_hash});

            // confirming the chain (i.e. flushing the memory mutation on the main db)
            fcu_updated = exec_engine.notify_fork_choice_update(block4_hash, block1_hash);
            CHECK(fcu_updated);

            CHECK(exec_engine.last_fork_choice() == BlockId{4, block4_hash});
            CHECK(exec_engine.last_finalized_block() == BlockId{1, block1_hash});

            CHECK(exec_engine.get_canonical_hash(2) == block2_hash);
            CHECK(exec_engine.get_canonical_header(2).has_value());
            CHECK(exec_engine.get_canonical_hash(3) == block3_hash);
            CHECK(exec_engine.get_canonical_header(3).has_value());
            CHECK(exec_engine.get_canonical_hash(4) == block4_hash);
            CHECK(exec_engine.get_canonical_header(4).has_value());

            std::tie(head_height, head_hash) = db::read_canonical_head(tx);
            CHECK(head_height == 4);
            CHECK(head_hash == block4_hash);
        }

        // creating a fork and changing the head (trigger unwind)
        auto block2b = generateSampleBlock(block1->header, chain_config);
        block2b->header.extra_data = string_view_to_byte_view("I'm different");  // to make it different from block2
        auto block2b_hash = block2b->header.hash();
        {
            // inserting & verifying the block
            exec_engine.insert_block(block2b);
            verification = exec_engine.verify_chain(block2b_hash).get();

            REQUIRE(holds_alternative<ValidChain>(verification));
            valid_chain = std::get<ValidChain>(verification);
            CHECK(valid_chain.current_head == BlockId{2, block2b_hash});

            // confirming the chain
            fcu_updated = exec_engine.notify_fork_choice_update(block2b_hash, header0_hash);
            CHECK(fcu_updated);

            CHECK(exec_engine.last_fork_choice() == BlockId{2, block2b_hash});
            CHECK(exec_engine.last_finalized_block() == block0_id);
            CHECK(exec_engine.main_chain_.last_chosen_head() == BlockId{2, block2b_hash});

            CHECK(exec_engine.get_canonical_hash(2) == block2b_hash);
            CHECK(exec_engine.get_canonical_header(2).has_value());
            CHECK(not exec_engine.get_canonical_header(3).has_value());
            CHECK(not exec_engine.get_canonical_header(4).has_value());

            std::tie(head_height, head_hash) = db::read_canonical_head(tx);
            CHECK(head_height == 2);
            CHECK(head_hash == block2b_hash);
        }

        CHECK(exec_engine.get_header(block2b_hash).has_value());  // we do not remove old blocks
        CHECK(exec_engine.get_header(block2_hash).has_value());   // we do not remove old blocks
        CHECK(exec_engine.get_header(block3_hash).has_value());   // we do not remove old blocks
        CHECK(exec_engine.get_header(block4_hash).has_value());   // we do not remove old blocks
    }
}

class EccKeyPairEx : public EccKeyPair {
  public:
    using EccKeyPair::EccKeyPair;
    using EccKeyPair::private_key;
    using EccKeyPair::private_key_hex;
    using EccKeyPair::public_key;

    Bytes sign(ByteView data) {
        SecP256K1Context ctx{false, true};  // allow_verify=false, allow_sign=true

        secp256k1_ecdsa_signature signature;
        bool ok = secp256k1_ecdsa_sign(ctx.raw(), &signature, data.data(), private_key_.data(), nullptr, nullptr);
        if (!ok) throw std::runtime_error("EccKeyPairEx::sign failed");

        Bytes serialized_signature(64, 0);
        ok = secp256k1_ecdsa_signature_serialize_compact(ctx.raw(), serialized_signature.data(), &signature);
        if (!ok) throw std::runtime_error("EccKeyPairEx::sign failed");

        return serialized_signature;
    }

    Bytes sign_in_recoverable_way(ByteView data) {
        SecP256K1Context ctx{false, true};  // allow_verify=false, allow_sign=true

        secp256k1_ecdsa_recoverable_signature signature;
        bool ok = ctx.sign_recoverable(&signature, data, private_key_);
        if (!ok) throw std::runtime_error("EccKeyPairEx::sign_in_recoverable_way failed");

        auto [signature_data, recovery_id] = ctx.serialize_recoverable_signature(&signature);
        signature_data.push_back(recovery_id);

        return signature_data;
    }

    using dest_type = const uint8_t (&)[32];

    void sign_in_recoverable_way(Transaction& tx) {
        Bytes rlp_tx;
        rlp::encode(rlp_tx, tx);
        const auto tx_hash{keccak256(rlp_tx)};
        ByteView hash{tx_hash.bytes};
        auto signature = sign_in_recoverable_way(hash);

        uint8_t r[32];
        memcpy(r, signature.data(), 32);

        uint8_t s[32];
        memcpy(r, signature.data() + 32, 32);

        // Load the first 32 bytes (the r value) into a intx::uint256
        tx.r = intx::be::load<intx::uint256>(r);

        // Load the second 32 bytes (the s value) into a intx::uint256
        tx.s = intx::be::load<intx::uint256>(s);

        tx.odd_y_parity = signature[64] % 2;
    }
};

static std::shared_ptr<Block> generate_sample_block(const BlockHeader& parent, const ChainConfig& config, EccKeyPairEx& key_pair) {
    auto block = std::make_shared<Block>();
    auto parent_hash = parent.hash();

    uint64_t pseudo_random_gas_limit = parent.gas_limit + parent.number;
    if (pseudo_random_gas_limit > parent.gas_limit / 1024) pseudo_random_gas_limit = parent.gas_limit;

    // BlockHeader
    block->header.number = parent.number + 1;
    block->header.parent_hash = parent_hash;
    block->header.beneficiary = 0xc8ebccc5f5689fa8659d83713341e5ad19349448_address;
    block->header.state_root = kEmptyRoot;
    block->header.receipts_root = kEmptyRoot;
    block->header.gas_limit = pseudo_random_gas_limit;
    block->header.gas_used = 0;
    block->header.timestamp = parent.timestamp + 12;
    block->header.extra_data = {};
    block->header.difficulty = protocol::EthashRuleSet::difficulty(
        block->header.number, block->header.timestamp, parent.difficulty, parent.timestamp, false /*parent has uncles*/, config);

    // BlockBody: transactions
    block->transactions.resize(1);
    block->transactions[0].nonce = parent.number;
    block->transactions[0].max_priority_fee_per_gas = 50 * kGiga;
    block->transactions[0].max_fee_per_gas = 50 * kGiga;
    block->transactions[0].gas_limit = 90'000;
    block->transactions[0].to = 0xe5ef458d37212a06e3f59d40c454e76150ae7c32_address;
    block->transactions[0].value = 1'027'501'080 * kGiga;
    block->transactions[0].data = {};
    // CHECK(block->transactions[0].set_v(27));

    key_pair.sign_in_recoverable_way(block->transactions[0]);

    // root hash
    block->header.transactions_root = protocol::compute_transaction_root(*block);

    return block;
}

// Method to get the address of the public key
std::string getAddress(EccPublicKey& public_key) {
    // We hash the data using Keccak-256
    auto hash = ethash::keccak256(public_key.data().data(), public_key.data().size());

    // The Ethereum address is the last 20 bytes (40 characters in hex format) of the hashed public key
    // So we convert the relevant part of the hash to a hex string
    std::stringstream address;
    for (int i = 12; i < 32; ++i) {  // Ethereum addresses are 20 bytes, so skip the first 12 bytes of the 32-byte hash
        address << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(hash.bytes[i]);
    }

    return address.str();
}

TEST_CASE("ExecutionEngine-full-stages") {
    // test::SetLogVerbosityGuard log_guard(log::Level::kNone);

    asio::io_context io;
    asio::executor_work_guard<decltype(io.get_executor())> work{io.get_executor()};

    /*
        Address: 0xe0defb92145fef3c3a945637705fafd3aa74a241
        Public key: 0x93e39cde5cdb3932e204cdd43b89578ad58d7489c31cbc30e61d167f67e3c8e76b9b2249377fa84f73b11c68f2f7a62f205f430f3a4370fd5dab6e3139d84977
        Private key: 0xba1488fd638adc2e9f62fc70d41ff0ffc0e8d32ef6744d801987bc3ecb6a0953
    */

    EccKeyPairEx key_pair_1(*from_hex("ba1488fd638adc2e9f62fc70d41ff0ffc0e8d32ef6744d801987bc3ecb6a0953"));
    auto public_key_1 = key_pair_1.public_key();
    auto address_1 = public_key_1.address();
    log::Info() << "address " << to_hex(address_1) << "\n";
    log::Info() << "address " << getAddress(public_key_1) << "\n";  // 83307331c0063dbba7e2fa8232ce54f0afbbda37

    std::string genesis_data = R"(
    {
    "alloc": {
            "83307331c0063dbba7e2fa8232ce54f0afbbda37": {
                    "balance": "1337000000000000000000"
            },
            "ddf5810a0eb2fb2e32323bb2c99509ab320f24ac": {
                    "balance": "17900000000000000000000"
            },
            "2489ac126934d4d6a94df08743da7b7691e9798e": {
                    "balance": "1000000000000000000000"
            },
            "f42f905231c770f0a406f2b768877fb49eee0f21": {
                    "balance": "197000000000000000000"
            },
            "756f45e3fa69347a9a973a725e3c98bc4db0b5a0": {
                    "balance": "200000000000000000000"
            }
    },
    "coinbase": "0x0000000000000000000000000000000000000000",
    "config": {
            "chainId": 111,
            "homesteadBlock": 1150000,
            "daoForkBlock": 1920000,
            "daoForkSupport": true,
            "eip150Block": 2463000,
            "eip150Hash": "0x2086799aeebeae135c246c65021c82b4e15a2c451340993aacfd2751886514f0",
            "eip155Block": 2675000,
            "eip158Block": 2675000,
            "byzantiumBlock": 4370000,
            "constantinopleBlock": 7280000,
            "petersburgBlock": 7280000,
            "istanbulBlock": 9069000,
            "muirGlacierBlock": 9200000,
            "berlinBlock": 12244000,
            "londonBlock": 12965000,
            "arrowGlacierBlock": 13773000,
            "grayGlacierBlock": 15050000,
            "terminalTotalDifficulty": "58750000000000000000000",
            "shanghaiTime": 1681338455,
            "ethash": {}
    },
    "difficulty": "0x0400000000",
    "extraData": "0x11bbe8db4e347b4e8c937c1c8370e4b5ed33adb3db69cbdb7a38e1e50b1b82fa",
    "gasLimit": "0x1388",
    "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "nonce": "0x0000000000000042",
    "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "timestamp": "0x00"
    }
    )";

    test::Context context;
    bool genesis_data_valid = context.add_custom_genesis_data(genesis_data);
    REQUIRE(genesis_data_valid);
    // context.add_genesis_data();
    context.commit_txn();

    ChainConfig& chain_config = *context.node_settings().chain_config;
    chain_config.protocol_rule_set = protocol::RuleSetType::kNoProof;  // skip seal validation

    PreverifiedHashes::current.clear();  // disable preverified hashes

    db::RWAccess db_access{context.env()};
    ExecutionEngine_ForTest exec_engine{io, context.node_settings(), db_access};
    exec_engine.open();

    auto& tx = exec_engine.main_chain_.tx();  // mdbx refuses to open a ROTxn when there is a RWTxn in the same thread

    auto header0_hash = db::read_canonical_hash(tx, 0);
    REQUIRE(header0_hash.has_value());

    auto header0 = db::read_canonical_header(tx, 0);
    REQUIRE(header0.has_value());

    // BlockId block0_id{0, *header0_hash};

    SECTION("full stages validation") {
        Environment::set_stop_before_stage("");                            // all the stages
        chain_config.protocol_rule_set = protocol::RuleSetType::kNoProof;  // skip seal validation

        // generate block 1
        auto block1 = generate_sample_block(*header0, chain_config, key_pair_1);
        auto block1_hash = block1->header.hash();

        // block generation check
        auto validation_result = protocol::pre_validate_transactions(*block1, *context.node_settings().chain_config);
        CHECK(validation_result == ValidationResult::kOk);
        auto rule_set = protocol::rule_set_factory(*context.node_settings().chain_config);
        db::Buffer chain_state{tx, /*prune_history_threshold=*/0, /*historical_block=null*/};

        chain_state.insert_block(*block1, block1_hash);  // to validate next blocks

        // delete this row
        generateSampleBlockWithOmmers(block1->header, block1->header, chain_config);  // dummy, suppress warning of unused generateSampleBlockWithOmmers

        // generate block 2 & 3
        // auto block2 = generateSampleBlock(block1->header, chain_config);
        // auto block2_hash = block2->header.hash();
        //
        // chain_state.insert_block(*block2, block2_hash);  // to validate next blocks
        //
        // auto block3 = generateSampleBlockWithOmmers(block2->header, block1->header, chain_config);
        // auto block3_hash = block3->header.hash();
        //
        // validation_result = rule_set->validate_ommers(*block3, chain_state);
        // CHECK(validation_result == ValidationResult::kOk);

        // inserting & verifying the block
        exec_engine.insert_block(block1);
        // exec_engine.insert_block(block2);
        // exec_engine.insert_block(block3);
        // auto verification = exec_engine.verify_chain(block3_hash).get();  // FAILS at execution stage because "from" address has zero gas
        auto verification = exec_engine.verify_chain(block1_hash).get();

        // todo: make this test pass
        // REQUIRE(holds_alternative<ValidChain>(verification));
        // auto valid_chain = std::get<ValidChain>(verification);
        // CHECK(valid_chain.current_head == BlockId{3, block3_hash});
    }
}

}  // namespace silkworm
