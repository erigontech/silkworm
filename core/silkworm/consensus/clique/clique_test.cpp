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


#include <catch2/catch.hpp>

#include "clique_snapshot.hpp"
#include "clique.hpp"

using namespace evmc::literals;

namespace silkworm::consensus {

constexpr uint64_t zero = 0;
constexpr evmc::bytes32 zero_hash{};

// This the RLP of Goerli Block 1.
const char* rlp_sample_header_hex{
    "f90256a0bf7e331f7f7c1dd2e05159666b3bf8bc7a8a3a9eb1d518969"
    "eab529dd9b88c1aa01dcc4de8dec75d7aab85b567b6ccd41ad312451b"
    "948a7413f0a142fd40d49347940000000000000000000000000000000"
    "000000000a05d6cded585e73c4e322c30c2f782a336316f17dd85a486"
    "3b9d838d2d4b8b3008a056e81f171bcc55a6ff8345e692c0f86e5b48e"
    "01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0"
    "f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000"
    "000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000201839fd8018084"
    "5c530ffdb861506172697479205465636820417574686f72697479000"
    "00000000000000000002bbf886181970654ed46e3fae0ded41ee53fec"
    "702c47431988a7ae80e6576f3552684f069af80ba11d36327aaf846d47"
    "0526e4a1c461601b2fd4ebdcdc2b734a01a00000000000000000000000"
    "000000000000000000000000000000000000000000880000000000000000"
};

CliqueConfig config_sample{3, 3};
constexpr evmc::address no_vote{};
// signers
constexpr evmc::address signer_a = 0x0000000000000000000000000000000000000001_address;
constexpr evmc::address signer_b = 0x0000000000000000000000000000000000000002_address;
constexpr evmc::address signer_c = 0x0000000000000000000000000000000000000003_address;
constexpr evmc::address signer_d = 0x0000000000000000000000000000000000000004_address;
constexpr evmc::address signer_e = 0x0000000000000000000000000000000000000005_address;
constexpr evmc::address signer_f = 0x0000000000000000000000000000000000000006_address;

ValidationResult execute_vote(CliqueSnapshot& snapshot, evmc::address signer, evmc::address voted, bool authorize, bool checkpoint = false) {
    BlockHeader header;
    header.beneficiary = voted;
    if (authorize) {
        header.nonce = kNonceAuthVote;
    } else {
        header.nonce = kNonceDropVote;
    }
    if (checkpoint) {
        header.number = 3; // process it do not treat it like an epoch
    } else {
        header.number = 8; // process it do not treat it like an epoch
    }
    return snapshot.add_header(header, signer, config_sample);
}

// Encoding/Decoding
TEST_CASE("empty snapshot encoding/decoding") {
    CliqueSnapshot snapshot{0, evmc::bytes32{}, {}, {}};
    auto snapshot_encoded{snapshot.to_bytes()};
    ByteView snapshot_encoded_view{snapshot_encoded.data(), snapshot_encoded.size()};
    CHECK(snapshot_encoded.size() == 8);
    CHECK(int(snapshot_encoded[0]) == 0);
    auto snapshot_decoded{CliqueSnapshot::from_bytes(snapshot_encoded_view, zero, evmc::bytes32{})};
    CHECK(snapshot_decoded.get_signers().size() == 0);
    CHECK(snapshot_decoded.get_recents().size() == 0);
}

TEST_CASE("Signers without recents snapshot encoding/decoding") {
    CliqueSnapshot snapshot{zero, zero_hash, {signer_a, signer_b}, {}};
    auto snapshot_encoded{snapshot.to_bytes()};
    ByteView snapshot_encoded_view{snapshot_encoded.data(), snapshot_encoded.size()};
    CHECK(snapshot_encoded.size() == 2 * kAddressLength + 8);
    CHECK(snapshot_encoded[0] == 2);
    auto snapshot_decoded{CliqueSnapshot::from_bytes(snapshot_encoded_view, zero, zero_hash)};
    auto signers{snapshot_decoded.get_signers()};
    CHECK(signers.size() == 2);
    CHECK(signers[0] == signer_a);
    CHECK(signers[1] == signer_b);
    CHECK(snapshot_decoded.get_recents().size() == 0);
}

TEST_CASE("Recents without signers snapshot encoding/decoding") {
    CliqueSnapshot snapshot{zero, zero_hash, {}, {signer_a, signer_b}};
    auto snapshot_encoded{snapshot.to_bytes()};
    ByteView snapshot_encoded_view{snapshot_encoded.data(), snapshot_encoded.size()};
    REQUIRE(snapshot_encoded.size() == 2 * kAddressLength + 8);
    REQUIRE(snapshot_encoded[0] == 0);
    auto snapshot_decoded{CliqueSnapshot::from_bytes(snapshot_encoded_view, zero, zero_hash)};
    auto recents{snapshot_decoded.get_recents()};
    REQUIRE(recents.size() == 2);
    CHECK(recents[0] == signer_a);
    CHECK(recents[1] == signer_b);
    CHECK(snapshot_decoded.get_signers().size() == 0);
}

TEST_CASE("Recents and signers snapshot encoding/decoding") {
    CliqueSnapshot snapshot{zero, zero_hash, {signer_a, signer_b}, {signer_a}};
    auto snapshot_encoded{snapshot.to_bytes()};
    ByteView snapshot_encoded_view{snapshot_encoded.data(), snapshot_encoded.size()};
    REQUIRE(snapshot_encoded.size() == 3 * kAddressLength + 8);
    REQUIRE(snapshot_encoded[0] == 2);
    auto snapshot_decoded{CliqueSnapshot::from_bytes(snapshot_encoded_view, zero, zero_hash)};
    auto signers{snapshot_decoded.get_signers()};
    auto recents{snapshot_decoded.get_recents()};
    REQUIRE(signers.size() == 2);
    REQUIRE(recents.size() == 1);
    CHECK(signers[0] == signer_a);
    CHECK(signers[1] == signer_b);
    CHECK(recents[0] == signer_a);
}
// Signature and Seal
TEST_CASE("Signer recovery") {
    Clique engine(kDefaultCliqueConfig);
    Bytes rlp_bytes{*from_hex(rlp_sample_header_hex)};
    ByteView in{rlp_bytes};
    BlockHeader header{};

    REQUIRE(rlp::decode(in, header) == rlp::DecodingResult::kOk);
    CHECK(*engine.get_signer_from_clique_header(header) ==
          0xe0a2bd4258d2768837baa26a28fe71dc079f84c7_address);

}

TEST_CASE("Seal Verification") {
    evmc::address signer = 0xe0a2bd4258d2768837baa26a28fe71dc079f84c7_address;
    CliqueSnapshot snapshot{zero, zero_hash, {signer}, {}};
    Bytes rlp_bytes{*from_hex(rlp_sample_header_hex)};
    ByteView in{rlp_bytes};
    BlockHeader header{};

    REQUIRE(rlp::decode(in, header) == rlp::DecodingResult::kOk);
    CHECK(snapshot.verify_seal(header, signer) == ValidationResult::kOk);
}

TEST_CASE("Seal Verification with invalid difficulty") {
    evmc::address signer = 0xe0a2bd4258d2768837baa26a28fe71dc079f84c7_address;
    CliqueSnapshot snapshot{zero, zero_hash, {signer}, {}};
    Bytes rlp_bytes{*from_hex(rlp_sample_header_hex)};
    ByteView in{rlp_bytes};
    BlockHeader header{};

    REQUIRE(rlp::decode(in, header) == rlp::DecodingResult::kOk);
    header.difficulty = 5;
    CHECK(snapshot.verify_seal(header, signer) == ValidationResult::kInvalidSeal);
}
// Clique Consensus tests (Look https://eips.ethereum.org/EIPS/eip-225)
TEST_CASE("Single signer, no votes cast") {
    Clique engine(kDefaultCliqueConfig);
    Bytes rlp_bytes{*from_hex(rlp_sample_header_hex)};
    ByteView in{rlp_bytes};
    BlockHeader header{};

    REQUIRE(rlp::decode(in, header) == rlp::DecodingResult::kOk);
    auto signer{*engine.get_signer_from_clique_header(header)};
    CHECK(signer == 0xe0a2bd4258d2768837baa26a28fe71dc079f84c7_address);
}

TEST_CASE("Single signer, voting to add two others (only accept first, second needs 2 votes)") {
    CliqueSnapshot snapshot{0, evmc::bytes32{}, {signer_a}, {}};
    CHECK(execute_vote(snapshot, signer_a, signer_b, true) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_b, no_vote, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_a, signer_c, true) == ValidationResult::kOk);
    auto signers{snapshot.get_signers()};
    CHECK(signers.size() == 2);
    CHECK(signers[0] == signer_a);
    CHECK(signers[1] == signer_b);

}

TEST_CASE("Two signers, voting to add three others (only accept first two, third needs 3 votes already)") {
    CliqueSnapshot snapshot{0, evmc::bytes32{}, {signer_a, signer_b}, {}};
    CHECK(execute_vote(snapshot, signer_a, signer_c, true) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_b, signer_c, true) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_a, signer_d, true) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_b, signer_d, true) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_c, no_vote, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_a, signer_e, true) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_b, signer_e, true) == ValidationResult::kOk);
    // Signer B and Signer A must be the only authorized signers
    auto signers{snapshot.get_signers()};
    CHECK(signers.size() == 4);
    CHECK(signers[0] == signer_a);
    CHECK(signers[1] == signer_b);
    CHECK(signers[2] == signer_c);
    CHECK(signers[3] == signer_d);
}

TEST_CASE("Single signer, dropping itself (weird, but one less cornercase by explicitly allowing this)") {
    CliqueSnapshot snapshot{0, evmc::bytes32{}, {signer_a}, {}};
    CHECK(execute_vote(snapshot, signer_a, signer_a, false) == ValidationResult::kOk);
    CHECK(snapshot.get_signers().size() == 0);
}

TEST_CASE("Two signers, actually needing mutual consent to drop either of them (not fulfilled)") {
    CliqueSnapshot snapshot{0, evmc::bytes32{}, {signer_a, signer_b}, {}};
    CHECK(execute_vote(snapshot, signer_a, signer_b, false) == ValidationResult::kOk);
    CHECK(snapshot.get_signers().size() == 2);
}

TEST_CASE("Three signers, two of them deciding to drop the third") {
    CliqueSnapshot snapshot{0, evmc::bytes32{}, {signer_a, signer_b, signer_c}, {}};
    CHECK(execute_vote(snapshot, signer_a, signer_c, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_b, signer_c, false) == ValidationResult::kOk);
    auto signers{snapshot.get_signers()};
    CHECK(signers.size() == 2);
    CHECK(signers[0] == signer_a);
    CHECK(signers[1] == signer_b);
}

TEST_CASE("Four signers, consensus of two not being enough to drop anyone") {
    CliqueSnapshot snapshot{0, evmc::bytes32{}, {signer_a, signer_b, signer_c, signer_d}, {}};
    CHECK(execute_vote(snapshot, signer_a, signer_c, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_b, signer_c, false) == ValidationResult::kOk);
    CHECK(snapshot.get_signers().size() == 4);
}

TEST_CASE("Four signers, consensus of three already being enough to drop someone") {
    CliqueSnapshot snapshot{0, evmc::bytes32{}, {signer_a, signer_b, signer_c, signer_d}, {}};
    CHECK(execute_vote(snapshot, signer_a, signer_c, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_b, signer_c, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_d, signer_c, false) == ValidationResult::kOk);
    auto signers{snapshot.get_signers()};
    CHECK(signers.size() == 3);
    CHECK(signers[0] == signer_a);
    CHECK(signers[1] == signer_b);
    CHECK(signers[2] == signer_d);
}

TEST_CASE("Authorizations are counted once per signer per target") {
    CliqueSnapshot snapshot{0, evmc::bytes32{}, {signer_a, signer_b}, {}};
    CHECK(execute_vote(snapshot, signer_a, signer_b, true) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_b, no_vote, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_a, signer_b, true) == ValidationResult::kOk);
    CHECK(snapshot.get_signers().size() == 2);
}

TEST_CASE("Authorizing multiple accounts concurrently is permitted") {
    CliqueSnapshot snapshot{0, evmc::bytes32{}, {signer_a, signer_b}, {}};
    CHECK(execute_vote(snapshot, signer_a, signer_c, true) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_b, no_vote, true) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_a, signer_d, true) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_b, signer_c, true) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_a, no_vote, true) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_b, signer_d, true) == ValidationResult::kOk);
    auto signers{snapshot.get_signers()};
    REQUIRE(signers.size() == 4);
    CHECK(signers[0] == signer_a);
    CHECK(signers[1] == signer_b);
    CHECK(signers[2] == signer_c);
    CHECK(signers[3] == signer_d);
}

TEST_CASE("Deauthorizations are counted once per signer per target") {
    CliqueSnapshot snapshot{0, evmc::bytes32{}, {signer_a, signer_b}, {}};
    CHECK(execute_vote(snapshot, signer_a, signer_b, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_b, no_vote, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_a, signer_b, false) == ValidationResult::kOk);
    CHECK(snapshot.get_signers().size() == 2);
}

TEST_CASE("Deauthorizing multiple accounts concurrently is permitted") {
    CliqueSnapshot snapshot{0, evmc::bytes32{}, {signer_a, signer_b, signer_c, signer_d}, {}};
    CHECK(execute_vote(snapshot, signer_a, signer_c, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_b, no_vote, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_c, no_vote, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_a, signer_d, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_b, no_vote, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_c, no_vote, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_a, no_vote, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_b, signer_d, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_c, signer_d, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_a, no_vote, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_b, signer_c, false) == ValidationResult::kOk);
    auto signers{snapshot.get_signers()};
    CHECK(signers.size() == 2);
    CHECK(signers[0] == signer_a);
    CHECK(signers[1] == signer_b);
}

TEST_CASE("Votes from deauthorized signers are discarded immediately (deauth votes)") {
    CliqueSnapshot snapshot{0, evmc::bytes32{}, {signer_a, signer_b, signer_c}, {}};
    CHECK(execute_vote(snapshot, signer_c, signer_a, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_a, signer_c, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_b, signer_c, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_a, signer_a, false) == ValidationResult::kOk);
    auto signers{snapshot.get_signers()};
    CHECK(signers.size() == 2);
    CHECK(signers[0] == signer_a);
    CHECK(signers[1] == signer_b);
}

TEST_CASE("Cascading changes are not allowed, only the account being voted on may change") {
    CliqueSnapshot snapshot{0, evmc::bytes32{}, {signer_a, signer_b, signer_c, signer_d}, {}};
    CHECK(execute_vote(snapshot, signer_a, signer_c, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_b, no_vote, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_c, no_vote, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_a, signer_d, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_b, signer_c, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_c, no_vote, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_a, no_vote, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_b, signer_d, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_c, signer_d, false) == ValidationResult::kOk);

    auto signers{snapshot.get_signers()};
    CHECK(signers.size() == 3);
    CHECK(signers[0] == signer_a);
    CHECK(signers[1] == signer_b);
    CHECK(signers[2] == signer_c);
}

TEST_CASE("Changes reaching consensus out of bounds (via a deauth) execute on touch") {
    CliqueSnapshot snapshot{0, evmc::bytes32{}, {signer_a, signer_b, signer_c, signer_d}, {}};
    CHECK(execute_vote(snapshot, signer_a, signer_c, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_b, no_vote, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_c, no_vote, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_a, signer_d, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_b, signer_c, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_c, no_vote, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_a, no_vote, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_b, signer_d, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_c, signer_d, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_a, no_vote, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_c, signer_c, true) == ValidationResult::kOk);

    auto signers{snapshot.get_signers()};
    CHECK(signers.size() == 2);
    CHECK(signers[0] == signer_a);
    CHECK(signers[1] == signer_b);
}

TEST_CASE("Changes reaching consensus out of bounds (via a deauth) may go out of consensus on first touch") {
    CliqueSnapshot snapshot{0, evmc::bytes32{}, {signer_a, signer_b, signer_c, signer_d}, {}};
    CHECK(execute_vote(snapshot, signer_a, signer_c, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_b, no_vote, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_c, no_vote, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_a, signer_d, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_b, signer_c, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_c, no_vote, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_a, no_vote, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_b, signer_d, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_c, signer_d, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_a, no_vote, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_b, signer_c, true) == ValidationResult::kOk);

    auto signers{snapshot.get_signers()};
    CHECK(signers.size() == 3);
    CHECK(signers[0] == signer_a);
    CHECK(signers[1] == signer_b);
    CHECK(signers[2] == signer_c);
}

TEST_CASE("Ensure that pending votes don't survive authorization status changes.") {
    CliqueSnapshot snapshot{0, evmc::bytes32{}, {signer_a, signer_b, signer_c, signer_d, signer_e}, {}};
    CHECK(execute_vote(snapshot, signer_a, signer_f, true) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_b, signer_f, true) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_c, signer_f, true) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_d, signer_f, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_e, signer_f, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_b, signer_f, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_c, signer_f, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_d, signer_f, true) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_e, signer_f, true) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_b, signer_a, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_c, signer_a, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_d, signer_a, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_b, signer_f, true) == ValidationResult::kOk);

    auto signers{snapshot.get_signers()};
    CHECK(signers.size() == 5);
    CHECK(signers[0] == signer_b);
    CHECK(signers[1] == signer_c);
    CHECK(signers[2] == signer_d);
    CHECK(signers[3] == signer_e);
    CHECK(signers[4] == signer_f);

}

TEST_CASE("An unauthorized signer should not be able to sign blocks") {
    CliqueSnapshot snapshot{0, evmc::bytes32{}, {signer_a}, {}};
    CHECK(execute_vote(snapshot, signer_b, no_vote, false) == ValidationResult::kUnauthorizedSigner);
}

TEST_CASE("An authorized signer that signed recenty should not be able to sign again") {
    CliqueSnapshot snapshot{0, evmc::bytes32{}, {signer_a, signer_b}, {}};
    CHECK(execute_vote(snapshot, signer_b, no_vote, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_b, no_vote, false) == ValidationResult::kRecentlySigned);
}

TEST_CASE("Recent signatures should not reset on checkpoint blocks imported in a batch") {
    CliqueSnapshot snapshot{0, evmc::bytes32{}, {signer_a, signer_b}, {}};
    CHECK(execute_vote(snapshot, signer_a, no_vote, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_b, no_vote, false) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_a, no_vote, false, true) == ValidationResult::kOk);
    CHECK(execute_vote(snapshot, signer_a, no_vote, false) == ValidationResult::kRecentlySigned);

}

}  // namespace silkworm
