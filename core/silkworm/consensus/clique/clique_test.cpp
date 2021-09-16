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

using namespace evmc::literals;

namespace silkworm {

CliqueConfig config_sample{3, 3};
constexpr evmc::address no_vote = 0x0000000000000000000000000000000000000000_address;
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
        header.nonce = kNonceAuthorize;
    } else {
        header.nonce = kNonceUnauthorize;
    }
    if (checkpoint) {
        header.number = 3; // process it do not treat it like an epoch
    } else {
        header.number = 8; // process it do not treat it like an epoch
    }
    return snapshot.add_header(header, signer, config_sample);
}
// Clique Consensus tests (Look https://eips.ethereum.org/EIPS/eip-225)
TEST_CASE("Single signer, no votes cast") {
    CliqueSnapshot snapshot{0, evmc::bytes32{}, {signer_a}, {}};
    CHECK(execute_vote(snapshot, signer_a, no_vote, false) == ValidationResult::kOk);
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
    CHECK(signers.size() == 4);
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
    CHECK(execute_vote(snapshot, signer_b, no_vote, false) == ValidationResult::kUnhauthorizedSigner);
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
