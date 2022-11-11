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

#include "types.hpp"

#include <catch2/catch.hpp>

#include <silkworm/common/util.hpp>
#include <silkworm/lightclient/test/ssz.hpp>

namespace silkworm::cl {

TEST_CASE("Eth1Data SSZ") {
    SECTION("round-trip") {
        Eth1Data a{
            0xFF000000000000000000EE00000000000000000000EE000000000000000000FF_bytes32,
            31,
            0xFF000000000000000000EE00000000000000000000EE000000000000000000FF_bytes32
        };
        Bytes b{};
        ssz::encode(a, b);
        CHECK(b == *from_hex(
                       "FF000000000000000000EE00000000000000000000EE000000000000000000FF"
                       "1F00000000000000"
                       "FF000000000000000000EE00000000000000000000EE000000000000000000FF"));
        CHECK(test::decode_success<Eth1Data>(to_hex(b)) == a);
    }
    SECTION("decoding error") {
        CHECK(test::decode_failure<Eth1Data>("") == DecodingResult::kInputTooShort);
        CHECK(test::decode_failure<Eth1Data>("00") == DecodingResult::kInputTooShort);
        CHECK(test::decode_failure<Eth1Data>("FF000000000000000000EE00000000000000000000EE000000000000000000FF"
                                             "1F00000000000000"
                                             "FF000000000000000000EE00000000000000000000EE000000000000000000")
              == DecodingResult::kInputTooShort);
    }
}

TEST_CASE("Checkpoint SSZ") {
    SECTION("round-trip") {
        Checkpoint a{
            21,
            0xFF000000000000000000EE00000000000000000000EE000000000000000000FF_bytes32
        };
        Bytes b{};
        ssz::encode(a, b);
        CHECK(b == *from_hex(
                       "1500000000000000"
                       "FF000000000000000000EE00000000000000000000EE000000000000000000FF"));
        CHECK(test::decode_success<Checkpoint>(to_hex(b)) == a);
    }
    SECTION("decoding error") {
        CHECK(test::decode_failure<Checkpoint>("") == DecodingResult::kInputTooShort);
        CHECK(test::decode_failure<Checkpoint>("00") == DecodingResult::kInputTooShort);
        CHECK(test::decode_failure<Checkpoint>("1F00000000000000"
                                             "FF000000000000000000EE00000000000000000000EE000000000000000000")
              == DecodingResult::kInputTooShort);
    }
}

TEST_CASE("AttestationData SSZ") {
    SECTION("round-trip") {
        AttestationData a{
            120,
            6,
            0xFF000000000000000000EE00000000000000000000EE000000000000000000FF_bytes32,
            std::make_unique<Checkpoint>(Checkpoint{
                21,
                0xFF000000000000000000EE00000000000000000000EE000000000000000000FF_bytes32
            }),
            std::make_unique<Checkpoint>(Checkpoint{
                21,
                0xFF000000000000000000EE00000000000000000000EE000000000000000000FF_bytes32
            }),
        };
        Bytes b{};
        ssz::encode(a, b);
        CHECK(b == *from_hex(
                       "7800000000000000"
                       "0600000000000000"
                       "FF000000000000000000EE00000000000000000000EE000000000000000000FF"
                       "1500000000000000"
                       "FF000000000000000000EE00000000000000000000EE000000000000000000FF"
                       "1500000000000000"
                       "FF000000000000000000EE00000000000000000000EE000000000000000000FF"));
        CHECK(test::decode_success<AttestationData>(to_hex(b)) == a);
    }
    SECTION("decoding error") {
        CHECK(test::decode_failure<AttestationData>("") == DecodingResult::kInputTooShort);
        CHECK(test::decode_failure<AttestationData>("00") == DecodingResult::kInputTooShort);
        CHECK(test::decode_failure<AttestationData>("7400000000000000"
                                                    "0600000000000000"
                                                    "FF000000000000000000EE00000000000000000000EE000000000000000000FF"
                                                    "1F00000000000000"
                                                    "FF000000000000000000EE00000000000000000000EE000000000000000000FF"
                                                    "1F00000000000000"
                                                    "FF000000000000000000EE00000000000000000000EE000000000000000000")
              == DecodingResult::kInputTooShort);
    }
}

TEST_CASE("BeaconBlockHeader SSZ") {
    SECTION("round-trip") {
        BeaconBlockHeader a{
            21,
            120,
            0xFF000000000000000000EE00000000000000000000EE000000000000000000FF_bytes32,
            0xFF000000000000000000EE00000000000000000000EE000000000000000000FF_bytes32,
            0xFF000000000000000000EE00000000000000000000EE000000000000000000FF_bytes32
        };
        Bytes b{};
        ssz::encode(a, b);
        CHECK(b == *from_hex(
                       "1500000000000000"
                       "7800000000000000"
                       "FF000000000000000000EE00000000000000000000EE000000000000000000FF"
                       "FF000000000000000000EE00000000000000000000EE000000000000000000FF"
                       "FF000000000000000000EE00000000000000000000EE000000000000000000FF"));
        CHECK(test::decode_success<BeaconBlockHeader>(to_hex(b)) == a);
    }
    SECTION("decoding error") {
        CHECK(test::decode_failure<BeaconBlockHeader>("") == DecodingResult::kInputTooShort);
        CHECK(test::decode_failure<BeaconBlockHeader>("00") == DecodingResult::kInputTooShort);
        CHECK(test::decode_failure<BeaconBlockHeader>("1500000000000000"
                                                      "7800000000000000"
                                                      "FF000000000000000000EE00000000000000000000EE000000000000000000FF"
                                                      "FF000000000000000000EE00000000000000000000EE000000000000000000FF"
                                                      "FF000000000000000000EE00000000000000000000EE000000000000000000")
              == DecodingResult::kInputTooShort);
    }
}

TEST_CASE("SignedBeaconBlockHeader SSZ") {
    SECTION("round-trip") {
        SignedBeaconBlockHeader a{
            std::make_unique<BeaconBlockHeader>(BeaconBlockHeader{
                21,
                120,
                0xFF000000000000000000EE00000000000000000000EE000000000000000000FF_bytes32,
                0xFF000000000000000000EE00000000000000000000EE000000000000000000FF_bytes32,
                0xFF000000000000000000EE00000000000000000000EE000000000000000000FF_bytes32
            }),
            {}
        };
        Bytes b{};
        ssz::encode(a, b);
        CHECK(b == *from_hex(
                       "1500000000000000"
                       "7800000000000000"
                       "FF000000000000000000EE00000000000000000000EE000000000000000000FF"
                       "FF000000000000000000EE00000000000000000000EE000000000000000000FF"
                       "FF000000000000000000EE00000000000000000000EE000000000000000000FF"
                       "0000000000000000000000000000000000000000000000000000000000000000"
                       "0000000000000000000000000000000000000000000000000000000000000000"
                       "0000000000000000000000000000000000000000000000000000000000000000"));
        CHECK(test::decode_success<SignedBeaconBlockHeader>(to_hex(b)) == a);
    }
    SECTION("decoding error") {
        CHECK(test::decode_failure<SignedBeaconBlockHeader>("") == DecodingResult::kInputTooShort);
        CHECK(test::decode_failure<SignedBeaconBlockHeader>("00") == DecodingResult::kInputTooShort);
        CHECK(test::decode_failure<SignedBeaconBlockHeader>("1500000000000000"
                                                            "7800000000000000"
                                                            "FF000000000000000000EE00000000000000000000EE000000000000000000FF"
                                                            "FF000000000000000000EE00000000000000000000EE000000000000000000FF"
                                                            "FF000000000000000000EE00000000000000000000EE00000000000000000000"
                                                            "0000000000000000000000000000000000000000000000000000000000000000"
                                                            "0000000000000000000000000000000000000000000000000000000000000000"
                                                            "00000000000000000000000000000000000000000000000000000000000000")
              == DecodingResult::kInputTooShort);
    }
}

TEST_CASE("IndexedAttestation SSZ") {
    SECTION("round-trip zero indices") {
        IndexedAttestation a{
            {},
            std::make_unique<AttestationData>(AttestationData{
                120,
                6,
                0xFF000000000000000000EE00000000000000000000EE000000000000000000FF_bytes32,
                std::make_unique<Checkpoint>(Checkpoint{
                    21,
                    0xFF000000000000000000EE00000000000000000000EE000000000000000000FF_bytes32}),
                std::make_unique<Checkpoint>(Checkpoint{
                    21,
                    0xFF000000000000000000EE00000000000000000000EE000000000000000000FF_bytes32}),
            }),
            {}
        };
        Bytes b{};
        ssz::encode(a, b);
        CHECK(b == *from_hex(
                       "E4000000"
                       "7800000000000000"
                       "0600000000000000"
                       "FF000000000000000000EE00000000000000000000EE000000000000000000FF"
                       "1500000000000000"
                       "FF000000000000000000EE00000000000000000000EE000000000000000000FF"
                       "1500000000000000"
                       "FF000000000000000000EE00000000000000000000EE000000000000000000FF"
                       "0000000000000000000000000000000000000000000000000000000000000000"
                       "0000000000000000000000000000000000000000000000000000000000000000"
                       "0000000000000000000000000000000000000000000000000000000000000000"));
        CHECK(test::decode_success<IndexedAttestation>(to_hex(b)) == a);
    }
    SECTION("decoding error") {
        CHECK(test::decode_failure<IndexedAttestation>("") == DecodingResult::kInputTooShort);
        CHECK(test::decode_failure<IndexedAttestation>("00") == DecodingResult::kInputTooShort);
        CHECK(test::decode_failure<IndexedAttestation>("E4000000"
                                                       "7800000000000000"
                                                       "0600000000000000"
                                                       "FF000000000000000000EE00000000000000000000EE000000000000000000FF"
                                                       "1500000000000000"
                                                       "FF000000000000000000EE00000000000000000000EE000000000000000000FF"
                                                       "1500000000000000"
                                                       "FF000000000000000000EE00000000000000000000EE000000000000000000FF"
                                                       "0000000000000000000000000000000000000000000000000000000000000000"
                                                       "0000000000000000000000000000000000000000000000000000000000000000"
                                                       "00000000000000000000000000000000000000000000000000000000000000")
              == DecodingResult::kInputTooShort);
    }
    SECTION("round-trip two indices") {
        IndexedAttestation a{
            {1, 11},
            std::make_unique<AttestationData>(AttestationData{
                120,
                6,
                0xFF000000000000000000EE00000000000000000000EE000000000000000000FF_bytes32,
                std::make_unique<Checkpoint>(Checkpoint{
                    21,
                    0xFF000000000000000000EE00000000000000000000EE000000000000000000FF_bytes32}),
                std::make_unique<Checkpoint>(Checkpoint{
                    21,
                    0xFF000000000000000000EE00000000000000000000EE000000000000000000FF_bytes32}),
            }),
            {}
        };
        Bytes b{};
        ssz::encode(a, b);
        CHECK(b == *from_hex(
                       "E4000000"
                       "7800000000000000"
                       "0600000000000000"
                       "FF000000000000000000EE00000000000000000000EE000000000000000000FF"
                       "1500000000000000"
                       "FF000000000000000000EE00000000000000000000EE000000000000000000FF"
                       "1500000000000000"
                       "FF000000000000000000EE00000000000000000000EE000000000000000000FF"
                       "0000000000000000000000000000000000000000000000000000000000000000"
                       "0000000000000000000000000000000000000000000000000000000000000000"
                       "0000000000000000000000000000000000000000000000000000000000000000"
                       "0100000000000000"
                       "0B00000000000000"));
        CHECK(test::decode_success<IndexedAttestation>(to_hex(b)) == a);
    }
}

}  // namespace silkworm::cl
