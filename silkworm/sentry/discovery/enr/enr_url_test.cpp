// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "enr_url.hpp"

#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/udp.hpp>
#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/sentry/common/ecc_key_pair.hpp>

namespace silkworm::sentry::discovery::enr {

static EccKeyPair test_key_pair() {
    constexpr std::string_view kPrivateKey = "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291";
    return EccKeyPair{from_hex(kPrivateKey).value()};
}

using namespace boost::asio::ip;

TEST_CASE("EnrUrl::parse") {
    {
        auto record = EnrUrl::parse("enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8");
        CHECK(to_hex(record.public_key.serialized_std(/* is_compressed = */ true)) == "03ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138");
        CHECK(record.seq_num == 1);
        REQUIRE(record.address_v4.has_value());
        CHECK(record.address_v4->endpoint.address().to_string() == "127.0.0.1");
        CHECK(record.address_v4->endpoint.port() == 30303);
        CHECK(record.address_v4->port_rlpx == 0);
        CHECK_FALSE(record.address_v6.has_value());
    }

    {
        auto record = EnrUrl::parse("enr:-Ku4QHqVeJ8PPICcWk1vSn_XcSkjOkNiTg6Fmii5j6vUQgvzMc9L1goFnLKgXqBJspJjIsB91LTOleFmyWWrFVATGngBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhAMRHkWJc2VjcDI1NmsxoQKLVXFOhp2uX6jeT0DvvDpPcU8FWMjQdR4wMuORMhpX24N1ZHCCIyg");
        CHECK(record.seq_num == 1);
        REQUIRE(record.address_v4.has_value());
        CHECK(record.address_v4->endpoint.address().to_string() == "3.17.30.69");
        CHECK(record.address_v4->endpoint.port() == 9000);
    }

    {
        auto record = EnrUrl::parse("enr:-Ku4QImhMc1z8yCiNJ1TyUxdcfNucje3BGwEHzodEZUan8PherEo4sF7pPHPSIB1NNuSg5fZy7qFsjmUKs2ea1Whi0EBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQOVphkDqal4QzPMksc5wnpuC3gvSC8AfbFOnZY_On34wIN1ZHCCIyg");
        CHECK(record.seq_num == 1);
        REQUIRE(record.address_v4.has_value());
        CHECK(record.address_v4->endpoint.address().to_string() == "18.223.219.100");
        CHECK(record.address_v4->endpoint.port() == 9000);
    }
}

TEST_CASE("EnrUrl::encode_decode") {
    EccKeyPair key_pair = test_key_pair();
    EnrRecord expected_record{
        key_pair.public_key(),
        123,
        NodeAddress{make_address("10.0.0.1"), 100, 101},
        NodeAddress{make_address("fe80::40b6:ef45:4458:7fcf"), 200, 201},
        Bytes{0x83, 'e', '1', 'f'},
        Bytes{0x83, 'e', '2', 'f'},
        Bytes{0x83, 'a', 't', 'n'},
    };
    auto actual_record = EnrUrl::parse(EnrUrl::make(expected_record, key_pair));
    CHECK(actual_record.public_key == expected_record.public_key);
    CHECK(actual_record.seq_num == expected_record.seq_num);
    REQUIRE(expected_record.address_v4.has_value());
    CHECK(actual_record.address_v4->endpoint == expected_record.address_v4->endpoint);
    CHECK(actual_record.address_v4->port_rlpx == expected_record.address_v4->port_rlpx);
    REQUIRE(expected_record.address_v6.has_value());
    CHECK(actual_record.address_v6->endpoint == expected_record.address_v6->endpoint);
    CHECK(actual_record.address_v6->port_rlpx == expected_record.address_v6->port_rlpx);
    CHECK(actual_record.eth1_fork_id_data == expected_record.eth1_fork_id_data);
    CHECK(actual_record.eth2_fork_id_data == expected_record.eth2_fork_id_data);
    CHECK(actual_record.eth2_attestation_subnets_data == expected_record.eth2_attestation_subnets_data);
}

}  // namespace silkworm::sentry::discovery::enr