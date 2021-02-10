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

#include "block.hpp"

#include <catch2/catch.hpp>

namespace silkworm {

TEST_CASE("BlockBody RLP") {
    // https://etherscan.io/block/3
    const char* rlp_hex{
        "f90219c0f90215f90212a0d4e56740f876aef8c010b86a40d5f56745a118d090"
        "6a34e69aec8c0db1cb8fa3a01dcc4de8dec75d7aab85b567b6ccd41ad312451b"
        "948a7413f0a142fd40d4934794c8ebccc5f5689fa8659d83713341e5ad193494"
        "48a01e6e030581fd1873b4784280859cd3b3c04aa85520f08c304cf5ee63d393"
        "5adda056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e3"
        "63b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5"
        "e363b421b9010000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "000000000000008503ff80000001821388808455ba42429a5961746573205261"
        "6e64616c6c202d2045746865724e696e6a61a0f8c94dfe61cf26dcdf8cffeda3"
        "37cf6a903d65c449d7691a022837f6e2d994598868b769c5451a7aea"};

    Bytes rlp_bytes{*from_hex(rlp_hex)};
    ByteView in{rlp_bytes};
    BlockBody bb{};

    REQUIRE(rlp::decode(in, bb) == rlp::DecodingResult::kOk);

    CHECK(bb.transactions.size() == 0);
    REQUIRE(bb.ommers.size() == 1);
    CHECK(bb.ommers[0].number == 1);
    CHECK(bb.ommers[0].beneficiary == 0xc8ebccc5f5689fa8659d83713341e5ad19349448_address);
    CHECK(bb.ommers[0].difficulty == 17'171'480'576);

    Bytes out{};
    rlp::encode(out, bb);
    CHECK(to_hex(out) == rlp_hex);
}

TEST_CASE("BlockBody RLP 2") {
    BlockBody body{};
    body.transactions.resize(2);

    body.transactions[0].nonce = 172339;
    body.transactions[0].gas_price = 50 * kGiga;
    body.transactions[0].gas_limit = 90'000;
    body.transactions[0].to = 0xe5ef458d37212a06e3f59d40c454e76150ae7c32_address;
    body.transactions[0].value = 1'027'501'080 * kGiga;
    body.transactions[0].data = {};
    body.transactions[0].v = 27;
    body.transactions[0].r =
        intx::from_string<intx::uint256>("0x48b55bfa915ac795c431978d8a6a992b628d557da5ff759b307d495a36649353");
    body.transactions[0].s =
        intx::from_string<intx::uint256>("0x1fffd310ac743f371de3b9f7f9cb56c0b28ad43601b4ab949f53faa07bd2c804");

    body.transactions[1].nonce = 1;
    body.transactions[1].gas_price = 50 * kGiga;
    body.transactions[1].gas_limit = 1'000'000;
    body.transactions[1].to = {};
    body.transactions[1].value = 0;
    body.transactions[1].data = *from_hex("602a6000556101c960015560068060166000396000f3600035600055");
    body.transactions[1].v = 37;
    body.transactions[1].r =
        intx::from_string<intx::uint256>("0x52f8f61201b2b11a78d6e866abc9c3db2ae8631fa656bfe5cb53668255367afb");
    body.transactions[1].s =
        intx::from_string<intx::uint256>("0x52f8f61201b2b11a78d6e866abc9c3db2ae8631fa656bfe5cb53668255367afb");

    body.ommers.resize(1);
    body.ommers[0].parent_hash = 0xb397a22bb95bf14753ec174f02f99df3f0bdf70d1851cdff813ebf745f5aeb55_bytes32;
    body.ommers[0].ommers_hash = kEmptyListHash;
    body.ommers[0].beneficiary = 0x0c729be7c39543c3d549282a40395299d987cec2_address;
    body.ommers[0].state_root = 0xc2bcdfd012534fa0b19ffba5fae6fc81edd390e9b7d5007d1e92e8e835286e9d_bytes32;
    body.ommers[0].transactions_root = kEmptyRoot;
    body.ommers[0].receipts_root = kEmptyRoot;
    body.ommers[0].difficulty = 12'555'442'155'599;
    body.ommers[0].number = 1'000'013;
    body.ommers[0].gas_limit = 3'141'592;
    body.ommers[0].gas_used = 0;
    body.ommers[0].timestamp = 1455404305;
    body.ommers[0].mix_hash = 0xf0a53dfdd6c2f2a661e718ef29092de60d81d45f84044bec7bf4b36630b2bc08_bytes32;
    body.ommers[0].nonce[7] = 35;

    Bytes rlp{};
    rlp::encode(rlp, body);

    ByteView view{rlp};
    BlockBody decoded{};
    REQUIRE(rlp::decode(view, decoded) == rlp::DecodingResult::kOk);

    CHECK(view.empty());
    CHECK(decoded == body);
}

TEST_CASE("Invlaid Block RLP") {
    // Consensus test RLP_InputList_TooManyElements_HEADER_DECODEINTO_BLOCK_EXTBLOCK_HEADER
    const char* rlp_hex{
        "0xf90260f90207a068a61c4a05db4913009de5666753258eb9306157680dc5da0d93656550c9257ea01dcc4de8dec75d7aab85b567b6cc"
        "d41ad312451b948a7413f0a142fd40d49347948888f1f195afa192cfee860698584c030f4c9db1a0ef1552a40b7165c3cd773806b9e0c1"
        "65b75356e0314bf0706f279c729f51e017a0b6c9fd1447d0b414a1f05957927746f58ef5a2ebde17db631d460eaf6a93b18da0bc37d797"
        "53ad738a6dac4921e57392f145d8887476de3f783dfa7edae9283e52b90100000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000008302000001832fefd8825208845509814280a00451dd53d9c09f3cfb627b51d9d80632ed801f6330ee584b"
        "ffc26caac9b9249f88c7bffe5ebd94cc2ff861f85f800a82c35094095e7baea6a6c7c4c2dfeb977efac326af552d870a801ba098c3a099"
        "885a281885f487fd37550de16436e8c47874cd213531b10fe751617fa044b6b81011ce57bffcaf610bf728fb8a7237ad261ea2d937423d"
        "78eb9e137076c0"};

    Bytes rlp_bytes{*from_hex(rlp_hex)};
    ByteView view{rlp_bytes};
    Block block;

    CHECK(rlp::decode(view, block) == rlp::DecodingResult::kListLengthMismatch);
}

}  // namespace silkworm
