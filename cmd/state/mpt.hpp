//// evmone: Fast Ethereum Virtual Machine implementation
//// Copyright 2022 The evmone Authors.
//// SPDX-License-Identifier: Apache-2.0
//#pragma once
//
//#include "hash_utils.hpp"
//#include <memory>
//
//namespace silkworm::state
//{
//using namespace evmc;
//constexpr auto emptyMPTHash =
//    0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421_bytes32;
//
///// Insert-only Merkle Patricia Trie implementation for getting the root hash
///// out of (key, value) pairs.
//class MPT
//{
//    std::unique_ptr<class MPTNode> m_root;
//
//public:
//    MPT() noexcept;
//    ~MPT() noexcept;
//
//    void insert(evmc::bytes_view key, evmc::bytes&& value);
//
//    [[nodiscard]] ethash::hash256 hash() const;
//};
//
//}  // namespace silkworm::state
