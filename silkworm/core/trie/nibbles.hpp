// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once
#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>

namespace silkworm::trie {

//! \brief Transforms a string of Nibbles into a string of Bytes
//! \def A Nibble's value is [0..16)
//! \see Erigon's CompressNibbles
Bytes pack_nibbles(ByteView unpacked);

//! \brief Transforms a string of bytes into a string of Nibbles
//! \def A Nibble's value is [0..16)
//! \see Erigon's DecompressNibbles
Bytes unpack_nibbles(ByteView data);

}  // namespace silkworm::trie
