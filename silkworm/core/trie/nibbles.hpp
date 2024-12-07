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
