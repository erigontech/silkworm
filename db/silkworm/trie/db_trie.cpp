/*
   Copyright 2021 The Silkworm Authors

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

#include "db_trie.hpp"

namespace silkworm::trie {

evmc::bytes32 regenerate_db_tries(lmdb::Transaction&) {
    // TODO[Issue 179] implement
    // TODO[Issue 179] use ETL
    // TODO[Issue 179] storage

    return kEmptyRoot;
}

Node unmarshal_node(ByteView) {
    Node n;
    // TODO[Issue 179] implement
    return n;
}

}  // namespace silkworm::trie
