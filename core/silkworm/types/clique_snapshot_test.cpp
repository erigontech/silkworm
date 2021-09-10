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

#include "clique_snapshot.hpp"

#include <catch2/catch.hpp>

#include <silkworm/common/util.hpp>

namespace silkworm {

nlohmann::json clique_json = R"({
        "hash": "04491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f",
        "number": 52,
        "signers": {
            "22341ae42d6dd7384bc8584e50419ea3ac75b83f": null,
            "e7fb22dfef11920312e4989a3a2b81e2ebf05986": null
        },
        "recents": {
            "0x00000010": "22341ae42d6dd7384bc8584e50419ea3ac75b83f",
            "0x00000022": "e7fb22dfef11920312e4989a3a2b81e2ebf05986"
        },
        "votes": [
            {
                "signer":  "e7fb22d2fef11920312e4989a3a2b81e2ebf0598",
                "address": "04491edcd115127caedbd478e2e7895ed80c7847",
                "block": 10,
                "authorize": false
            }
        ],
        "tally": {
            "e7fb22dfef11920312e4989a3a2b81e2ebf05986": {
                "votes": 43,
                "authorize": false
            }
        }
})"_json;

TEST_CASE("Encode/Decode Snapshot") {
    auto snapshot{CliqueSnapshot::from_json(clique_json)};
    auto decoded_snapshot{snapshot.to_json()};
    CHECK(decoded_snapshot == clique_json);
}
}  // namespace silkworm
