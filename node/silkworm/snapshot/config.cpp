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

#include "config.hpp"

#include <algorithm>

#include <toml.hpp>

#include <silkworm/common/log.hpp>

namespace silkworm::snapshot {

PreverifiedList from_toml(std::string_view preverified_toml_doc) {
    const auto table = toml::parse(preverified_toml_doc);
    SILK_DEBUG << "from_toml #size: " << preverified_toml_doc.size() << " #snapshots: " << table.size();

    PreverifiedList preverified;
    preverified.reserve(table.size());
    for (auto&& [key, value] : table) {
        preverified.emplace_back(PreverifiedEntry{
            {key.begin(), key.end()},
            value.as_string()->get()});
    }
    std::sort(preverified.begin(), preverified.end(), [](auto& p1, auto& p2) { return p1.name < p2.name; });

    std::for_each(preverified.begin(), preverified.end(), [](auto& p) {
        SILK_DEBUG << "name: " << p.name << " hash: " << p.hash;
    });

    return preverified;
}

}  // namespace silkworm::snapshot
