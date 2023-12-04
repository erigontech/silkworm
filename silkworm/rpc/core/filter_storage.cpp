/*
   Copyright 2023 The Silkworm Authors

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

#include "filter_storage.hpp"

#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/json/types.hpp>

namespace silkworm::rpc {

std::mt19937_64 random_engine{std::random_device{}()};

Generator default_generator = []() { return random_engine(); };

FilterStorage::FilterStorage(std::size_t max_size, double max_filter_age) : generator_{default_generator}, max_size_{max_size}, max_filter_age_{max_filter_age} {}

FilterStorage::FilterStorage(Generator& generator, std::size_t max_size, double max_filter_age) : generator_{generator}, max_size_{max_size}, max_filter_age_{max_filter_age} {}

std::optional<std::string> FilterStorage::add_filter(const StoredFilter& filter) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (storage_.size() >= max_size_) {
        clean_up();
    }

    if (storage_.size() >= max_size_) {
        SILK_WARN << "No room available in storage, max size " << max_size_ << " reached";
        return std::nullopt;
    }

    FilterEntry entry{filter};
    std::string filter_id;
    bool slot_found{false};
    std::size_t count{0};
    while (max_size_ > count++) {
        filter_id = to_quantity(generator_());
        slot_found = storage_.find(filter_id) == storage_.end();
        if (slot_found) {
            break;
        }
    }
    if (!slot_found) {
        SILK_WARN << "Unable to generate a new filter_id without clashing";
        return std::nullopt;
    }

    storage_.emplace(filter_id, entry);
    return filter_id;
}

bool FilterStorage::remove_filter(const std::string& filter_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    const auto itr = storage_.find(filter_id);
    if (itr == storage_.end()) {
        return false;
    }
    storage_.erase(itr);

    return true;
}

std::optional<std::reference_wrapper<StoredFilter>> FilterStorage::get_filter(const std::string& filter_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    clean_up();

    const auto itr = storage_.find(filter_id);
    if (itr == storage_.end()) {
        return std::nullopt;
    }

    auto age = itr->second.age();
    if (age > max_filter_age_) {
        SILK_TRACE << "Filter  " << filter_id << " exhausted: removed";
        storage_.erase(itr);
        return std::nullopt;
    }

    itr->second.renew();
    return itr->second.filter;
}

void FilterStorage::clean_up() {
    auto itr = storage_.begin();
    while (itr != storage_.end()) {
        auto age = itr->second.age();
        if (age > max_filter_age_) {
            SILK_TRACE << "Filter  " << itr->first << " exhausted: removed";
            itr = storage_.erase(itr);
        } else {
            ++itr;
        }
    }
}
}  // namespace silkworm::rpc
