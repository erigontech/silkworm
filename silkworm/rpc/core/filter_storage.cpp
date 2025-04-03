// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "filter_storage.hpp"

#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/json/types.hpp>

namespace silkworm::rpc {

std::mt19937_64 random_engine{std::random_device{}()};

Generator default_generator = []() { return random_engine(); };

FilterStorage::FilterStorage(size_t max_size, double max_filter_age) : generator_{default_generator}, max_size_{max_size}, max_filter_age_{max_filter_age} {}

FilterStorage::FilterStorage(Generator& generator, size_t max_size, double max_filter_age) : generator_{generator}, max_size_{max_size}, max_filter_age_{max_filter_age} {}

std::optional<std::string> FilterStorage::add_filter(const StoredFilter& filter) {
    std::scoped_lock lock{mutex_};

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
    size_t count{0};
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
    std::scoped_lock lock{mutex_};

    const auto itr = storage_.find(filter_id);
    if (itr == storage_.end()) {
        return false;
    }
    storage_.erase(itr);

    return true;
}

std::optional<std::reference_wrapper<StoredFilter>> FilterStorage::get_filter(const std::string& filter_id) {
    std::scoped_lock lock{mutex_};

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
