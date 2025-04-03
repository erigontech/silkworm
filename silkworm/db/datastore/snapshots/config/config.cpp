// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "config.hpp"

#include <ranges>
#include <span>

#include <silkworm/core/common/small_map.hpp>

#include "chains/amoy.hpp"
#include "chains/bor_mainnet.hpp"
#include "chains/holesky.hpp"
#include "chains/mainnet.hpp"
#include "chains/sepolia.hpp"

namespace silkworm::snapshots {

inline constexpr SmallMap<ChainId, std::span<const Entry>> kKnownConfigGeneratedEntries{
    {*kKnownChainNameToId.find("mainnet"sv), {kMainnetSnapshots.data(), kMainnetSnapshots.size()}},
    {*kKnownChainNameToId.find("sepolia"sv), {kSepoliaSnapshots.data(), kSepoliaSnapshots.size()}},
    {*kKnownChainNameToId.find("holesky"sv), {kHoleskySnapshots.data(), kHoleskySnapshots.size()}},
    {*kKnownChainNameToId.find("bor-mainnet"sv), {kBorMainnetSnapshots.data(), kBorMainnetSnapshots.size()}},
    {*kKnownChainNameToId.find("amoy"sv), {kAmoySnapshots.data(), kAmoySnapshots.size()}},
};

Config Config::lookup_known_config(
    ChainId chain_id,
    std::optional<std::function<bool(std::string_view file_name)>> include_filter_opt) {
    const auto entries_ptr = kKnownConfigGeneratedEntries.find(chain_id);
    if (!entries_ptr) {
        return Config{PreverifiedList{}};
    }

    PreverifiedList entries(entries_ptr->begin(), entries_ptr->end());
    entries = remove_unsupported_entries(entries);

    if (include_filter_opt) {
        auto& include_filter = *include_filter_opt;
        std::erase_if(entries, [&](const Entry& entry) {
            return !include_filter(entry.file_name);
        });
    }

    return Config{std::move(entries)};
}

PreverifiedList Config::remove_unsupported_entries(const PreverifiedList& entries) {
    static constexpr std::array kUnsupportedSnapshotNameTokens = {
        "/"sv,
        ".txt"sv,
        "beaconblocks"sv,
        "blobsidecars"sv,
    };

    PreverifiedList results = entries;

    // erase file names containing any of the unsupported tokens
    std::erase_if(results, [&](const Entry& entry) {
        return std::ranges::any_of(kUnsupportedSnapshotNameTokens, [&entry](std::string_view token) {
            // NOLINTNEXTLINE(abseil-string-find-str-contains)
            return entry.file_name.find(token) != std::string_view::npos;
        });
    });

    return results;
}

PreverifiedListOfPairs Config::preverified_snapshots_as_pairs() const {
    PreverifiedListOfPairs entries;
    for (const Entry& entry : entries_) {
        entries.emplace_back(entry.file_name, entry.torrent_hash);
    }
    return entries;
}

bool Config::contains_file_name(std::string_view file_name) const {
    return std::ranges::any_of(entries_, [&](const Entry& entry) {
        return entry.file_name == file_name;
    });
}

}  // namespace silkworm::snapshots
