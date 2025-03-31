// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <filesystem>

// Disable warnings raised during compilation of libtorrent
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#include <libtorrent/add_torrent_params.hpp>
#pragma GCC diagnostic pop

#include <silkworm/core/common/bytes.hpp>

namespace silkworm::snapshots::bittorrent {

class TorrentFile {
  public:
    explicit TorrentFile(ByteView data);
    explicit TorrentFile(const std::filesystem::path& path);

    static TorrentFile from_source_file(const std::filesystem::path& source_file_path, std::time_t creation_date = 0);

    const lt::add_torrent_params& params() const { return params_; }
    std::string info_hash() const;
    Bytes to_bytes() const;
    void save(const std::filesystem::path& path) const;

  private:
    lt::add_torrent_params params_;
};

}  // namespace silkworm::snapshots::bittorrent
