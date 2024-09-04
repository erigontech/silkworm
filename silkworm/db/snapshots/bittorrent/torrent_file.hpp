/*
   Copyright 2024 The Silkworm Authors

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
    TorrentFile(ByteView data);
    TorrentFile(const std::filesystem::path& path);

    static TorrentFile from_source_file(const std::filesystem::path& source_file_path, std::time_t creation_date = 0);

    const lt::add_torrent_params& params() const { return params_; }
    std::string info_hash() const;
    Bytes to_bytes() const;
    void save(const std::filesystem::path& path);

  private:
    lt::add_torrent_params params_;
};

}  // namespace silkworm::snapshots::bittorrent
