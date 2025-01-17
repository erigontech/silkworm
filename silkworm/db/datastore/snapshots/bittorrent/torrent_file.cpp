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

#include "torrent_file.hpp"

#include <fstream>
#include <iterator>
#include <sstream>
#include <string>

#include <libtorrent/create_torrent.hpp>
#include <libtorrent/file_storage.hpp>
#include <libtorrent/load_torrent.hpp>
#include <libtorrent/write_resume_data.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes_to_string.hpp>

#include "trackers.hpp"

namespace silkworm::snapshots::bittorrent {

static constexpr int kDefaultPieceSize = static_cast<int>(2_Mebi);

TorrentFile::TorrentFile(ByteView data)
    : params_(lt::load_torrent_buffer(byte_view_to_str_span(data))) {
}

TorrentFile::TorrentFile(const std::filesystem::path& path)
    : params_(lt::load_torrent_file(path.string())) {
}

TorrentFile TorrentFile::from_source_file(const std::filesystem::path& source_file_path, std::time_t creation_date) {
    lt::file_storage storage;
    lt::create_flags_t flags = lt::create_torrent::v1_only;
    lt::add_files(storage, source_file_path.string(), flags);

    lt::create_torrent torrent{storage, kDefaultPieceSize, flags};
    lt::set_piece_hashes(torrent, source_file_path.parent_path().string());
    torrent.set_creator("silkworm");
    if (creation_date > 0) {
        torrent.set_creation_date(creation_date);
    }
    for (auto& tracker : kBestTrackers) {
        torrent.add_tracker(tracker, 0);
    }

    std::string data;
    lt::bencode(std::back_inserter(data), torrent.generate());
    return TorrentFile{string_view_to_byte_view(data)};
}

std::string TorrentFile::info_hash() const {
    std::stringstream stream;
    stream << params_.ti->info_hashes().get_best();
    return stream.str();
}

Bytes TorrentFile::to_bytes() const {
    std::string data;
    lt::bencode(std::back_inserter(data), lt::write_torrent_file(params_));
    return string_to_bytes(data);
}

void TorrentFile::save(const std::filesystem::path& path) const {
    Bytes data = to_bytes();
    std::ofstream file{path, std::ios::binary | std::ios::trunc};
    file.exceptions(std::ios::failbit | std::ios::badbit);
    file << byte_view_to_string_view(data);
}

}  // namespace silkworm::snapshots::bittorrent
