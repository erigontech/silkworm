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

#include <atomic>
#include <filesystem>
#include <memory>
#include <set>
#include <string>
#include <thread>
#include <vector>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wc++11-compat"
#pragma GCC diagnostic ignored "-Wshadow"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#include <libtorrent/session.hpp>
#include <libtorrent/session_params.hpp>
#pragma GCC diagnostic pop

namespace silkworm {

constexpr const char* kDefaultTorrentRepoPath{".torrent"};
constexpr const char* kDefaultSessionFilePath{".session"};
constexpr const char* kDefaultResumeFilePath{".resume"};
constexpr const char* kDefaultMagnetsFilePath{".magnet_links"};

constexpr int kDefaultDownloadRateLimit{64 * 1024 * 1024};  // 64MiB
constexpr int kDefaultUploadRateLimit{4 * 1024 * 1024};     // 4MiB
constexpr int kDefaultActiveDownloads{6};

//! The settings for handling BitTorrent protocol
struct BitTorrentSettings {
    std::string repository_path{kDefaultTorrentRepoPath};
    std::string magnets_file_path{kDefaultMagnetsFilePath};
    int download_rate_limit{kDefaultDownloadRateLimit};
    int upload_rate_limit{kDefaultUploadRateLimit};
    int active_downloads{kDefaultActiveDownloads};
};

//! The BitTorrent protocol client handling multiple torrents *asynchronously* using one thread.
class BitTorrentClient {
  public:
    explicit BitTorrentClient(BitTorrentSettings settings);
    ~BitTorrentClient();

    void resume();
    void wait_for_completion();
    void stop();

  protected:
    static std::vector<char> load_file(const std::string& filename);
    static void save_file(const std::string& filename, const std::vector<char>& data);

    [[nodiscard]] lt::session_params load_or_create_session_parameters() const;
    std::vector<lt::add_torrent_params> resume_or_create_magnets();

  private:
    void run();

    BitTorrentSettings settings_;
    lt::session_params session_params_;
    std::string session_file_path_;
    std::string resume_file_prefix_;

    // TODO(canepat) replace w/ std::jthread when supported by LLVM libc++
    std::thread worker_thread_;
    std::atomic<bool> stop_token_{false};
};

}  // namespace silkworm
