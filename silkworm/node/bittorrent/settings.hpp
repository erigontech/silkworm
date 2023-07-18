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

#include <chrono>
#include <filesystem>
#include <optional>

namespace silkworm {

//! The settings for handling BitTorrent protocol
struct BitTorrentSettings {
    inline const static std::filesystem::path kDefaultTorrentRepoPath{".torrent"};
    constexpr static std::chrono::seconds kDefaultWaitBetweenAlertPolls{1};
    constexpr static int kDefaultNumberOfPollsBetweenStats{30};
    constexpr static std::chrono::seconds kDefaultResumeDataSaveInterval{60};
    constexpr static bool kDefaultVerifyOnStartup{false};
    constexpr static bool kDefaultSeeding{false};

    constexpr static int kDefaultDownloadRateLimit{64 * 1024 * 1024};  // 64MiB
    constexpr static int kDefaultUploadRateLimit{4 * 1024 * 1024};     // 4MiB
    constexpr static int kDefaultActiveDownloads{6};
    constexpr static int kDefaultMaxOutRequestQueue{6000};
    constexpr static bool kDefaultAnnounceToAllTiers{true};
    constexpr static int kDefaultAsyncIOThreads{32};

    /* BitTorrentClient configuration settings */
    //! Directory path where torrent files will be stored
    std::filesystem::path repository_path{kDefaultTorrentRepoPath};

    //! Path for magnet links
    std::optional<std::string> magnets_file_path;

    //! Time interval between two alert polling loopsErigon forks 242
    std::chrono::seconds wait_between_alert_polls{kDefaultWaitBetweenAlertPolls};

    //! The number of alert polls between two contiguous stats requests
    int number_of_polls_between_stats{kDefaultNumberOfPollsBetweenStats};

    //! Time interval between two resume data savings
    std::chrono::seconds resume_data_save_interval{kDefaultResumeDataSaveInterval};

    //! Flag indicating if snapshots will be verified on startup
    bool verify_on_startup{kDefaultVerifyOnStartup};

    //! Flag indicating if the client should seed torrents when done or not
    bool seeding{kDefaultSeeding};

    /* BitTorrent protocol settings */
    int download_rate_limit{kDefaultDownloadRateLimit};
    int upload_rate_limit{kDefaultUploadRateLimit};
    int active_downloads{kDefaultActiveDownloads};
    int max_out_request_queue{kDefaultMaxOutRequestQueue};
    bool announce_to_all_tiers{kDefaultAnnounceToAllTiers};
    int aio_threads{kDefaultAsyncIOThreads};
};

}  // namespace silkworm
