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

namespace silkworm::snapshots::bittorrent {

//! The settings for handling BitTorrent protocol
struct BitTorrentSettings {
    static inline const std::filesystem::path kDefaultTorrentRepoPath{".torrent"};

    /* BitTorrentClient configuration settings */
    //! Directory path where torrent files will be stored
    std::filesystem::path repository_path{kDefaultTorrentRepoPath};

    //! Time interval between two alert polling loops
    std::chrono::seconds wait_between_alert_polls{1};

    //! The number of alert polls between two contiguous stats requests
    int number_of_polls_between_stats{30};

    //! Time interval between two resume data savings
    std::chrono::seconds resume_data_save_interval{60};

    //! Flag indicating if BitTorrent failure/error alerts should be treated as warnings
    bool warn_on_error_alerts{false};

    /* BitTorrent protocol settings */
    int download_rate_limit{64};  // 64MiB
    int upload_rate_limit{4};     // 4MiB
    int active_downloads{6};
    int max_out_request_queue{6000};
    bool announce_to_all_tiers{true};
    int aio_threads{32};
};

}  // namespace silkworm::snapshots::bittorrent
