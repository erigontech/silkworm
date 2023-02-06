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

#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <vector>

// Disable warnings raised during compilation of libtorrent
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wc++11-compat"
#pragma GCC diagnostic ignored "-Wshadow"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#include <libtorrent/session.hpp>
#include <libtorrent/session_params.hpp>
#pragma GCC diagnostic pop

namespace silkworm {

//! The settings for handling BitTorrent protocol
struct BitTorrentSettings {
    inline const static std::filesystem::path kDefaultTorrentRepoPath{".torrent"};
    constexpr static std::chrono::seconds kDefaultWaitBetweenAlertPolls{10};
    constexpr static std::chrono::seconds kDefaultResumeDataSaveInterval{60};
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
    //! Time interval between two alert polling loops
    std::chrono::seconds wait_between_alert_polls{kDefaultWaitBetweenAlertPolls};
    //! Time interval between two resume data savings
    std::chrono::seconds resume_data_save_interval{kDefaultResumeDataSaveInterval};
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

//! The BitTorrent protocol client handling multiple torrents *asynchronously* using one thread.
//! \details The user code should probably run the `execute_loop` method in a dedicated thread.
class BitTorrentClient {
  public:
    constexpr static const char* kSessionFileName{".session"};
    constexpr static const char* kResumeDirName{".resume"};
    constexpr static const char* kResumeFileExt{".resume"};

    explicit BitTorrentClient(BitTorrentSettings settings = {});
    ~BitTorrentClient();

    //! Add the specified info hash to the download list
    void add_info_hash(const std::string& name, const std::string& info_hash);

    //! Run the client execution loop until it is stopped or has finished downloading and seeding is not required
    void execute_loop();

    //! Ask the client to stop execution
    void stop();

  protected:
    static std::vector<char> load_file(const std::filesystem::path& filename);
    static void save_file(const std::filesystem::path& filename, const std::vector<char>& data);

    [[nodiscard]] lt::session_params load_or_create_session_parameters() const;
    [[nodiscard]] std::vector<lt::add_torrent_params> resume_or_create_magnets() const;
    [[nodiscard]] std::filesystem::path resume_file_path(const lt::info_hash_t& info_hashes) const;
    [[nodiscard]] bool exists_resume_file(const lt::info_hash_t& info_hashes) const;
    [[nodiscard]] inline bool all_torrents_seeding() const;

    void request_torrent_updates();
    void request_save_resume_data(lt::resume_data_flags_t flags);
    void process_alerts();
    bool handle_alert(const lt::alert* alert);

  private:
    //! The BitTorrent client configuration parameters
    BitTorrentSettings settings_;

    //! The file containing the session state
    std::filesystem::path session_file_;

    //! The directory containing the resume state files
    std::filesystem::path resume_dir_;

    //! The BitTorrent client session
    lt::session session_;

    //! The number of save resume data requests still outstanding
    int outstanding_resume_requests_{0};

    //! The last time when resume state has been saved
    std::chrono::steady_clock::time_point last_save_resume_;

    //! Mutual exclusion access to the stop condition
    std::mutex stop_mutex_;

    //! Condition indicating that the client should stop
    std::condition_variable stop_condition_;

    //! Flag indicating stop protected by mutex and signalled by condition variable
    bool stop_requested_{false};
};

}  // namespace silkworm
