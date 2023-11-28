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
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <span>
#include <string_view>
#include <thread>
#include <vector>

#include <boost/signals2.hpp>
// Disable warnings raised during compilation of libtorrent
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wc++11-compat"
#pragma GCC diagnostic ignored "-Wshadow"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#include <libtorrent/session.hpp>
#include <libtorrent/session_params.hpp>
#include <libtorrent/session_stats.hpp>
#pragma GCC diagnostic pop

#include <silkworm/node/bittorrent/settings.hpp>

namespace silkworm {

//! The BitTorrent protocol client handling multiple torrents *asynchronously* using one thread.
//! \details The user code should probably run the `execute_loop` method in a dedicated thread.
class BitTorrentClient {
  public:
    constexpr static const char* kSessionFileName{".session"};
    constexpr static const char* kResumeDirName{".resume"};
    constexpr static const char* kResumeFileExt{".resume"};

    using FileCallback = void(const std::filesystem::path&);
    using StatsCallback = void(lt::span<const int64_t> counters);

    explicit BitTorrentClient(BitTorrentSettings settings = {});
    ~BitTorrentClient();

    //! Subscription for torrent added announcements
    boost::signals2::signal<FileCallback> added_subscription;

    //! Subscription for torrent metrics' announcements
    boost::signals2::signal<StatsCallback> stats_subscription;

    //! Subscription for torrent completion announcements
    boost::signals2::signal<FileCallback> completed_subscription;

    [[nodiscard]] const std::vector<lt::stats_metric>& stats_metrics() const { return stats_metrics_; }

    //! Add the specified info hash to the download list
    void add_info_hash(std::string_view name, std::string_view info_hash);

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

    void recheck_all_finished_torrents();
    void request_torrent_updates(bool stats_included);
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

    //! The session statistics
    std::vector<lt::stats_metric> stats_metrics_;

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
