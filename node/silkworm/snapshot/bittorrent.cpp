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

#include "bittorrent.hpp"

#include <fstream>
#include <utility>

#include <libtorrent/alert_types.hpp>
#include <libtorrent/magnet_uri.hpp>
#include <libtorrent/read_resume_data.hpp>
#include <libtorrent/write_resume_data.hpp>
#include <magic_enum.hpp>

#include <silkworm/common/assert.hpp>
#include <silkworm/common/log.hpp>

namespace silkworm {

namespace fs = std::filesystem;
using namespace std::chrono_literals;

std::vector<char> BitTorrentClient::load_file(const std::string& filename) {
    std::ifstream input_file_stream{filename, std::ios_base::binary};
    input_file_stream.unsetf(std::ios_base::skipws);
    return {std::istream_iterator<char>(input_file_stream), std::istream_iterator<char>()};
}

void BitTorrentClient::save_file(const std::string& filename, const std::vector<char>& data) {
    std::ofstream output_file_stream{filename, std::ios_base::binary};
    output_file_stream.unsetf(std::ios_base::skipws);
    output_file_stream.write(data.data(), static_cast<std::streamsize>(data.size()));
}

BitTorrentClient::BitTorrentClient(BitTorrentSettings settings)
    : settings_(std::move(settings)),
      session_file_path_{settings_.repository_path + '/' + kDefaultSessionFilePath},
      resume_file_prefix_{settings_.repository_path + '/' + kDefaultResumeFilePath} {}

BitTorrentClient::~BitTorrentClient() {
    stop();
}

void BitTorrentClient::resume() {
    SILK_TRACE << "BitTorrentClient::resume start";
    session_params_ = load_or_create_session_parameters();
    worker_thread_ = std::thread{std::bind_front(&BitTorrentClient::run, this)};
    SILK_TRACE << "BitTorrentClient::resume end";
}

void BitTorrentClient::wait_for_completion() {
    SILK_TRACE << "BitTorrentClient::wait_for_completion start";
    if (worker_thread_.joinable()) worker_thread_.join();
    SILK_TRACE << "BitTorrentClient::wait_for_completion end";
}

void BitTorrentClient::stop() {
    SILK_TRACE << "BitTorrentClient::stop start";
    stop_token_ = true;
    SILK_TRACE << "BitTorrentClient::stop end";
}

lt::session_params BitTorrentClient::load_or_create_session_parameters() const {
    // Restore session parameters from old session, if any
    const auto prev_session_data = BitTorrentClient::load_file(session_file_path_);
    auto session_params =
        prev_session_data.empty() ? lt::session_params{} : lt::read_session_params(prev_session_data);

    // Customize the session settings
    auto& settings = session_params.settings;
    settings.set_int(lt::settings_pack::alert_mask,
                     lt::alert_category::error | lt::alert_category::storage | lt::alert_category::status |
                         lt::alert_category::file_progress | lt::alert_category::performance_warning);
    settings.set_int(lt::settings_pack::download_rate_limit, settings_.download_rate_limit);
    settings.set_int(lt::settings_pack::upload_rate_limit, settings_.upload_rate_limit);
    settings.set_int(lt::settings_pack::active_downloads, settings_.active_downloads);

    return session_params;
}

std::vector<lt::add_torrent_params> BitTorrentClient::resume_or_create_magnets() {
    fs::path repository_path{settings_.repository_path};
    fs::create_directories(repository_path);
    SILKWORM_ASSERT(fs::exists(repository_path) && fs::is_directory(repository_path));

    // Load the resulting resume files and re-create magnet parameters
    std::vector<lt::add_torrent_params> add_magnet_params;
    for (const auto& file : fs::directory_iterator{repository_path}) {
        if (!fs::is_regular_file(file.path()) || !file.path().filename().string().starts_with(resume_file_prefix_)) {
            continue;
        }
        SILK_DEBUG << "Path: " << file.path() << " name: " << file.path().filename();
        const auto resume_data = load_file(file.path().string());
        if (!resume_data.empty()) {
            auto add_magnet = lt::read_resume_data(resume_data);
            add_magnet.save_path = settings_.repository_path;
            add_magnet_params.push_back(add_magnet);
        }
    }

    // Add magnet parameters for other magnet links
    std::ifstream magnet_input_file_stream{settings_.magnets_file_path};
    std::string magnet_uri;
    while (std::getline(magnet_input_file_stream, magnet_uri)) {
        if (magnet_uri.empty()) continue;
        SILK_DEBUG << "Magnet URI from file: " << magnet_uri;
        lt::add_torrent_params add_magnet = lt::parse_magnet_uri(magnet_uri);
        add_magnet.save_path = settings_.repository_path;
        add_magnet_params.push_back(add_magnet);
    }

    return add_magnet_params;
}

void BitTorrentClient::run() {
    SILK_TRACE << "BitTorrentClient::run start";
    lt::session session{session_params_};

    auto add_magnet_params_sequence = resume_or_create_magnets();
    for (auto& add_magnet_params : add_magnet_params_sequence) {
        session.async_add_torrent(std::move(add_magnet_params));
    }
    std::chrono::steady_clock::time_point last_save_resume = std::chrono::steady_clock::now();
    SILK_DEBUG << "Resumed #torrents: " << add_magnet_params_sequence.size();

    std::set<lt::torrent_handle> torrent_handles;

    bool done{false};
    while (!stop_token_) {
        std::vector<lt::alert*> session_alerts;
        session.pop_alerts(&session_alerts);
        SILK_DEBUG << "Session raised #alerts: " << session_alerts.size();

        for (lt::alert const* alert : session_alerts) {
            SILK_TRACE << "Current alert message: " << alert->message() << " what: " << alert->what();

            // When we receive the added alert, keep track of the torrent
            if (const auto at = lt::alert_cast<lt::add_torrent_alert>(alert)) {
                torrent_handles.insert(at->handle);
                SILK_INFO << "Torrent: " << at->torrent_name() << " added";
            }

            if (const auto alt = lt::alert_cast<lt::file_completed_alert>(alert)) {
                const auto& status = alt->handle.status();
                SILK_INFO << "Torrent: " << alt->torrent_name() << " download_rate: " << (status.download_rate / 1000)
                          << " kB/s download_payload_rate: " << (status.download_payload_rate / 1000)
                          << " kB/s completed in " << (status.completed_time - status.added_time) << " sec";
                torrent_handles.erase(alt->handle);
                if (torrent_handles.empty()) stop_token_ = true;
            }

            // When we receive the finished alert or an error, we're done
            if (lt::alert_cast<lt::torrent_finished_alert>(alert)) {
                for (const auto& torrent_handle : torrent_handles) {
                    torrent_handle.save_resume_data(lt::torrent_handle::save_info_dict);
                }
                done = true;
            }
            if (lt::alert_cast<lt::torrent_error_alert>(alert)) {
                SILK_ERROR << "Torrent error alert: " << alert->message();
                for (const auto& torrent_handle : torrent_handles) {
                    torrent_handle.save_resume_data(lt::torrent_handle::save_info_dict);
                }
                done = true;
            }

            // When resume data is ready, save it
            if (auto rd = lt::alert_cast<lt::save_resume_data_alert>(alert)) {
                const auto resume_params_data{lt::write_resume_data_buf(rd->params)};
                BitTorrentClient::save_file(resume_file_prefix_ + "_" + rd->torrent_name(), resume_params_data);
                if (done) break;
            }

            if (lt::alert_cast<lt::save_resume_data_failed_alert>(alert)) {
                if (done) break;
            }

            // When we receive a state update, report stats
            if (auto st = lt::alert_cast<lt::state_update_alert>(alert)) {
                if (st->status.empty()) continue;
                for (const auto& ts : st->status) {
                    SILK_DEBUG << "[" << ts.handle.id() << "]: " << magic_enum::enum_name(ts.state) << ' ' << (ts.download_payload_rate / 1000) << " kB/s "
                               << (ts.total_done / 1000) << " kB (" << (ts.progress_ppm / 10000) << "%) downloaded (" << ts.num_peers << " peers)\x1b[K";
                }
            }

            // When we receive the performance alert, just log it
            if (const auto al = lt::alert_cast<lt::performance_alert>(alert)) {
                SILK_WARN << "Torrent: " << al->torrent_name() << " performance alert: " << al->message();
            }
        }

        std::this_thread::sleep_for(200ms);  // TODO (canepat) no magic number

        // Ask the session to post a state update alert for our torrents
        session.post_torrent_updates();

        // Save resume data every once in a while
        if (std::chrono::steady_clock::now() - last_save_resume >= std::chrono::seconds(60)) {  // TODO (canepat) no magic number
            for (const auto& torrent_handle : torrent_handles) {
                torrent_handle.save_resume_data(lt::torrent_handle::save_info_dict);
                last_save_resume = std::chrono::steady_clock::now();
            }
        }
    }
    SILK_DEBUG << "Stop request received";

    for (const auto& torrent_handle : session.get_torrents()) {
        torrent_handle.save_resume_data(lt::torrent_handle::save_info_dict);
    }
    const auto session_params_data{lt::write_session_params_buf(session_params_)};
    BitTorrentClient::save_file(session_file_path_, session_params_data);
    SILK_DEBUG << "Torrents saved after stop request received";

    SILK_TRACE << "BitTorrentClient::run end";
}

}  // namespace silkworm
