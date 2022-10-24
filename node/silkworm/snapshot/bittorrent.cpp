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

#include <ctime>
#include <fstream>
#include <utility>

#include <libtorrent/alert_types.hpp>
#include <libtorrent/magnet_uri.hpp>
#include <libtorrent/read_resume_data.hpp>
#include <libtorrent/write_resume_data.hpp>
#include <magic_enum.hpp>

#include <silkworm/common/assert.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/common/util.hpp>

namespace silkworm {

namespace fs = std::filesystem;
using namespace std::chrono_literals;

std::vector<char> BitTorrentClient::load_file(const fs::path& filename) {
    std::ifstream input_file_stream{filename, std::ios_base::binary};
    input_file_stream.unsetf(std::ios_base::skipws);
    return {std::istream_iterator<char>(input_file_stream), std::istream_iterator<char>()};
}

void BitTorrentClient::save_file(const fs::path& filename, const std::vector<char>& data) {
    SILK_DEBUG << "Save #data=" << data.size() << " in file: " << filename;
    std::ofstream output_file_stream{filename, std::ios_base::binary};
    output_file_stream.unsetf(std::ios_base::skipws);
    output_file_stream.write(data.data(), static_cast<std::streamsize>(data.size()));
}

BitTorrentClient::BitTorrentClient(BitTorrentSettings settings)
    : settings_(std::move(settings)),
      session_file_{fs::path(settings_.repository_path) / fs::path(kSessionFileName)},
      resume_dir_{fs::path(settings_.repository_path) / fs::path(kResumeDirName)},
      session_{load_or_create_session_parameters()} {
    SILK_TRACE << "BitTorrentClient::BitTorrentClient start";
    auto add_magnet_params_sequence = resume_or_create_magnets();
    for (auto& add_magnet_params : add_magnet_params_sequence) {
        session_.async_add_torrent(std::move(add_magnet_params));
    }
    last_save_resume_ = std::chrono::steady_clock::now();
    SILK_DEBUG << "Torrents #total: " << add_magnet_params_sequence.size();
}

BitTorrentClient::~BitTorrentClient() {
    stop();
}

void BitTorrentClient::stop() {
    SILK_TRACE << "BitTorrentClient::stop start";
    stop_token_ = true;
    SILK_TRACE << "BitTorrentClient::stop end";
}

lt::session_params BitTorrentClient::load_or_create_session_parameters() const {
    // Restore session parameters from old session, if any
    const auto prev_session_data = BitTorrentClient::load_file(session_file_);
    auto session_params =
        prev_session_data.empty() ? lt::session_params{} : lt::read_session_params(prev_session_data);

    // Customize the session settings
    auto& settings = session_params.settings;
    settings.set_int(lt::settings_pack::alert_mask,
                     lt::alert_category::error | lt::alert_category::storage |
                         lt::alert_category::status | lt::alert_category::performance_warning);
    settings.set_int(lt::settings_pack::download_rate_limit, settings_.download_rate_limit);
    settings.set_int(lt::settings_pack::upload_rate_limit, settings_.upload_rate_limit);
    settings.set_int(lt::settings_pack::active_downloads, settings_.active_downloads);
    settings.set_int(lt::settings_pack::max_out_request_queue, settings_.max_out_request_queue);
    settings.set_int(lt::settings_pack::aio_threads, settings_.aio_threads);
    settings.set_bool(lt::settings_pack::announce_to_all_tiers, settings_.announce_to_all_tiers);

    return session_params;
}

std::vector<lt::add_torrent_params> BitTorrentClient::resume_or_create_magnets() const {
    fs::create_directories(settings_.repository_path);
    SILKWORM_ASSERT(fs::exists(settings_.repository_path) && fs::is_directory(settings_.repository_path));
    SILK_DEBUG << "Torrent repository folder: " << settings_.repository_path;

    fs::create_directories(resume_dir_);
    SILKWORM_ASSERT(fs::exists(resume_dir_) && fs::is_directory(resume_dir_));
    SILK_DEBUG << "Resume folder: " << resume_dir_;

    // Load the resulting resume files and re-create magnet parameters
    std::vector<lt::add_torrent_params> add_magnet_params;
    for (const auto& file : fs::directory_iterator{resume_dir_}) {
        if (!fs::is_regular_file(file.path()) || file.path().extension() != kResumeFileExt) {
            continue;
        }
        SILK_DEBUG << "File path: " << file.path() << " name: " << file.path().filename();
        const auto resume_data = load_file(file.path().string());
        if (!resume_data.empty()) {
            auto add_magnet = lt::read_resume_data(resume_data);
            add_magnet.save_path = settings_.repository_path;
            add_magnet_params.push_back(add_magnet);
        }
    }
    SILK_DEBUG << "Torrents #resumed: " << add_magnet_params.size();

    // Add magnet parameters for other magnet links
    std::ifstream magnet_input_file_stream{settings_.magnets_file_path};
    std::string magnet_uri;
    while (std::getline(magnet_input_file_stream, magnet_uri)) {
        if (magnet_uri.empty()) continue;
        SILK_DEBUG << "Magnet URI from file: " << magnet_uri;
        lt::add_torrent_params add_magnet = lt::parse_magnet_uri(magnet_uri);
        if (exists_resume_file(add_magnet.info_hashes)) {
            SILK_DEBUG << "Resume file found: " << resume_file_path(add_magnet.info_hashes);
            continue;
        }
        add_magnet.save_path = settings_.repository_path;
        add_magnet_params.push_back(add_magnet);
    }

    return add_magnet_params;
}

fs::path BitTorrentClient::resume_file_path(const lt::info_hash_t& info_hashes) const {
    const lt::sha1_hash torrent_best_hash{info_hashes.get_best()};
    auto resume_file_name = to_hex({reinterpret_cast<const uint8_t*>(torrent_best_hash.data()), lt::sha1_hash::size()});
    resume_file_name.append(kResumeFileExt);
    SILK_DEBUG << "Resume file name: " << resume_file_name;
    return resume_dir_ / resume_file_name;
}

bool BitTorrentClient::exists_resume_file(const lt::info_hash_t& info_hashes) const {
    return std::filesystem::exists(resume_file_path(info_hashes));
}

void BitTorrentClient::execute_loop() {
    SILK_TRACE << "BitTorrentClient::execute_loop start";

    while (!stop_token_ && (settings_.seeding || !session_.get_torrents().empty())) {
        request_torrent_updates();
        process_alerts();

        std::this_thread::sleep_for(settings_.wait_between_alert_polls);
    }
    SILK_DEBUG << "Execution loop completed [stop_token=" << stop_token_ << "]";

    request_save_resume_data(lt::torrent_handle::save_info_dict);
    while (outstanding_resume_requests_ > 0) {
        const auto* alert = session_.wait_for_alert(settings_.wait_between_alert_polls);
        if (alert == nullptr) continue;
        process_alerts();
    }
    SILK_DEBUG << "Resume data saved after execution loop completion";

    const auto session_params_data{lt::write_session_params_buf(session_.session_state())};
    BitTorrentClient::save_file(session_file_, session_params_data);
    SILK_DEBUG << "Session saved after execution loop completion";

    SILK_TRACE << "BitTorrentClient::execute_loop end";
}

void BitTorrentClient::request_torrent_updates() {
    SILK_TRACE << "BitTorrentClient::request_torrent_updates start";
    // Ask the session to post update alerts for our torrents
    session_.post_torrent_updates();

    // Save resume data every once in a while
    if (std::chrono::steady_clock::now() - last_save_resume_ >= settings_.resume_data_save_interval) {
        request_save_resume_data(lt::torrent_handle::save_info_dict);
        last_save_resume_ = std::chrono::steady_clock::now();
    }
    SILK_TRACE << "BitTorrentClient::request_torrent_updates end";
}

void BitTorrentClient::request_save_resume_data(lt::resume_data_flags_t flags) {
    SILK_TRACE << "BitTorrentClient::request_save_resume_data start";
    const auto if_need_save_resume = [](auto& ts) { return ts.need_save_resume; };
    for (const auto& torrent_status : session_.get_torrent_status(if_need_save_resume)) {
        torrent_status.handle.save_resume_data(flags);
        ++outstanding_resume_requests_;
        SILK_DEBUG << "Save resume data requested for: " << torrent_status.name;
    }
    SILK_TRACE << "BitTorrentClient::request_save_resume_data end";
}

void BitTorrentClient::process_alerts() {
    std::vector<lt::alert*> session_alerts;
    session_.pop_alerts(&session_alerts);
    SILK_DEBUG << "Session raised #alerts: " << session_alerts.size();

    for (const auto* alert : session_alerts) {
        handle_alert(alert);
    }
}

bool BitTorrentClient::handle_alert(const lt::alert* alert) {
    bool handled{false};
    if (const auto ata = lt::alert_cast<lt::add_torrent_alert>(alert)) {
        if (ata->error) {
            SILK_ERROR << "Failed to add torrent: " << (ata->params.ti ? ata->params.ti->name() : ata->params.name)
                       << " message: " << ata->error.message();
        } else {
            SILK_INFO << "Torrent: " << ata->torrent_name() << " added";
            ata->handle.save_resume_data(lt::torrent_handle::save_info_dict | lt::torrent_handle::only_if_modified);
            ++outstanding_resume_requests_;
        }
        handled = true;
    }

    // When we receive the finished alert, we request to save resume data for the torrent
    if (const auto* tfa = lt::alert_cast<lt::torrent_finished_alert>(alert)) {
        const auto& status = tfa->handle.status();
        SILK_INFO << "Torrent: " << tfa->torrent_name() << " finished download_rate: " << (status.download_rate / 1000) << " kB/s"
                  << " download_payload_rate: " << (status.download_payload_rate / 1000) << " kB/s"
                  << " in " << (status.completed_time - status.added_time) << " sec at "
                  << std::put_time(std::gmtime(&status.completed_time), "%c %Z");

        // TODO(canepat) check if improves download speed
        tfa->handle.set_max_connections(tfa->handle.max_connections() / 2);
        tfa->handle.save_resume_data(lt::torrent_handle::save_info_dict);

        handled = true;
    }

    if (const auto* mra = alert_cast<lt::metadata_received_alert>(alert)) {
        SILK_DEBUG << "Torrent: " << mra->torrent_name() << " metadata received";
        mra->handle.save_resume_data(lt::torrent_handle::save_info_dict);
        ++outstanding_resume_requests_;
        handled = true;
    }

    // When resume data is ready, we save it to disk
    if (const auto* rda = lt::alert_cast<lt::save_resume_data_alert>(alert)) {
        const auto resume_params_data{lt::write_resume_data_buf(rda->params)};
        BitTorrentClient::save_file(resume_file_path(rda->params.info_hashes), resume_params_data);
        SILK_DEBUG << "Torrent: " << rda->torrent_name() << " resume data saved";
        --outstanding_resume_requests_;
        handled = true;
    }

    if (const auto fa = lt::alert_cast<lt::save_resume_data_failed_alert>(alert)) {
        SILK_DEBUG << "Torrent: " << fa->torrent_name() << " save resume data failed ["
                   << (fa->error == lt::errors::resume_data_not_modified ? "not modified" : ("error=" + fa->error.to_string()))
                   << "]";
        --outstanding_resume_requests_;
        handled = true;
    }

    // When we receive a state update, report stats
    if (const auto sta = lt::alert_cast<lt::state_update_alert>(alert)) {
        if (!sta->status.empty()) {
            for (const auto& ts : sta->status) {
                SILK_DEBUG << "[" << std::to_string(ts.handle.id()) << "]: " << magic_enum::enum_name(ts.state) << ' '
                           << (ts.download_payload_rate / 1'000'000) << " MB/s " << (ts.total_done / 1'000'000) << " MB ("
                           << (ts.progress_ppm / 10000) << "%) downloaded (" << ts.num_peers << " peers)\x1b[K";
            }
        }
        handled = true;
    }

    // When we receive any performance alert, put it out as warning
    if (const auto pa = lt::alert_cast<lt::performance_alert>(alert)) {
        SILK_WARN << alert->message() << " [warning_code=" << pa->warning_code << "]";
        handled = true;
    }

    // Finally, if an alert has not been unhandled yet, just log it for debug purposes
    if (!handled) {
        SILK_DEBUG << alert->message();
    }

    return false;
}

}  // namespace silkworm
