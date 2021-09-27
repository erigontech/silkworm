/*
   Copyright 2021 The Silkworm Authors

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
#include <chrono>
#include <thread>

#include <silkworm/common/log.hpp>

#include "header_downloader.hpp"
#include "messages/InboundGetBlockHeaders.hpp"
#include "messages/OutboundGetBlockHeaders.hpp"
#include "rpc/ReceiveMessages.hpp"
#include "rpc/SetStatus.hpp"
#include "internals/header_retrieval.hpp"
#include "internals/persisted_chain.hpp"

namespace silkworm {

HeaderDownloader::HeaderDownloader(SentryClient& sentry, Db::ReadWriteAccess db_access, ChainIdentity chain_identity):
    chain_identity_(std::move(chain_identity)),
    db_access_{db_access},
    sentry_{sentry}
{
    auto tx = db_access_.start_ro_tx();
    working_chain_.recover_initial_state(tx);
    //working_chain_.set_preverified_hashes(...); // todo: activate
}

HeaderDownloader::~HeaderDownloader() {
    SILKWORM_LOG(LogLevel::Error) << "HeaderDownloader destroyed\n";
}

void HeaderDownloader::send_status() {
    HeaderRetrieval headers(db_access_);
    auto [head_hash, head_td] = headers.head_hash_and_total_difficulty();

    rpc::SetStatus set_status(chain_identity_, head_hash, head_td);
    sentry_.exec_remotely(set_status);

    SILKWORM_LOG(LogLevel::Info) << "HeaderDownloader, set_status sent\n";
    sentry::SetStatusReply reply = set_status.reply();

    sentry::Protocol supported_protocol = reply.protocol();
    if (supported_protocol != sentry::Protocol::ETH66) {
        SILKWORM_LOG(LogLevel::Critical) << "HeaderDownloader: sentry do not support eth/66 protocol, is_stopping...\n";
        sentry_.need_close();
        throw HeaderDownloaderException("HeaderDownloader exception, cause: sentry do not support eth/66 protocol");
    }
}

void HeaderDownloader::receive_messages(MessageQueue& messages, std::atomic<bool>& stopping) {

    rpc::ReceiveMessages message_subscription(rpc::ReceiveMessages::Scope::BlockAnnouncements);
    sentry_.exec_remotely(message_subscription);

    while (!stopping && !sentry_.closing() && message_subscription.receive_one_reply()) {

        auto message = InboundBlockAnnouncementMessage::make(message_subscription.reply(), working_chain_, sentry_);

        messages.push(message);
    }

    SILKWORM_LOG(LogLevel::Warn) << "HeaderDownloader execution_loop is_stopping...\n";

}

void HeaderDownloader::process_one_message(MessageQueue& messages) {
    using namespace std::chrono_literals;

    // pop a message from the queue
    std::shared_ptr<Message> message;
    bool present = messages.timed_wait_and_pop(message, 1000ms);
    if (!present) return;   // timeout, needed to check exiting_

    SILKWORM_LOG(LogLevel::Trace) << "HeaderDownloader processing message " << message->name() << "\n";

    // process the message (command pattern)
    message->execute();
}

/*
// HeadersForward progresses Headers stage in the forward direction
func HeadersForward(
	s *StageState,
	u Unwinder,
	ctx context.Context,
	tx ethdb.RwTx,
	cfg HeadersCfg,
	initialCycle bool,
	test bool, // Set to true in tests, allows the stage to fail rather than wait indefinitely
) error {
	var headerProgress uint64
	var err error
	useExternalTx := tx != nil
	if !useExternalTx {
		tx, err = cfg.db.BeginRw(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback()
	}
	if err = cfg.hd.ReadProgressFromDb(tx); err != nil {
		return err
	}
	cfg.hd.SetFetching(true)
	defer cfg.hd.SetFetching(false)
	headerProgress = cfg.hd.Progress()
	logPrefix := s.LogPrefix()
	// Check if this is called straight after the unwinds, which means we need to create new canonical markings
	hash, err := rawdb.ReadCanonicalHash(tx, headerProgress)
	if err != nil {
		return err
	}
	logEvery := time.NewTicker(logInterval)
	defer logEvery.Stop()
	if hash == (common.Hash{}) {
		headHash := rawdb.ReadHeadHeaderHash(tx)
		if err = fixCanonicalChain(logPrefix, logEvery, headerProgress, headHash, tx); err != nil {
			return err
		}
		if !useExternalTx {
			if err = tx.Commit(); err != nil {
				return err
			}
		}
		s.Done()
		return nil
	}

	log.Info(fmt.Sprintf("[%s] Waiting for headers...", logPrefix), "from", headerProgress)

	localTd, err := rawdb.ReadTd(tx, hash, headerProgress)
	if err != nil {
		return err
	}
	headerInserter := headerdownload.NewHeaderInserter(logPrefix, localTd, headerProgress)
	cfg.hd.SetHeaderReader(&chainReader{config: &cfg.chainConfig, tx: tx})

	var peer []byte
	stopped := false
	prevProgress := headerProgress
	for !stopped {
		currentTime := uint64(time.Now().Unix())
		req, penalties := cfg.hd.RequestMoreHeaders(currentTime)
		if req != nil {
			peer = cfg.headerReqSend(ctx, req)
			if peer != nil {
				cfg.hd.SentRequest(req, currentTime, 5 ) // 5 = timeout
				log.Debug("Sent request", "height", req.Number)
			}
		}
		cfg.penalize(ctx, penalties)
		maxRequests := 64 // Limit number of requests sent per round to let some headers to be inserted into the database
		for req != nil && peer != nil && maxRequests > 0 {
			req, penalties = cfg.hd.RequestMoreHeaders(currentTime)
			if req != nil {
				peer = cfg.headerReqSend(ctx, req)
				if peer != nil {
					cfg.hd.SentRequest(req, currentTime, 5 ) // 5 = timeout
					log.Debug("Sent request", "height", req.Number)
				}
			}
			cfg.penalize(ctx, penalties)
			maxRequests--
		}

		// Send skeleton request if required
		req = cfg.hd.RequestSkeleton()
		if req != nil {
			peer = cfg.headerReqSend(ctx, req)
			if peer != nil {
				log.Debug("Sent skeleton request", "height", req.Number)
			}
		}
		// Load headers into the database
		var inSync bool
		if inSync, err = cfg.hd.InsertHeaders(headerInserter.FeedHeaderFunc(tx), logPrefix, logEvery.C); err != nil {
			return err
		}
		announces := cfg.hd.GrabAnnounces()
		if len(announces) > 0 {
			cfg.announceNewHashes(ctx, announces)
		}
		if headerInserter.BestHeaderChanged() { // We do not break unless there best header changed
			if !initialCycle {
				// if this is not an initial cycle, we need to react quickly when new headers are coming in
				break
			}
			// if this is initial cycle, we want to make sure we insert all known headers (inSync)
			if inSync {
				break
			}
		}
		if test {
			break
		}
		timer := time.NewTimer(1 * time.Second)
		select {
		case <-ctx.Done():
			stopped = true
		case <-logEvery.C:
			progress := cfg.hd.Progress()
			logProgressHeaders(logPrefix, prevProgress, progress)
			prevProgress = progress
		case <-timer.C:
			log.Trace("RequestQueueTime (header) ticked")
		case <-cfg.hd.DeliveryNotify:
			log.Debug("headerLoop woken up by the incoming request")
		}
		timer.Stop()
	}
	if headerInserter.Unwind() {
		if err := u.UnwindTo(headerInserter.UnwindPoint(), tx, common.Hash{}); err != nil {
			return fmt.Errorf("%s: failed to unwind to %d: %w", logPrefix, headerInserter.UnwindPoint(), err)
		}
	} else if headerInserter.GetHighest() != 0 {
		if err := fixCanonicalChain(logPrefix, logEvery, headerInserter.GetHighest(), headerInserter.GetHighestHash(), tx); err != nil {
			return fmt.Errorf("%s: failed to fix canonical chain: %w", logPrefix, err)
		}
	}
	s.Done()
	if !useExternalTx {
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	if stopped {
		return common.ErrStopped
	}
	// We do not print the followin line if the stage was interrupted
	log.Info(fmt.Sprintf("[%s] Processed", logPrefix), "highest inserted", headerInserter.GetHighest(), "age", common.PrettyAge(time.Unix(int64(headerInserter.GetHighestTimestamp()), 0)))
	stageHeadersGauge.Update(int64(cfg.hd.Progress()))
	return nil
}
*/

auto HeaderDownloader::forward(bool first_sync) -> StageResult {

    using std::shared_ptr;
    using namespace std::chrono_literals;

    bool new_height_reached = false;

    MessageQueue messages{}; // thread safe queue where receive messages from sentry thread
    std::atomic<bool> stopping{false};
    std::thread message_receiving;

    try {
        Db::ReadWriteAccess::Tx tx = db_access_.start_tx();

        PersistedChain persisted_chain_(tx);

        if (persisted_chain_.unwind_detected()) {
            return StageResult::Done;
        }

        // sync status
        //working_chain_.target_height(new_height);
        working_chain_.sync_current_state_with(persisted_chain_);

        // send status to sentry
        send_status(); // todo: avoid if already sent by BlockProvider?

        // start message receiving (headers & blocks requests)
        message_receiving = std::thread([this, &messages, &stopping]() {
            receive_messages(messages, stopping);
        });

        // message processing
        time_point_t last_request;
        while (!new_height_reached && !sentry_.closing()) {

            // process inbound messages
            process_one_message(messages);  // pop a message from the queue and process it

            // at every minute...
            if (std::chrono::system_clock::now() - last_request > 60s) {
                last_request = std::chrono::system_clock::now();

                // make some outbound header requests
                send_header_requests();

                // check if it needs to persist some headers
                bool in_sync = working_chain_.save_steady_headers(persisted_chain_);

                // do announcements
                send_announcements();

                // check if finished - todo: improve clarity
                if (first_sync) {  // first_sync_ = installation time or run time after a long break
                    // if this is the first sync, we want to make sure we insert as many headers as possible
                    new_height_reached = in_sync && persisted_chain_.best_header_changed();
                } else {
                    // if this is not the first sync, we are working at the tip of the chain,
                    // so we need to react quickly when new headers are coming in
                    new_height_reached = persisted_chain_.best_header_changed();
                }

                // todo: log progress - logProgressHeaders(logPrefix, prevProgress, progress)
                SILKWORM_LOG(LogLevel::Debug) << "HeaderDownloader status: current persisted height="
                                              << persisted_chain_.highest_height() << "\n";
            }

            SILKWORM_LOG(LogLevel::Debug) << "WorkingChain status: " << working_chain_.human_readable_status() << "\n";
        }

        // see HeadersForward
        if (persisted_chain_.unwind()) {
            signal_to_unwind_to(persisted_chain_.unwind_point());
        }
        else if (persisted_chain_.highest_bn_ != 0) {
            fix_canonical_chain(persisted_chain_.highest_height(), persisted_chain_.highest_hash(), tx);
        }

        tx.commit(); // todo: commit only if opened here
    }
    catch(const std::exception& e) {
        SILKWORM_LOG(LogLevel::Error) << "HeaderDownloader wind operation is_stopping due to exception: " << e.what() << "\n";
        // tx rollback executed automatically if needed
        return StageResult::Error;
    }

    stopping = true; // todo: it is better to try to cancel the grpc call, do a message_subscription.try_cancel() or both
    message_receiving.join();

    SILKWORM_LOG(LogLevel::Info) << "HeaderDownloader wind operation completed\n";
    return StageResult::Done;
}

auto HeaderDownloader::unwind_to([[maybe_unused]] BlockNum new_height) -> StageResult {
    // todo: to implement
    return StageResult::Done;
}

void HeaderDownloader::send_header_requests() {

    OutboundGetBlockHeaders message(working_chain_, sentry_);
    message.execute();

}

void HeaderDownloader::send_announcements() {
    // todo: complete the implementation below
    auto announces_to_do = working_chain_.announces_to_do();
    /*
    for(Announce& announce: announcesToDo_) {
        send(announce);
    }
    */
    announces_to_do.clear();
}
}  // namespace silkworm

