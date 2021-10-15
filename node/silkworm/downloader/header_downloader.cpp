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
#include "header_downloader.hpp"

#include <chrono>
#include <thread>

#include <silkworm/common/log.hpp>

#include "internals/header_retrieval.hpp"
#include "messages/InboundGetBlockHeaders.hpp"
#include "messages/InternalMessage.hpp"
#include "messages/OutboundGetBlockHeaders.hpp"
#include "messages/OutboundNewBlockHashes.hpp"
#include "rpc/ReceiveMessages.hpp"
#include "rpc/SetStatus.hpp"

// todo: implement sentry ready check before usage & sentry reconnect semantics

namespace silkworm {

HeaderDownloader::HeaderDownloader(SentryClient& sentry, Db::ReadWriteAccess db_access, ChainIdentity chain_identity)
    : chain_identity_(std::move(chain_identity)), db_access_{db_access}, sentry_{sentry} {
    auto tx = db_access_.start_ro_tx();
    working_chain_.recover_initial_state(tx);
    // working_chain_.set_preverified_hashes(...); // todo: activate
}

HeaderDownloader::~HeaderDownloader() {
    stop();
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
        sentry_.stop();
        throw HeaderDownloaderException("HeaderDownloader exception, cause: sentry do not support eth/66 protocol");
    }
}

void HeaderDownloader::receive_messages() {
    // todo: handle connection loss and retry (at each re-connect re-send status)

    // send status to sentry
    send_status();

    // send a message subscription
    rpc::ReceiveMessages message_subscription(rpc::ReceiveMessages::Scope::BlockAnnouncements);
    sentry_.exec_remotely(message_subscription);

    // receive messages
    while (!is_stopping() && !sentry_.is_stopping() && message_subscription.receive_one_reply()) {
        auto message = InboundBlockAnnouncementMessage::make(message_subscription.reply(), working_chain_, sentry_);

        messages_.push(message);
    }

    SILKWORM_LOG(LogLevel::Warn) << "HeaderDownloader execution_loop is_stopping...\n";
}

void HeaderDownloader::execution_loop() {
    using namespace std::chrono_literals;

    while (!is_stopping() && !sentry_.is_stopping()) {
        // pop a message from the queue
        std::shared_ptr<Message> message;
        bool present = messages_.timed_wait_and_pop(message, 1000ms);
        if (!present) continue;  // timeout, needed to check exiting_

        SILKWORM_LOG(LogLevel::Trace) << "HeaderDownloader processing message " << message->name() << "\n";

        // process the message (command pattern)
        message->execute();
    }
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

auto HeaderDownloader::forward(bool first_sync) -> Stage::Result {
    using std::shared_ptr;
    using namespace std::chrono_literals;

    Stage::Result result;
    bool new_height_reached = false;
    std::thread message_receiving;

    SILKWORM_LOG(LogLevel::Info) << "HeaderDownloader forward operation started\n";

    try {
        Db::ReadWriteAccess::Tx tx = db_access_.start_tx();  // this will start a new tx only if db_access has not
                                                             // an active tx
        PersistedChain persisted_chain_(tx);

        if (persisted_chain_.unwind_detected()) {
            result.status = Stage::Result::Done;
            return result;
        }

        // sync status
        auto sync_command = sync_working_chain(persisted_chain_.initial_height());
        sync_command->result().get();  // blocking

        // message processing
        time_point_t last_request;
        while (!new_height_reached && !sentry_.is_stopping()) {
            // at every minute...
            if (std::chrono::system_clock::now() - last_request > 60s) {
                last_request = std::chrono::system_clock::now();

                // make some outbound header requests
                send_header_requests();

                // check if it needs to persist some headers
                auto command = withdraw_stable_headers();
                auto [stable_headers, in_sync] = command->result().get();  // blocking
                persisted_chain_.persist(stable_headers);

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
                SILKWORM_LOG(LogLevel::Debug)
                    << "HeaderDownloader status: current persisted height=" << persisted_chain_.highest_height()
                    << "\n";
            } else
                std::this_thread::sleep_for(1s);

            SILKWORM_LOG(LogLevel::Debug) << "WorkingChain status: " << working_chain_.human_readable_status() << "\n";
        }

        result.status = Stage::Result::Done;

        // see HeadersForward
        if (persisted_chain_.unwind()) {
            result.status = Result::UnwindNeeded;
            result.unwind_point = persisted_chain_.unwind_point();
        }

        persisted_chain_.close();

        tx.commit();  // this will commit if the tx was started here

        SILKWORM_LOG(LogLevel::Info) << "HeaderDownloader forward operation completed\n";
    } catch (const std::exception& e) {
        SILKWORM_LOG(LogLevel::Error) << "HeaderDownloader forward operation is stopping due to an exception: "
                                      << e.what() << "\n";
        // tx rollback executed automatically if needed
        result.status = Stage::Result::Error;
    }

    stop();  // todo: it is better to try to cancel the grpc call, do a message_subscription.try_cancel() or both
    message_receiving.join();

    SILKWORM_LOG(LogLevel::Debug) << "HeaderDownloader forward operation clean exit\n";
    return result;
}

/*
func HeadersUnwind(u *UnwindState, s *StageState, tx ethdb.RwTx, cfg HeadersCfg) error {
	var err error
	useExternalTx := tx != nil
	if !useExternalTx {
		tx, err = cfg.db.BeginRw(context.Background())
		if err != nil {
			return err
		}
		defer tx.Rollback()
	}
	// Delete canonical hashes that are being unwound
	var headerProgress uint64
	headerProgress, err = stages.GetStageProgress(tx, stages.Headers)
	if err != nil {
		return err
	}
	badBlock := u.BadBlock != (common.Hash{})
	for blockHeight := headerProgress; blockHeight > u.UnwindPoint; blockHeight-- {
		if badBlock {
			var hash common.Hash
			if hash, err = rawdb.ReadCanonicalHash(tx, blockHeight); err != nil {
				return err
			}
			cfg.hd.ReportBadHeader(hash)
		}
		if err = rawdb.DeleteCanonicalHash(tx, blockHeight); err != nil {
			return err
		}
	}
	if u.BadBlock != (common.Hash{}) {
		cfg.hd.ReportBadHeader(u.BadBlock)
		// Find header with biggest TD
		tdCursor, cErr := tx.Cursor(dbutils.HeaderTDBucket)
		if cErr != nil {
			return cErr
		}
		defer tdCursor.Close()
		var k, v []byte
		k, v, err = tdCursor.Last()
		if err != nil {
			return err
		}
		var maxTd big.Int
		var maxHash common.Hash
		var maxNum uint64 = 0
		for ; err == nil && k != nil; k, v, err = tdCursor.Prev() {
			if len(k) != 40 {
				return fmt.Errorf("key in TD table has to be 40 bytes long: %x", k)
			}
			var hash common.Hash
			copy(hash[:], k[8:])
			if cfg.hd.IsBadHeader(hash) {
				continue
			}
			var td big.Int
			if err = rlp.DecodeBytes(v, &td); err != nil {
				return err
			}
			if td.Cmp(&maxTd) > 0 {
				maxTd.Set(&td)
				copy(maxHash[:], k[8:])
				maxNum = binary.BigEndian.Uint64(k[:8])
			}
		}
		if err != nil {
			return err
		}
		if maxNum == 0 {
			// Read genesis hash
			if maxHash, err = rawdb.ReadCanonicalHash(tx, 0); err != nil {
				return err
			}
		}
		if err = rawdb.WriteHeadHeaderHash(tx, maxHash); err != nil {
			return err
		}
		if err = s.DoneAndUpdate(tx, maxNum); err != nil {
			return err
		}
	} else if err = u.Skip(tx); err != nil {
		return err
	}
	if !useExternalTx {
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}
*/
auto HeaderDownloader::unwind_to(BlockNum new_height, Hash bad_block) -> Stage::Result {
    Stage::Result result;

    SILKWORM_LOG(LogLevel::Info) << "HeaderDownloader unwind operation started\n";

    try {
        Db::ReadWriteAccess::Tx tx = db_access_.start_tx();

        auto bad_headers = PersistedChain::remove_headers(new_height, bad_block, tx);

        update_bad_headers(std::move(bad_headers));  // update working_chain bad headers list todo: activate

        tx.commit();

        SILKWORM_LOG(LogLevel::Info) << "HeaderDownloader unwind operation completed\n";
    } catch (const std::exception& e) {
        SILKWORM_LOG(LogLevel::Error) << "HeaderDownloader unwind operation is stopping due to an exception: "
                                      << e.what() << "\n";
        // tx rollback executed automatically if needed
        result.status = Stage::Result::Error;
    }

    // todo: to implement

    return result;
}

// Request new headers from peers
void HeaderDownloader::send_header_requests() {
    // if (!sentry_.ready()) return;

    auto message = std::make_shared<OutboundGetBlockHeaders>(working_chain_, sentry_);
    messages_.push(message);
}

// New block hash announcements propagation
void HeaderDownloader::send_announcements() {
    // if (!sentry_.ready()) return;

    auto message = std::make_shared<OutboundNewBlockHashes>(working_chain_, sentry_);
    messages_.push(message);
}

auto HeaderDownloader::sync_working_chain(BlockNum highest_in_db) -> std::shared_ptr<InternalMessage<void>> {
    auto message = std::make_shared<InternalMessage<void>>(
        working_chain_, [highest_in_db](WorkingChain& wc) { wc.sync_current_state(highest_in_db); });

    messages_.push(message);

    return message;
}

auto HeaderDownloader::withdraw_stable_headers() -> std::shared_ptr<InternalMessage<std::tuple<Headers, bool>>> {
    using result_t = std::tuple<Headers, bool>;

    auto message = std::make_shared<InternalMessage<result_t>>(working_chain_, [](WorkingChain& wc) {
        Headers headers = wc.withdraw_stable_headers();
        bool in_sync = wc.in_sync();
        return result_t{std::move(headers), in_sync};
    });

    messages_.push(message);

    return message;
}

auto HeaderDownloader::update_bad_headers(std::set<Hash> bad_headers) -> std::shared_ptr<InternalMessage<void>> {
    auto message = std::make_shared<InternalMessage<void>>(
        working_chain_, [bads = std::move(bad_headers)](WorkingChain& wc) { wc.add_bad_headers(bads); });

    messages_.push(message);

    return message;
}

}  // namespace silkworm
