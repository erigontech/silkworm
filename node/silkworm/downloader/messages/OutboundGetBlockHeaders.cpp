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

#include "OutboundGetBlockHeaders.hpp"

#include <sstream>

#include <silkworm/common/log.hpp>
#include <silkworm/downloader/header_downloader.hpp>
#include <silkworm/downloader/packets/RLPEth66PacketCoding.hpp>
#include <silkworm/downloader/rpc/SendMessageByMinBlock.hpp>
#include <silkworm/downloader/rpc/PenalizePeer.hpp>

namespace silkworm {

OutboundGetBlockHeaders::OutboundGetBlockHeaders(WorkingChain& wc, SentryClient& s): working_chain_(wc), sentry_(s) {}

/*
// HeadersForward progresses Headers stage in the forward direction
func HeadersForward(s *StageState, u Unwinder, ctx context.Context, tx ethdb.RwTx, cfg HeadersCfg, initialCycle bool,...) error {

        [...]

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

        [...]

	return nil
}
*/

void OutboundGetBlockHeaders::execute() {
    using namespace std::literals::chrono_literals;

    time_point_t now = std::chrono::system_clock::now();
    seconds_t timeout = 5s;
    int max_requests = 64; // limit number of requests sent per round to let some headers to be inserted into the database

    // anchor extension
    do {
        auto [packet, penalizations] = working_chain_.request_more_headers(now, timeout);

        if (packet == std::nullopt)
            break;

        auto send_outcome = send_packet(*packet, timeout);

        SILKWORM_LOG(LogLevel::Info) << "Headers request sent, received by " << send_outcome.peers_size() << " peer(s)\n";

        if (send_outcome.peers_size() == 0) {
            working_chain_.request_nack(*packet);
            break;
        }

        for (auto& penalization : penalizations) {
            send_penalization(penalization, 1s);
        }

        max_requests--;
    } while(max_requests > 0); // && packet != std::nullopt && receiving_peers != nullptr

    // anchor collection
    auto packet = working_chain_.request_skeleton();

    if (packet != std::nullopt) {
        auto send_outcome = send_packet(*packet, timeout);

        SILKWORM_LOG(LogLevel::Info) << "Headers skeleton request sent, received by " << send_outcome.peers_size() << " peer(s)\n";
    }
}

sentry::SentPeers OutboundGetBlockHeaders::send_packet(const GetBlockHeadersPacket66& packet_, seconds_t timeout) {
    //packet_ = packet;

    if (std::holds_alternative<Hash>(packet_.request.origin))
        throw std::logic_error("OutboundGetBlockHeaders expects block number not hash");    // todo: check!

    BlockNum min_block = std::get<BlockNum>(packet_.request.origin); // choose target peer
    if (!packet_.request.reverse)
        min_block += packet_.request.amount * packet_.request.skip;

    auto msg_reply = std::make_unique<sentry::OutboundMessageData>(); // create header request

    msg_reply->set_id(sentry::MessageId::GET_BLOCK_HEADERS_66);

    Bytes rlp_encoding;
    rlp::encode(rlp_encoding, packet_);
    msg_reply->set_data(rlp_encoding.data(), rlp_encoding.length()); // copy

    SILKWORM_LOG(LogLevel::Info) << "Sending message OutboundGetBlockHeaders with send_message_by_min_block, content:" << packet_ << " \n";
    rpc::SendMessageByMinBlock rpc{min_block, std::move(msg_reply)};

    rpc.timeout(timeout);

    sentry_.exec_remotely(rpc);

    sentry::SentPeers peers = rpc.reply();
    SILKWORM_LOG(LogLevel::Info) << "Received rpc result of OutboundGetBlockHeaders " << packet_ << ": " << std::to_string(peers.peers_size()) + " peer(s)\n";

    return peers;
}

void OutboundGetBlockHeaders::send_penalization(const PeerPenalization& penalization, seconds_t timeout) {
    rpc::PenalizePeer rpc{penalization.peerId, penalization.penalty};

    rpc.timeout(timeout);

    sentry_.exec_remotely(rpc);
}


}