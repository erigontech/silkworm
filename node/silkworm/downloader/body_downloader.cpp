/*
Copyright 2021-2022 The Silkworm Authors

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

#include "body_downloader.h"

namespace silkworm {

/*
    Erigon block downloader pseudo-code
    -----------------------------------

    Data structures
    ---------------
    requests:         map offset → bodies_request
    deliveriesB:      map offset → body
    deliveriesH:      map offset → header
    requestedMap:     map hash(txes)+hash(uncles) → blockNum
    delivered:        set blockNum
    prefetchedBlocks: rlu-map hash → block
    peerMap:          map peer-id → #penalizations


    BodiesForward()
    ---------------
    1. UpdateStatusFromDb
    2. Loop
       2.1 for more times
          2.1.1 req = RequestMoreBodies()
          2.1.2 send_message_by_min_block(req)
       2.2 headers, bodies = GetDeliveries()
       2.3 for each (header, body)
          2.3.1 verify(body) [requires headers from db]
          2.3.2 write_to_db(body)
       2.4 update_progress

    RequestMoreBodies()
    -------------------
    1. headerProgress <-- db
    2. bodyProgress <-- StageState (=stage loop?)
    3. delivered = roaring64.Bitmap<blockNum>
    4. requests = map<offset -> bodies_request>
    5. newRequest = BodyRequest
    6. for blockNum = min(requested), while newRequest.len() < max, blockNum++
       6.0 index = blockNum - min(requested)
       6.1 if delivered.contains(blockNum) continue
       6.2 request_made = requests.contains(offset)
       6.3 if request_made
          6.3.1 if not timeout continue
          6.3.2 else delete request_made from requests, increment peer penalties
       6.4 header = get_from_deliveries_h_b() or get_from_cache() or get_from_canonical_table(blockNum)
       6.5 add header to deliveries_h
       6.6 if block in cache/db
          6.6.1 add block to deliveries_b,
          6.6.2 to_request <-- false
          6.6.3 delivered.add(blockNum)
       6.7 else
          6.7.1 to_request <-- true
          6.7.2 newRequest.blockNums.append(blockNum)
          6.7.3 newRequest.hashes.append(hash)
          6.7.4 requests.add(blockNum → newRequest)
          6.7.5 requestMap.add(hash(txes)+hash(uncles) → blockNum)

    GetDeliveries()
    ---------------
    1. for body in received_bodies
       1.1 if requestedMap[hash(txes)+hash(uncles)] == false
          1.1.1 continue
       1.2 else
          1.2.1 clear requestedMap & requests[offset]
          1.2.2 deliveriesB.add(offset → body)
          1.2.3 delivered.add(blockNum)
    2. headers,bodies = lowest_contiguous_sequence(deliveriesH,deliveriesB)
    3. remove (headers,bodies) from (deliveriesH,deliveriesB)
    4. returns (headers,bodies)

 */


}