# Sync
Sync component is responsible for chain synchronization. 
To carry on this task it asks blocks from peers, save blocks to Execution database, detects forks, asks Execution for 
chain verifications, applies consensus rules and takes decision on forks.

There are actually two distinct implementations of Sync: 
- **PoWSync**: implement the block synchronization logic of a PoW chain; it executes cycles of block downloading & block validation
- **PoSSync**: implement the Execution Interface of the Ethereum PoS chain and needs an external Consensus Client

Other components of Sync are:
- **BlockExchange**: responsible for downloading blocks from the network
- **SentryClient**: responsible for connecting to the Sentry component  

## Sync-Execution interaction
The following diagram depicts the overall architecture of the
![architecture](../../docs/imgs/sync_execution_structure.png)

Sync and Execution are two independent components structured in a client-server architecture as per Torax architecture.
The Sync component is the client and the Execution component is the server. They can be instantiated in process or 
out of process using a gRPC interface.

| component | far from the chain tip                                                                                                                                                                                                                                   | near the chain tip                                                                                                                                                                                                                                                                                                                                       | far vs near detection | 
|-----------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| -------- |
| **Sync**  | - detect chain tip using newPayload/FCU, <br> - download blocks and insert them to the EL while they are arriving                                                                                                                                        | - at newPayload: <br> a) if  the block  has its parent on the EL: <br> - send the block to the EL <br> - trigger a EL's VerifyChain <br> b) if parent block is missing on the EL <br> - start a downloading of the missing parents; <br><br> - at FCU: send FCU to EL                                                                                    | The  first VerifyChain triggers the state change from "far from the tip" to "near the tip" |
| **Exec**  | - InsertBlock inserts blocks on the "default" fork that is the db <br> - manage collisions (ommers) using the non-canonical-txes mapping <br> - the body stage "fix" blocks with collisions putting canonical ones to the canonical transactions mapping | - the first VerifyChain start the overlay mechanism to do fork tracking <br> - at each InsertBlock, after the first VerifyChain, add the block to the fork which it belongs, if not present it creates the fork <br> - VerifyChains are executed in parallel on each fork <br> - each FCU determines which fork must survive and must be copied to the db | The  first VerifyChain triggers the state change from "far from the tip" to "near the tip" |


## BlockExchange

The BlockExchange is the component that has the responsibility to download block headers and block bodies. 

It is always active and performs some operations on its own (e.g. replying to received devp2p messages, downloading
more headers or bodies up to a target, ...); it is driven by the Sync component that sends it messages to start/stop
the downloading process or to set downloading targets.

Two classes have the responsibility to implement header and body download algorithms: **HeaderChain** and
**BodySequence**. 

Communication among such objects is carried by message-passing techniques. Three types of messages are present:
- incoming messages from remote peers (for example: hash announcements, headers, bodies, ...) are routed to `HeaderChain` and `BodySequence`
- outgoing messages to remote peers (for example: new header or bodies needed) contain information from `HeaderChain` and `BodySequence`
- internal messages are a design choice to share information between objects in different threads

When the BlockExchange is asked to download blocks up to a target, it instructs the HeaderChain to download headers;
when headers are ready they are transferred to BodySequence that carry on the task to download corresponding bodies.
Then, the ready blocks are put on the thread-safe queue `BlockQueue` that is read by the Sync component.
    


