# Block Downloader

The block downloader is the components that assumes the responsibility to download headers and bodies. 

He is always active, connects to the Sentry component, receive p2p messages and make requests when the stage-loop
give control to it.

## Architecture

The following diagram depicts the overall architecture:

![architecture](../../../docs/imgs/downloader_structure.png)

The header downloader is split in two classes:

- **HeadersStage**: it governs the header downloading process and save headers on the db using the read-write tx
  received from the stage-loop; it has forward() and unwind_to() methods
- **BlockExchange**: it receives messages (new headers, requested headers, request for headers, ...) from remote peers
  and messages from the `HeadersStage`; it processes messages (using the "command pattern") acting on `HeaderChain`

In the same manner the body downloader is divided in two classes:

- **BodiesStage**: it governs the body downloading process and save bodies on the db using the read-write tx received
  from the stage-loop; it has forward() and unwind_to() methods
- **BlockExchange**: it receives messages (new bodies, requested bodies, request for bodies, ...) from remote peers
  and messages from the `BodiesStage` and acts on `BodySequence`

Two classes have the responsibility to implement headers and body downloading algorithms: **HeaderChain** and
**BodySequence**. They are members of **BlockExchange** whose responsibility is to receive messages and process them.
Incoming messages (from remote peers) carry information to `HeaderChain` and `BodySequence` (for example: hash
announcements, headers, bodies, ...). Also outgoing messages request information to `HeaderChain` and `BodySequence` 
(for example: new header or bodies needed) and send it to remote peers. Internal messages are a way for the objects in
different thread to communicate.

Threading model:

- **stage classes** run in the same thread of the stage-loop
- **BlockExchange** runs in its own thread and uses message-passing as communication mechanism with the other threads
- **SentryClient** runs in its own thread

## Code organisation

Directories:

- downloader: contains the main classes that are exposed outside
- rpc & packets: contains the code that wraps the gRPC interface with the Sentry
  - rpc: each class embody a remote procedure call of the Sentry interface
  - packets: each class is a data packet that can be sent or received via one rpc
- messages: are divided in inbound messages and outbound messages
  - inbound msgs: modularize the code to handle incoming packets
  - outbound msgs: modularize the code that make requests generating outgoing packets
- internals: implementation classes
  - header_chain: code that implement the header downloading process 
  - body_sequence: code that implement the body downloading process
  - header_persistence: code that save headers to mdbx
  - body_persistence: code that save bodies to mdbx
  - other stuff: utilities
    


