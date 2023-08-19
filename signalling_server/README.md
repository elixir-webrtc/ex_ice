# SignallingServer

Simple signalling server for connecting two ICE peers.

It creates a single room where only two peers can join. 
Every message sent by one peer will be forwarded to the other peer.


1. Connect as 

```js
sock  = new WebSocket("ws://localhost:4000/websocket")
```

2. When the other peer connects, the signalling server sends simple info JSON:

```json
{
  "type": "peer_joined", 
  "role": "controlled"
}
```

The `role` field is a role a peer that received info JSON should use to avoid role conflict.

3. Send any message via WS, it will be forwarded to the other side.