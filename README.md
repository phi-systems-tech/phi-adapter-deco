# phi-adapter-deco

TP-Link Deco mesh for phi, over the main Deco's local web API (the one its web
UI uses): the nodes as gateway devices, the network's clients through the SDK's
`ClientTracker` (pairing style `Listing`: offered under Add device -> Network
clients), WLAN block as each client's `network_access` switch.

- One instance per mesh: the main Deco's address and the owner password of the
  Deco app (user `admin` on the wire).
- The Deco takes one admin session at a time. The adapter logs in for one round
  per poll (default 60 s, at least 30 s) and logs out again; the app may have to
  log in again meanwhile. A refused password is never retried on its own (about
  ten lock the account) - the instance waits for new settings.
- HTTPS with the node's self-signed certificate: taken on first contact with the
  address and pinned (state directory, `deco-cert.pem`); a different one later
  fails until the address changes or the file is removed.
- In AP mode a block takes the client off the WLAN; it is no internet pause.
- Probed on X55 firmware 1.11.1; protocol references amosyuen/ha-tplink-deco and
  fullo/deco-mcp (MIT).
