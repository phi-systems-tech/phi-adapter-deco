#pragma once

// The Deco's certificate, pinned.
//
// Every node serves its web UI over HTTPS with a self-signed certificate of
// its own (CN tplinkdeco.net, CA:FALSE), and port 80 only redirects there. The
// SDK's client always checks the chain, so the master's certificate is taken
// once - trust on first use - and handed to it as the only CA, with the name
// check off. A different certificate later fails the handshake: a new master,
// a reset, or somebody in between, and in each case the household decides.

#include <chrono>
#include <optional>
#include <string>

namespace phicore::deco::ipc {

/// The peer certificate of host:port as PEM, without checking it; nothing
/// with `error` set when no TLS handshake came about within `timeout`.
/// Blocking - called once per new address, on the instance's own thread.
std::optional<std::string> fetchPeerCertificatePem(const std::string &host, int port,
                                                   std::chrono::milliseconds timeout,
                                                   std::string *error);

/// SHA-256 of the certificate in the PEM, hex with colons; empty when it does
/// not parse. For the log line that says which certificate was trusted.
std::string certificateFingerprint(const std::string &pem);

} // namespace phicore::deco::ipc
