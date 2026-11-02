#pragma once

#include <optional>
#include <string>

#include "phi/adapter/net/tdp.h"
#include "phi/adapter/v1/discovery.h"
#include "phi/adapter/v1/schema.h"

namespace phicore::deco::ipc {

inline constexpr const char kPluginType[] = "deco";
inline constexpr const char kMetaPollIntervalS[] = "pollIntervalS";
inline constexpr int kDefaultPollIntervalS = 60;
/// Below this the app would hardly ever get a turn at the one admin session.
inline constexpr int kMinPollIntervalS = 30;

phicore::adapter::v1::Utf8String displayName();
phicore::adapter::v1::Utf8String description();
phicore::adapter::v1::Utf8String iconSvg();
phicore::adapter::v1::AdapterCapabilities capabilities();
phicore::adapter::v1::AdapterConfigSchema configSchema();

/// The candidate for a TDP answer: only the main Deco ("master" of a
/// HOMEWIFISYSTEM) of a mesh, at the datagram's sender, port 443. Nullopt for
/// every other answer.
std::optional<phicore::adapter::v1::DiscoveryCandidate> decoCandidateFor(const phicore::adapter::net::TdpAnswer &answer,
                                                                          const std::string &fromIp);

} // namespace phicore::deco::ipc
