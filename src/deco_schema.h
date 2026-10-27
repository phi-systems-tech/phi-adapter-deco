#pragma once

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

} // namespace phicore::deco::ipc
