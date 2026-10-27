#pragma once

#include <memory>

#include "phi/adapter/sdk/sidecar.h"

namespace phicore::deco::ipc {

std::unique_ptr<phicore::adapter::sdk::AdapterInstance> makeInstance();

} // namespace phicore::deco::ipc
