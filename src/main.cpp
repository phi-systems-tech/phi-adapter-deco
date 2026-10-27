// Process entry point for the TP-Link Deco sidecar: the factory and the SDK's
// main loop. The mesh runtime lives in deco_instance, the web API in
// deco_session and deco_crypto.

#include <cstdlib>
#include <memory>
#include <optional>

#include "phi/adapter/sdk/loop_execution_backend.h"
#include "phi/adapter/sdk/sidecar.h"

#include "deco_instance.h"
#include "deco_schema.h"

namespace sdk = phicore::adapter::sdk;
namespace v1 = phicore::adapter::v1;
using namespace phicore::deco::ipc;

namespace {

class DecoFactory final : public sdk::AdapterFactory
{
protected:
    std::unique_ptr<sdk::InstanceExecutionBackend> createFactoryExecutionBackend() override
    {
        return sdk::createLoopExecutionBackend("deco-factory");
    }

    // A loop of its own per mesh: the certificate is fetched blocking, once,
    // and the session needs somewhere to wait for its answers.
    std::unique_ptr<sdk::InstanceExecutionBackend> createInstanceExecutionBackend(
        const sdk::ExternalId &externalId) override
    {
        (void)externalId;
        return sdk::createLoopExecutionBackend("deco-instance");
    }

    v1::Utf8String pluginType() const override { return kPluginType; }
    v1::Utf8String displayName() const override { return phicore::deco::ipc::displayName(); }
    v1::Utf8String description() const override { return phicore::deco::ipc::description(); }
    v1::Utf8String apiVersion() const override { return v1::kProtocolLabel; }
    v1::Utf8String iconSvg() const override { return phicore::deco::ipc::iconSvg(); }
    int timeoutMs() const override { return 30000; }
    int maxInstances() const override { return 0; }

    v1::AdapterCapabilities capabilities() const override { return phicore::deco::ipc::capabilities(); }

    std::optional<v1::AdapterConfigSchema> configSchema() const override
    {
        return phicore::deco::ipc::configSchema();
    }

    std::unique_ptr<sdk::AdapterInstance> createInstance(const sdk::ExternalId &externalId) override
    {
        (void)externalId;
        return makeInstance();
    }
};

} // namespace

int main(int argc, char **argv)
{
    const char *envSocketPath = std::getenv("PHI_ADAPTER_SOCKET_PATH");
    const v1::Utf8String socketPath = argc > 1
        ? argv[1]
        : (envSocketPath ? envSocketPath : v1::Utf8String("/tmp/phi-adapter-deco-ipc.sock"));
    DecoFactory factory;
    sdk::SidecarHost host(socketPath, factory);
    return sdk::runSidecarMain(host);
}
