// Process entry point for the TP-Link Deco sidecar: the factory and the SDK's
// main loop. The mesh runtime lives in deco_instance, the web API in
// deco_session and deco_crypto.

#include <cstdio>
#include <cstdlib>
#include <memory>
#include <optional>
#include <string>
#include <unistd.h>

#include "phi/adapter/sdk/loop_execution_backend.h"
#include "phi/adapter/sdk/sidecar.h"
#include "phi/runtime/loop.h"

#include "deco_cert.h"
#include "deco_instance.h"
#include "deco_json.h"
#include "deco_model.h"
#include "deco_schema.h"
#include "deco_session.h"

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

    /// "Test connection": the address and the password from the form, one
    /// round - login, the nodes, logout.
    void onFactoryActionInvoke(const sdk::AdapterActionInvokeRequest &request) override
    {
        if (request.actionId() != "probe") {
            answer(request.cmdId(), v1::CmdStatus::NotSupported, "Factory action not supported");
            return;
        }
        const Json form = parseObject(request.paramsJson());
        const Json candidate = jsonValue(form, "factoryAdapter");
        const Json meta = jsonValue(candidate, "meta");
        // The form wins as a whole: a typed address beats a discovered one.
        const auto pick = [&](std::initializer_list<const char *> keys) {
            for (const Json *source : {&form, &candidate, &meta})
                for (const char *key : keys) {
                    const std::string value = jsonString(*source, key);
                    if (!value.empty())
                        return value;
                }
            return std::string();
        };
        const std::string host = pick({"ip", "host"});
        const std::string password = pick({"password"});
        if (host.empty() || password.empty()) {
            answer(request.cmdId(), v1::CmdStatus::InvalidArgument, "The main Deco's address and the password are needed");
            return;
        }
        phi::runtime::Loop *loop = phi::runtime::Loop::current();
        if (!loop) {
            answer(request.cmdId(), v1::CmdStatus::Failure, "No loop on the factory thread");
            return;
        }
        if (m_session && m_session->busy()) {
            answer(request.cmdId(), v1::CmdStatus::Failure, "A test is already running");
            return;
        }
        std::string error;
        const std::optional<std::string> pem = fetchPeerCertificatePem(host, 443, std::chrono::seconds(5), &error);
        if (!pem) {
            answer(request.cmdId(), v1::CmdStatus::Failure, "No HTTPS answer from " + host + ": " + error);
            return;
        }
        // The certificate only for this test; the instance pins its own.
        char path[] = "/tmp/phi-deco-probe-XXXXXX";
        const int fd = ::mkstemp(path);
        if (fd < 0 || ::write(fd, pem->data(), pem->size()) != static_cast<ssize_t>(pem->size())) {
            if (fd >= 0) {
                ::close(fd);
                ::unlink(path);
            }
            answer(request.cmdId(), v1::CmdStatus::Failure, "The certificate could not be kept for the test");
            return;
        }
        ::close(fd);
        m_probeCert = path;
        if (!m_session)
            m_session.emplace(*loop);
        m_session->setEndpoint(host, m_probeCert);
        m_session->setPassword(password);

        auto nodes = std::make_shared<std::vector<DecoNode>>();
        std::vector<DecoSession::Step> steps;
        steps.push_back({"admin/device", "device_list", Json{{"operation", "read"}},
                         [nodes](const Json &reply, std::vector<DecoSession::Step> &) { *nodes = parseDeviceList(reply); }});
        const v1::CmdId cmdId = request.cmdId();
        m_session->run(std::move(steps), [this, cmdId, nodes, host](DecoSession::Result result) {
            ::unlink(m_probeCert.c_str());
            m_probeCert.clear();
            if (result.outcome == DecoSession::Outcome::LoginRejected) {
                answer(cmdId, v1::CmdStatus::Failure, "The Deco refused the password");
                return;
            }
            if (result.outcome != DecoSession::Outcome::Ok) {
                answer(cmdId, v1::CmdStatus::Failure, std::string("Deco: ") + outcomeName(result.outcome) + " - " + result.error);
                return;
            }
            const DecoNode *master = nullptr;
            for (const DecoNode &node : *nodes)
                if (node.role == "master")
                    master = &node;
            if (!master) {
                answer(cmdId, v1::CmdStatus::Failure, host + " is no main Deco (log in worked, but it lists no master)");
                return;
            }
            const std::string text = "Deco " + master->model + " (" + (master->name.empty() ? host : master->name)
                + "), " + std::to_string(nodes->size()) + (nodes->size() == 1 ? " node" : " nodes");
            auto response = v1::ActionResponse::success(cmdId);
            response.setResult(text, v1::ActionResultType::String);
            send(std::move(response));
        });
    }

    void onFactoryStopping() override
    {
        if (m_session)
            m_session->cancel();
        m_session.reset();
        if (!m_probeCert.empty())
            ::unlink(m_probeCert.c_str());
    }

private:
    void answer(v1::CmdId cmdId, v1::CmdStatus status, const std::string &error)
    {
        send(v1::ActionResponse().setId(cmdId).setStatus(status).setError(error));
    }

    void send(v1::ActionResponse response)
    {
        v1::Utf8String error;
        if (!sendResult(response, &error))
            log(sdk::LogLevel::Error, sdk::LogCategory::Internal, "failed to send the factory result: %1", {error});
    }

    std::optional<DecoSession> m_session;
    std::string m_probeCert;
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
