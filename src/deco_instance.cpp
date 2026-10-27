#include "deco_instance.h"

#include <algorithm>
#include <chrono>
#include <deque>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "phi/adapter/sdk/network_clients.h"
#include "phi/runtime/loop.h"
#include "phi/runtime/str.h"

#include "deco_cert.h"
#include "deco_json.h"
#include "deco_model.h"
#include "deco_schema.h"
#include "deco_session.h"

namespace phicore::deco::ipc {

namespace sdk = phicore::adapter::sdk;
namespace str = phi::str;
namespace v1 = phicore::adapter::v1;

namespace {

constexpr const char kCertFile[] = "deco-cert.pem";
constexpr const char kCertHostFile[] = "deco-cert.host";
constexpr const char kClientsFile[] = "clients.txt";

std::int64_t nowMs()
{
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

std::vector<std::string> macList(const Json &value)
{
    std::vector<std::string> out;
    if (!value.is_array())
        return out;
    for (const Json &entry : value) {
        const std::string mac = sdk::ClientTracker::normalizedMac(
            entry.is_string() ? entry.get<std::string>() : jsonString(entry, "value"));
        if (!mac.empty() && std::find(out.begin(), out.end(), mac) == out.end())
            out.push_back(mac);
    }
    return out;
}

class DecoInstance final : public sdk::AdapterInstance
{
protected:
    bool start() override
    {
        m_loop = phi::runtime::Loop::current();
        if (!m_loop) {
            log(sdk::LogLevel::Error, sdk::LogCategory::Lifecycle, "started off a loop; no timers are possible");
            return false;
        }
        m_session.emplace(*m_loop);
        m_tracker.setSink({
            [this](const v1::Device &device, const v1::ChannelList &channels) {
                v1::Utf8String error;
                if (!sendDeviceUpdated(device, channels, &error))
                    log(sdk::LogLevel::Error, sdk::LogCategory::Internal, "deviceUpdated(%1) failed: %2",
                        {device.externalId(), error});
            },
            [this](const std::string &device, const std::string &channel, const v1::ScalarValue &value) {
                sendChannelStateUpdated(device, channel, value, nowMs());
            },
            [this](const v1::DeviceCandidate &candidate) { sendDeviceCandidateUpdated(candidate); },
            [this](const std::string &id) { sendDeviceCandidateRemoved(id); },
            [this](const std::string &state) {
                v1::Utf8String error;
                if (!writeStateFile(kClientsFile, state, &error))
                    log(sdk::LogLevel::Warn, sdk::LogCategory::Internal, "clients not saved: %1", {error});
            },
        });
        m_tracker.restore(readStateFile(kClientsFile).value_or(std::string()));
        m_lifecycle = Lifecycle::Running;
        sendConnectionStateChanged(false);
        return true;
    }

    void stop() override
    {
        m_lifecycle = Lifecycle::Stopped;
        m_pollTimer.reset();
        failQueued("Instance stopped");
        if (m_session)
            m_session->cancel();
        m_session.reset();
        m_loop = nullptr;
    }

    void onDisconnected() override
    {
        m_lifecycle = Lifecycle::Paused;
        m_pollTimer.reset();
        failQueued("Instance disconnected");
        if (m_session)
            m_session->cancel();
        m_tracker.forgetReported();
        m_reportedNodes.clear();
        m_connected = false;
    }

    void onConfigChanged(const sdk::ConfigChangedRequest &request) override
    {
        if (m_lifecycle == Lifecycle::Stopped || !m_session)
            return;
        m_info = request.adapter();
        m_meta = parseObject(m_info.metaJson());
        m_lifecycle = Lifecycle::Running;

        sdk::ClientTracker::Settings settings;
        settings.awayDelayMs = std::int64_t{std::clamp(jsonInt(m_meta, sdk::kClientMetaAwayDelayS, 300), 0, 3600)} * 1000;
        settings.showGuests = jsonBool(m_meta, sdk::kClientMetaShowGuests);
        settings.ignorePrivateMacs = jsonBool(m_meta, sdk::kClientMetaIgnorePrivateMacs);
        // The Deco takes a block and does not enforce it in AP mode (the
        // iPad stayed online and rejoined, pi5 2026-10-27): no switch until
        // phi blocks as the router itself (ROADMAP "Cloud binding and network
        // roles").
        settings.canBlock = false;
        m_tracker.setSettings(settings);
        m_tracker.setTracked(macList(jsonValue(m_meta, sdk::kClientMetaTracked)));
        m_pollIntervalS = std::clamp(jsonInt(m_meta, kMetaPollIntervalS, kDefaultPollIntervalS), kMinPollIntervalS, 600);

        // A new password or address is a new chance for a refused login.
        const std::string host = this->host();
        if (host != m_host || m_info.password() != m_password)
            m_loginRefused = false;
        m_host = host;
        m_password = m_info.password();
        m_session->setPassword(m_password);

        if (m_host.empty() || m_password.empty()) {
            setConnected(false);
            return;
        }
        if (!pinCertificate())
            return;
        armPollTimer();
        poll();
    }

    void onPairingStart(const sdk::PairingStartRequest &request) override
    {
        // Listing: nothing opens, the clients seen are the candidates.
        m_tracker.listCandidates(std::int64_t{request.durationS()} * 1000, nowMs());
        answer(request.cmdId(), v1::CmdStatus::Success, {});
    }

    void onPairingStop(const sdk::PairingStopRequest &request) override
    {
        answer(request.cmdId(), v1::CmdStatus::Success, {});
    }

    void onPairCandidate(const sdk::PairCandidateRequest &request) override
    {
        if (!m_tracker.track(request.candidateId(), nowMs())) {
            answer(request.cmdId(), v1::CmdStatus::InvalidArgument, "This Deco has not seen that client");
            return;
        }
        answer(request.cmdId(), v1::CmdStatus::Success, {});
        saveTracked();
        sendPairingProgress(request.pairingId(), v1::PairingStage::Done, 100, {},
                            sdk::ClientTracker::normalizedMac(request.candidateId()));
    }

    void onDeviceRemoved(const sdk::DeviceRemovedRequest &request) override
    {
        if (m_tracker.untrack(request.deviceExternalId()))
            saveTracked();
        else
            m_reportedNodes.erase(request.deviceExternalId());
    }

private:
    enum class Lifecycle { Idle, Running, Paused, Stopped };

    struct Round {
        std::vector<DecoSession::Step> steps;
        std::function<void(DecoSession::Result)> done;
        bool poll = false;
    };

    std::string host() const
    {
        const std::string ip = str::trimmed(m_info.ip());
        return ip.empty() ? str::trimmed(m_info.host()) : ip;
    }

    // --- the certificate --------------------------------------------------

    /// The master's certificate, taken on the first contact with this address
    /// and kept; false when there is none and none could be had.
    bool pinCertificate()
    {
        const std::optional<std::string> pinnedFor = readStateFile(kCertHostFile);
        if (pinnedFor && str::trimmed(*pinnedFor) == m_host && readStateFile(kCertFile)) {
            m_session->setEndpoint(m_host, stateDirectory() + "/" + kCertFile);
            return true;
        }
        std::string error;
        const std::optional<std::string> pem = fetchPeerCertificatePem(m_host, 443, std::chrono::seconds(5), &error);
        if (!pem) {
            log(sdk::LogLevel::Warn, sdk::LogCategory::Network, "no certificate from %1 yet: %2",
                {v1::Utf8String(m_host), v1::Utf8String(error)});
            setConnected(false);
            // Try again with the next config or poll tick.
            armPollTimer();
            return false;
        }
        v1::Utf8String writeError;
        if (!writeStateFile(kCertFile, *pem, &writeError) || !writeStateFile(kCertHostFile, m_host, &writeError)) {
            log(sdk::LogLevel::Error, sdk::LogCategory::Internal, "certificate not kept: %1", {writeError});
            return false;
        }
        log(sdk::LogLevel::Info, sdk::LogCategory::Network, "trusting the certificate of %1 (SHA-256 %2)",
            {v1::Utf8String(m_host), v1::Utf8String(certificateFingerprint(*pem))});
        m_session->setEndpoint(m_host, stateDirectory() + "/" + kCertFile);
        return true;
    }

    // --- rounds -----------------------------------------------------------

    void armPollTimer()
    {
        if (!m_loop || m_lifecycle != Lifecycle::Running)
            return;
        m_pollTimer = m_loop->timerEvery(std::chrono::seconds(m_pollIntervalS), [this]() { poll(); });
    }

    void enqueue(std::vector<DecoSession::Step> steps, std::function<void(DecoSession::Result)> done,
                 bool isPoll = false)
    {
        m_queue.push_back({std::move(steps), std::move(done), isPoll});
        runNext();
    }

    void runNext()
    {
        if (!m_session || m_session->busy() || m_queue.empty() || m_lifecycle != Lifecycle::Running)
            return;
        Round round = std::move(m_queue.front());
        m_queue.pop_front();
        auto done = std::move(round.done);
        const bool started = m_session->run(std::move(round.steps), [this, done](DecoSession::Result result) {
            noteOutcome(result);
            if (done)
                done(result);
            runNext();
        });
        if (!started && done)
            done({DecoSession::Outcome::Unreachable, "no address"});
    }

    void failQueued(const std::string &reason)
    {
        auto queue = std::move(m_queue);
        m_queue.clear();
        for (Round &round : queue)
            if (round.done)
                round.done({DecoSession::Outcome::Unreachable, reason});
    }

    void noteOutcome(const DecoSession::Result &result)
    {
        switch (result.outcome) {
        case DecoSession::Outcome::Ok:
            setConnected(true);
            m_saidError.clear();
            return;
        case DecoSession::Outcome::LoginRejected:
            // Never again on its own: about ten of these lock the account.
            m_loginRefused = true;
            m_pollTimer.reset();
            setConnected(false);
            sendError(sdk::LogCategory::Config, "The Deco refused the password; fix it in the instance settings",
                      {}, {});
            return;
        case DecoSession::Outcome::Evicted:
            // The app logged in; the next poll tries again. Still connected.
            log(sdk::LogLevel::Debug, sdk::LogCategory::Network, "session taken over: %1", {v1::Utf8String(result.error)});
            return;
        case DecoSession::Outcome::Unreachable:
        case DecoSession::Outcome::Protocol:
            setConnected(false);
            if (result.error != m_saidError) {
                m_saidError = result.error;
                log(sdk::LogLevel::Warn, sdk::LogCategory::Network, "Deco %1: %2",
                    {v1::Utf8String(outcomeName(result.outcome)), v1::Utf8String(result.error)});
            }
            return;
        }
    }

    // --- the poll ---------------------------------------------------------

    void poll()
    {
        if (m_lifecycle != Lifecycle::Running || !m_session || m_host.empty() || m_loginRefused)
            return;
        // One poll in the queue is enough.
        for (const Round &round : m_queue)
            if (round.poll)
                return;
        if (!readStateFile(kCertFile) && !pinCertificate())
            return;

        struct Snapshot {
            std::vector<DecoNode> nodes;
            std::map<std::string, std::size_t> clientsPerNode;
            std::vector<sdk::NetworkClientSighting> seen;
            std::map<std::string, int> signal;
            bool complete = true;
        };
        auto snap = std::make_shared<Snapshot>();
        const auto failed = [snap](const Json &reply) {
            if (jsonInt(reply, "error_code", -1) != 0)
                snap->complete = false;
            return !snap->complete;
        };

        std::vector<DecoSession::Step> steps;
        steps.push_back({"admin/device", "device_list", Json{{"operation", "read"}},
                         [snap, failed](const Json &reply, std::vector<DecoSession::Step> &more) {
                             if (failed(reply))
                                 return;
                             snap->nodes = parseDeviceList(reply);
                             // Which clients each node has: the access point.
                             for (const DecoNode &node : snap->nodes) {
                                 const std::string name = node.name.empty() ? node.model : node.name;
                                 const std::string id = nodeDeviceId(node);
                                 more.push_back({"admin/client", "client_list",
                                                 Json{{"operation", "read"}, {"params", {{"device_mac", node.macDashed}}}},
                                                 [snap, failed, name, id](const Json &r, std::vector<DecoSession::Step> &) {
                                                     if (failed(r))
                                                         return;
                                                     auto clients = parseClientList(r, name);
                                                     snap->clientsPerNode[id] = clients.size();
                                                     for (auto &c : clients)
                                                         snap->seen.push_back(std::move(c));
                                                 }});
                             }
                         }});
        steps.push_back({"admin/client", "client_access", Json{{"operation", "read"}},
                         [snap](const Json &reply, std::vector<DecoSession::Step> &) {
                             // Signal is a bonus: a firmware without it still polls.
                             if (jsonInt(reply, "error_code", -1) == 0)
                                 snap->signal = parseClientSignal(reply);
                         }});
        // The client lists run after device_list, before client_access: the
        // session inserts a step's follow-ups right behind it.
        enqueue(std::move(steps), [this, snap](DecoSession::Result result) {
            if (result.outcome != DecoSession::Outcome::Ok || !snap->complete || snap->nodes.empty())
                return;   // not knowing is not everyone having left
            publishNodes(snap->nodes, snap->clientsPerNode);
            for (auto &s : snap->seen) {
                const auto sig = snap->signal.find(s.mac);
                if (sig != snap->signal.end())
                    s.rssiDbm = sig->second;
            }
            m_tracker.update(snap->seen, nowMs());
        }, true);
    }

    void publishNodes(const std::vector<DecoNode> &nodes, const std::map<std::string, std::size_t> &clients)
    {
        for (const DecoNode &node : nodes) {
            const std::string id = nodeDeviceId(node);
            const std::string fingerprint = nodeFingerprint(node);
            auto it = m_reportedNodes.find(id);
            if (it == m_reportedNodes.end() || it->second != fingerprint) {
                v1::Utf8String error;
                if (sendDeviceUpdated(buildNodeDevice(node), buildNodeChannels(), &error))
                    m_reportedNodes[id] = fingerprint;
                else
                    log(sdk::LogLevel::Error, sdk::LogCategory::Internal, "deviceUpdated(%1) failed: %2",
                        {v1::Utf8String(id), error});
            }
            const bool up = node.role == "master" ? node.internet : node.meshConnected;
            sendChannelStateUpdated(id, kNodeChannelOnline,
                                    static_cast<std::int64_t>(up ? v1::ConnectivityStatus::Connected
                                                                 : v1::ConnectivityStatus::Disconnected),
                                    nowMs());
            const auto count = clients.find(id);
            if (count != clients.end())
                sendChannelStateUpdated(id, kNodeChannelClients, static_cast<std::int64_t>(count->second), nowMs());
        }
    }

    // --- helpers ----------------------------------------------------------

    void saveTracked()
    {
        v1::ScalarList tracked;
        for (const std::string &mac : m_tracker.tracked())
            tracked.emplace_back(mac);
        m_meta[sdk::kClientMetaTracked] = m_tracker.tracked();
        v1::Utf8String error;
        if (!sendAdapterMetaUpdated({{sdk::kClientMetaTracked, tracked}}, &error))
            log(sdk::LogLevel::Error, sdk::LogCategory::Internal, "tracked clients not saved: %1", {error});
    }

    void setConnected(bool connected)
    {
        if (m_connected == connected)
            return;
        m_connected = connected;
        sendConnectionStateChanged(connected);
    }

    static v1::CmdResponse responseFor(v1::CmdId cmdId, v1::CmdStatus status, const std::string &error)
    {
        return v1::CmdResponse().setId(cmdId).setTsMs(nowMs()).setStatus(status).setError(error);
    }

    void sendCommandResponse(v1::CmdResponse response)
    {
        v1::Utf8String error;
        if (!sendResult(response, &error))
            log(sdk::LogLevel::Error, sdk::LogCategory::Internal, "failed to send the result: %1", {error});
    }

    void answer(v1::CmdId cmdId, v1::CmdStatus status, const std::string &error)
    {
        sendCommandResponse(responseFor(cmdId, status, error));
    }

    phi::runtime::Loop *m_loop = nullptr;
    std::optional<DecoSession> m_session;
    phi::runtime::Timer m_pollTimer;
    std::deque<Round> m_queue;
    sdk::ClientTracker m_tracker;

    v1::Adapter m_info;
    Json m_meta = Json::object();
    std::string m_host;
    std::string m_password;
    int m_pollIntervalS = kDefaultPollIntervalS;

    Lifecycle m_lifecycle = Lifecycle::Idle;
    bool m_connected = false;
    bool m_loginRefused = false;
    std::string m_saidError;
    std::map<std::string, std::string> m_reportedNodes;
};

} // namespace

std::unique_ptr<sdk::AdapterInstance> makeInstance()
{
    return std::make_unique<DecoInstance>();
}

} // namespace phicore::deco::ipc
