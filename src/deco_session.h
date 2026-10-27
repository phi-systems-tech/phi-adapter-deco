#pragma once

// One round with the Deco's web API: log in, a few calls, log out.
//
// The master takes one admin session at a time - logging in throws the Deco
// app out and the other way round - so the adapter never stays logged in: a
// poll or a write is one round, and the round ends with a logout. A rejected
// login is not tried again by the round; ~10 of them lock the account.

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "phi/adapter/net/http_client.h"
#include "phi/runtime/loop.h"

#include "deco_crypto.h"
#include "deco_json.h"

namespace phicore::deco::ipc {

class DecoSession
{
public:
    /// One call: `/cgi-bin/luci/;stok=<token>/<path>?form=<form>` with the
    /// payload. `done` gets the decrypted answer ({error_code, result}) or
    /// {"http": status} when the router answered with an error page; it may
    /// add calls to `more`, which run next in this round.
    struct Step;
    using StepDone = std::function<void(const Json &reply, std::vector<Step> &more)>;
    struct Step {
        std::string path;
        std::string form;
        Json payload;
        StepDone done;
    };

    enum class Outcome {
        Ok,
        /// The password was refused. Do not try again on your own.
        LoginRejected,
        /// No answer, no TLS, a certificate that is not the pinned one.
        Unreachable,
        /// The session went away mid-round (the app logged in): try later.
        Evicted,
        /// An answer that is not what the web UI gets.
        Protocol,
    };
    struct Result {
        Outcome outcome = Outcome::Ok;
        std::string error;
    };

    explicit DecoSession(phi::runtime::Loop &loop);
    ~DecoSession();

    /// The master's address and the pinned certificate (a PEM file).
    void setEndpoint(std::string host, std::string caFile);
    void setPassword(std::string password);

    [[nodiscard]] bool busy() const { return m_running; }
    /// Starts a round; false while one runs.
    bool run(std::vector<Step> steps, std::function<void(Result)> done);
    /// Drops the round in flight; its done is not called.
    void cancel();

private:
    using Http = phicore::adapter::net::HttpClient;

    void post(const std::string &path, const std::string &form, std::string body,
              std::function<void(Http::Result)> done);
    void encrypted(const std::string &path, const std::string &form, const Json &payload, bool login,
                   std::function<void(std::optional<Json> reply, int httpStatus)> done);
    void login();
    void next();
    void logout();
    void finish(Outcome outcome, std::string error);

    Http m_http;
    std::string m_host;
    std::string m_caFile;
    std::string m_password;

    bool m_running = false;
    std::vector<Step> m_steps;
    std::function<void(Result)> m_done;
    Result m_result;

    // One login's keys; a new pair every round.
    AesKey m_aes;
    std::string m_passwordKeyN, m_passwordKeyE;
    std::string m_signKeyN, m_signKeyE;
    long long m_seq = 0;
    std::string m_authHash;
    std::string m_stok;
    std::string m_cookie;
};

/// Rounds of their own: what the poll and the writes queue behind.
const char *outcomeName(DecoSession::Outcome outcome);

} // namespace phicore::deco::ipc
