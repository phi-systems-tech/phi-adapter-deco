#include "deco_cert.h"

#include <cerrno>
#include <cstring>
#include <memory>

#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

namespace phicore::deco::ipc {

namespace {

struct Fd {
    int fd = -1;
    ~Fd()
    {
        if (fd >= 0)
            ::close(fd);
    }
};

int connectWithin(const std::string &host, int port, std::chrono::milliseconds timeout, std::string *error)
{
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo *found = nullptr;
    const std::string service = std::to_string(port);
    if (::getaddrinfo(host.c_str(), service.c_str(), &hints, &found) != 0 || !found) {
        *error = "cannot resolve " + host;
        return -1;
    }
    std::unique_ptr<addrinfo, decltype(&::freeaddrinfo)> list(found, ::freeaddrinfo);
    for (addrinfo *a = found; a; a = a->ai_next) {
        const int fd = ::socket(a->ai_family, a->ai_socktype | SOCK_CLOEXEC | SOCK_NONBLOCK, a->ai_protocol);
        if (fd < 0)
            continue;
        if (::connect(fd, a->ai_addr, a->ai_addrlen) != 0 && errno != EINPROGRESS) {
            ::close(fd);
            continue;
        }
        pollfd p{fd, POLLOUT, 0};
        int soError = 0;
        socklen_t len = sizeof soError;
        if (::poll(&p, 1, static_cast<int>(timeout.count())) != 1
            || ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &soError, &len) != 0 || soError != 0) {
            ::close(fd);
            continue;
        }
        // Blocking from here, with the same deadline for each read and write.
        ::fcntl(fd, F_SETFL, ::fcntl(fd, F_GETFL) & ~O_NONBLOCK);
        timeval tv{};
        tv.tv_sec = static_cast<time_t>(timeout.count() / 1000);
        tv.tv_usec = static_cast<suseconds_t>((timeout.count() % 1000) * 1000);
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        return fd;
    }
    *error = "cannot connect to " + host + ":" + service;
    return -1;
}

} // namespace

std::optional<std::string> fetchPeerCertificatePem(const std::string &host, int port,
                                                   std::chrono::milliseconds timeout, std::string *error)
{
    std::string ignored;
    std::string &err = error ? *error : ignored;
    Fd sock{connectWithin(host, port, timeout, &err)};
    if (sock.fd < 0)
        return std::nullopt;

    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ctx(SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
    if (!ctx) {
        err = "no TLS context";
        return std::nullopt;
    }
    // Taken unchecked on purpose: this is the moment it becomes the one that
    // is checked against from now on.
    SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, nullptr);
    std::unique_ptr<SSL, decltype(&SSL_free)> ssl(SSL_new(ctx.get()), SSL_free);
    if (!ssl || SSL_set_fd(ssl.get(), sock.fd) != 1) {
        err = "no TLS session";
        return std::nullopt;
    }
    if (SSL_connect(ssl.get()) != 1) {
        err = "TLS handshake with " + host + " failed";
        ERR_clear_error();
        return std::nullopt;
    }
    std::unique_ptr<X509, decltype(&X509_free)> cert(SSL_get1_peer_certificate(ssl.get()), X509_free);
    SSL_shutdown(ssl.get());
    if (!cert) {
        err = host + " sent no certificate";
        return std::nullopt;
    }
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), BIO_free);
    if (!bio || PEM_write_bio_X509(bio.get(), cert.get()) != 1) {
        err = "certificate could not be written";
        return std::nullopt;
    }
    char *data = nullptr;
    const long size = BIO_get_mem_data(bio.get(), &data);
    return std::string(data, static_cast<std::size_t>(size));
}

std::string certificateFingerprint(const std::string &pem)
{
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())),
                                                  BIO_free);
    if (!bio)
        return {};
    std::unique_ptr<X509, decltype(&X509_free)> cert(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr),
                                                     X509_free);
    if (!cert)
        return {};
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (X509_digest(cert.get(), EVP_sha256(), md, &len) != 1)
        return {};
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string out;
    for (unsigned int i = 0; i < len; ++i) {
        if (i)
            out.push_back(':');
        out.push_back(kHex[md[i] >> 4]);
        out.push_back(kHex[md[i] & 0x0f]);
    }
    return out;
}

} // namespace phicore::deco::ipc
