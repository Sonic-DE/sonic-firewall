// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Joseph Crowell <joseph.w.crowell@gmail.com>

#include "servicejob.h"
#include "initsystem.h"
#include "serviceprotocol.h"

#include <KAuth/Action>
#include <KAuth/ExecuteJob>
#include <KLocalizedString>
#include <QTimer>

#include <Sonic/Ipc/Client>
#include <Sonic/Ipc/Connection>
#include <Sonic/Logging/Log>

namespace
{
// The daemon's worst case: up to 300 s for the polkit prompt plus 210 s of commands, with margin.
constexpr int replyTimeoutMs = 600000;
// The KAuth helper's worst case is three commands of 70 s each.
constexpr int kauthTimeoutMs = 240000;
}

ServiceJob::ServiceJob(bool enable, const QString &service, bool serviceOnly, QObject *parent)
    : KJob(parent)
    , m_enable(enable)
    , m_service(service)
    , m_serviceOnly(serviceOnly)
{
}

ServiceJob::ServiceJob(bool enable, const QString &service, bool serviceOnly, const TestOptions &options, QObject *parent)
    : KJob(parent)
    , m_enable(enable)
    , m_service(service)
    , m_serviceOnly(serviceOnly)
    , m_test(options)
{
}

ServiceJob::~ServiceJob() = default;

void ServiceJob::start()
{
    QTimer::singleShot(0, this, &ServiceJob::doStart);
}

void ServiceJob::doStart()
{
    const InitSystem::Type type = m_test ? m_test->type : InitSystem::detect();
    sonicDebug() << "service job:" << m_service << "enable:" << m_enable << "serviceOnly:" << m_serviceOnly << "init:" << InitSystem::typeName(type);
    startDaemonRequest();
}

void ServiceJob::startDaemonRequest()
{
    m_client = new Sonic::Ipc::Client(ServiceProtocol::version, ServiceProtocol::maxPayload, this);
    m_replyTimer = new QTimer(this);
    m_replyTimer->setSingleShot(true);
    m_replyTimer->setInterval(m_test ? m_test->replyTimeoutMs : replyTimeoutMs);

    connect(m_replyTimer, &QTimer::timeout, this, [this] {
        finish(KJob::UserDefinedError, i18n("The firewall service did not answer in time"));
    });

    // connectToServer() can emit synchronously, so everything is connected first.
    connect(m_client, &Sonic::Ipc::Client::connected, this, [this](Sonic::Ipc::Connection *connection) {
        m_connection = connection;
        connect(connection, &Sonic::Ipc::Connection::frameReceived, this, [this](quint32 type, const QByteArray &payload) {
            if (type != ServiceProtocol::Result) {
                sonicDebug() << "ignoring frame type" << type;
                return;
            }
            const std::optional<ServiceProtocol::Reply> reply = ServiceProtocol::decodeReply(payload);
            if (!reply) {
                finish(KJob::UserDefinedError, i18n("The firewall service sent an invalid reply"));
                return;
            }
            if (reply->code == InitSystem::AuthorizationUnavailable) {
                startKAuthFallback(QStringLiteral("daemon could not ask polkit: ") + reply->message);
                return;
            }
            finish(reply->code, reply->message);
        });
        connect(connection, &Sonic::Ipc::Connection::disconnected, this, [this] {
            finish(KJob::UserDefinedError, i18n("The firewall service closed the connection"));
        });
        connection->send(ServiceProtocol::Manage, ServiceProtocol::encode(ServiceProtocol::Request{m_service, m_enable, m_serviceOnly}));
        m_replyTimer->start();
    });
    connect(m_client, &Sonic::Ipc::Client::connectionFailed, this, [this](const QString &reason) {
        startKAuthFallback(reason);
    });
    connect(m_client, &Sonic::Ipc::Client::versionRejected, this, [this](quint16 version) {
        // The connection's disconnected follows this synchronously; the fallback detaches from it first.
        startKAuthFallback(QStringLiteral("daemon speaks protocol %1").arg(version));
    });

    // Logged first: connectToServer() can fail synchronously and start the fallback.
    sonicDebug() << "asking the firewall service daemon";
    m_client->connectToServer(m_test ? m_test->socketPath : ServiceProtocol::socketPath());
}

void ServiceJob::startKAuthFallback(const QString &reason)
{
    if (m_fallbackStarted || m_finished) {
        return;
    }
    m_fallbackStarted = true;

    // Detach from the daemon before anything else, so its coming disconnected can't finish the job.
    if (m_replyTimer) {
        m_replyTimer->stop();
    }
    if (m_connection) {
        QObject::disconnect(m_connection, nullptr, this, nullptr);
    }
    if (m_client) {
        m_client->disconnectFromServer();
    }
    sonicInfo() << "using the KAuth fallback:" << reason;

    if (m_test) {
        QTimer::singleShot(0, this, [this, reason] {
            finish(FallbackError, QStringLiteral("fallback: ") + reason);
        });
        return;
    }

    KAuth::Action action(QStringLiteral("org.sonicde.firewall.servicehelper.manage"));
    action.setHelperId(QStringLiteral("org.sonicde.firewall.servicehelper"));
    action.setArguments({
        {QStringLiteral("service"), m_service},
        {QStringLiteral("enable"), m_enable},
        {QStringLiteral("serviceOnly"), m_serviceOnly},
    });
    action.setTimeout(kauthTimeoutMs);

    KAuth::ExecuteJob *job = action.execute();
    connect(job, &KJob::result, this, [this, job] {
        finishFrom(job);
    });
    job->start();
}

void ServiceJob::finishFrom(KJob *job)
{
    finish(job->error(), job->errorText());
}

void ServiceJob::finish(int code, const QString &text)
{
    if (m_finished) {
        return;
    }
    m_finished = true;
    if (m_replyTimer) {
        m_replyTimer->stop();
    }
    if (code != 0) {
        setError(code);
        setErrorText(text);
        sonicWarning() << "service job for" << m_service << "failed:" << code << text;
    }
    emitResult();
}

#include "moc_servicejob.cpp"
