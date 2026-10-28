// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Joseph Crowell <joseph.w.crowell@gmail.com>

#pragma once

#include "initsystem.h"

#include <KJob>
#include <QPointer>
#include <QString>

#include <kcm_firewall_core_export.h>

#include <optional>

class QTimer;
namespace Sonic::Ipc
{
class Client;
class Connection;
}

// Starts, stops, enables or disables a firewall service through sonic-firewall-service, falling back to the
// org.sonicde.firewall.servicehelper KAuth helper when the daemon can't be used.
class KCM_FIREWALL_CORE_EXPORT ServiceJob : public KJob
{
    Q_OBJECT
public:
    // enable: start (unless serviceOnly) and enable at boot; otherwise stop (unless serviceOnly) and disable.
    ServiceJob(bool enable, const QString &service, bool serviceOnly = false, QObject *parent = nullptr);

    // Tests only: a fixed init type and socket path, a short reply timeout, and no real KAuth fallback.
    // Instead of running KAuth, the fallback finishes with FallbackError and "fallback: <reason>".
    struct TestOptions {
        InitSystem::Type type;
        QString socketPath;
        int replyTimeoutMs = 600000;
    };
    static constexpr int FallbackError = KJob::UserDefinedError + 1;
    ServiceJob(bool enable, const QString &service, bool serviceOnly, const TestOptions &options, QObject *parent = nullptr);
    ~ServiceJob() override;

    void start() override;

private:
    void doStart();
    void startDaemonRequest();
    void startKAuthFallback(const QString &reason);
    void finishFrom(KJob *job);
    void finish(int code, const QString &text);
    const bool m_enable;
    const QString m_service;
    const bool m_serviceOnly;
    Sonic::Ipc::Client *m_client = nullptr; // child of this
    QPointer<Sonic::Ipc::Connection> m_connection; // owned by m_client
    QTimer *m_replyTimer = nullptr; // child of this, created in startDaemonRequest()
    bool m_fallbackStarted = false;
    bool m_finished = false;
    std::optional<TestOptions> m_test; // set only by the test constructor
};
