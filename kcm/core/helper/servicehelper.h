// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Joseph Crowell <joseph.w.crowell@gmail.com>

#pragma once

#include <KAuth/ActionReply>
#include <QObject>
#include <QVariantMap>

// The KAuth fallback for sonic-firewall-service: does the same work when the daemon isn't running.
class ServiceHelper : public QObject
{
    Q_OBJECT

public Q_SLOTS:
    // Action org.sonicde.firewall.servicehelper.manage; args: service, enable, serviceOnly.
    KAuth::ActionReply manage(const QVariantMap &args);
};
