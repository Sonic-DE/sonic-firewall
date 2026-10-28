// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Joseph Crowell <joseph.w.crowell@gmail.com>

#include "servicehelper.h"
#include "initsystem.h"

#include <KAuth/HelperSupport>
#include <KLocalizedString>

#include <Sonic/Logging/Logging>

SONIC_LOGGING_COMPONENT("org.sonicde.firewall.servicehelper")

namespace
{
// KAUTH_HELPER_MAIN installs KAuth's syslog handler before it constructs QCoreApplication; this runs from
// that constructor, so the explicit install replaces KAuth's handler with Sonic Logging.
void installSonicLogging()
{
    Sonic::Logging::install();
}
}
Q_COREAPP_STARTUP_FUNCTION(installSonicLogging)

KAuth::ActionReply ServiceHelper::manage(const QVariantMap &args)
{
    if (!args.contains(QStringLiteral("service")) || !args.contains(QStringLiteral("enable")) || !args.contains(QStringLiteral("serviceOnly"))) {
        sonicWarning() << "invalid arguments; keys received:" << args.keys();
        KAuth::ActionReply reply = KAuth::ActionReply::HelperErrorReply(InitSystem::InvalidArguments);
        reply.setErrorDescription(i18n("Invalid arguments for the firewall service helper"));
        return reply;
    }

    sonicInfo() << "request came through the KAuth fallback";
    QString message;
    const int status = InitSystem::manage(args.value(QStringLiteral("service")).toString(),
                                          args.value(QStringLiteral("enable")).toBool(),
                                          args.value(QStringLiteral("serviceOnly")).toBool(),
                                          &message);
    if (status == InitSystem::Ok) {
        return KAuth::ActionReply::SuccessReply();
    }
    KAuth::ActionReply reply = KAuth::ActionReply::HelperErrorReply(status);
    reply.setErrorDescription(message);
    return reply;
}

KAUTH_HELPER_MAIN("org.sonicde.firewall.servicehelper", ServiceHelper)

#include "moc_servicehelper.cpp"
