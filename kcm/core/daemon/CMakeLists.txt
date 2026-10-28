# SPDX-License-Identifier: BSD-3-Clause
# SPDX-FileCopyrightText: 2026 Joseph Crowell <joseph.w.crowell@gmail.com>

add_executable(sonic-firewall-service main.cpp servicedaemon.cpp servicedaemon.h polkitauthority.cpp polkitauthority.h)
target_link_libraries(sonic-firewall-service kcm_firewall_initsystem Qt::Core Qt::DBus Sonic::Ipc Sonic::Logging KF6::I18n)
install(TARGETS sonic-firewall-service DESTINATION ${KDE_INSTALL_LIBEXECDIR})
