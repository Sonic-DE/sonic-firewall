# SPDX-License-Identifier: BSD-3-Clause
# SPDX-FileCopyrightText: 2026 Joseph Crowell <joseph.w.crowell@gmail.com>

add_executable(kcm_firewall_service_helper servicehelper.cpp servicehelper.h)
target_link_libraries(kcm_firewall_service_helper kcm_firewall_initsystem Qt::Core KF6::AuthCore KF6::I18n Sonic::Logging)
# The polkit action installed here is also what the daemon (../daemon) checks.
kauth_install_actions(org.sonicde.firewall.servicehelper org.sonicde.firewall.servicehelper.actions)
install(TARGETS kcm_firewall_service_helper DESTINATION ${KAUTH_HELPER_INSTALL_DIR})
kauth_install_helper_files(kcm_firewall_service_helper org.sonicde.firewall.servicehelper root)
