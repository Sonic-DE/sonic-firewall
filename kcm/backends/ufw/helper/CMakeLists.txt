# SPDX-License-Identifier: BSD-3-Clause
# SPDX-FileCopyrightText: 2020 Tomaz Canabrava <tcanabrava@kde.org>

# Find includes in corresponding build directories
set(CMAKE_INCLUDE_CURRENT_DIR ON)
include_directories(${CMAKE_BINARY_DIR})

# Instruct CMake to run moc automatically when needed.
set(CMAKE_AUTOMOC ON)

find_package(Qt6 ${QT_MIN_VERSION} CONFIG REQUIRED COMPONENTS
    Quick
)


find_package(KF6 ${KF6_MIN_VERSION} REQUIRED COMPONENTS
    I18n
    Auth
)


set(ufw_plugin_helper_SRCS helper.cpp helper.h ufwlogreader.cpp ufwlogreader.h)
add_executable(kde_ufw_plugin_helper ${ufw_plugin_helper_SRCS})

# set_target_properties(kcm_ufw_helper PROPERTIES OUTPUT_NAME kcm_ufw_helper)
target_link_libraries(kde_ufw_plugin_helper Qt::Core KF6::AuthCore KF6::I18n kcm_firewall_initsystem Sonic::InitInfo Sonic::Logging)

if (IS_ABSOLUTE "${KDE_INSTALL_LIBEXECDIR}")
  set(UFW_PLUGIN_HELPER_PATH ${KDE_INSTALL_LIBEXECDIR}/kde_ufw_plugin_helper.py)
else()
  set(UFW_PLUGIN_HELPER_PATH ${CMAKE_INSTALL_PREFIX}/${KDE_INSTALL_LIBEXECDIR}/kde_ufw_plugin_helper.py)
endif()
# The helper imports ufw, which may be installed for only one of several Pythons.
if(NOT UFW_PYTHON_EXECUTABLE)
    set(_ufw_python_candidates ${Python3_EXECUTABLE})
    get_filename_component(_python_dir "${Python3_EXECUTABLE}" DIRECTORY)
    foreach(_minor RANGE 30 9 -1)
        find_program(_ufw_python_3_${_minor} NAMES python3.${_minor} HINTS ${_python_dir} NO_CACHE)
        if(_ufw_python_3_${_minor})
            list(APPEND _ufw_python_candidates ${_ufw_python_3_${_minor}})
        endif()
    endforeach()
    list(REMOVE_DUPLICATES _ufw_python_candidates)
    foreach(_candidate IN LISTS _ufw_python_candidates)
        execute_process(COMMAND ${_candidate} -c "import ufw.common" RESULT_VARIABLE _ufw_import OUTPUT_QUIET ERROR_QUIET)
        if(_ufw_import EQUAL 0)
            set(UFW_PYTHON_EXECUTABLE ${_candidate})
            break()
        endif()
    endforeach()
    if(NOT UFW_PYTHON_EXECUTABLE)
        message(FATAL_ERROR "No Python can import ufw's modules (tried: ${_ufw_python_candidates}). "
                            "Install ufw, pass -DUFW_PYTHON_EXECUTABLE=<python that has ufw>, "
                            "or disable the backend with -DBUILD_UFW_BACKEND=OFF.")
    endif()
endif()
message(STATUS "UFW helper runs on ${UFW_PYTHON_EXECUTABLE}")
configure_file(kcm_ufw_helper.py.cmake ${CMAKE_BINARY_DIR}/kde_ufw_plugin_helper.py)
configure_file(ufw_helper_config.h.cmake ${CMAKE_BINARY_DIR}/ufw_helper_config.h)

kauth_install_actions(org.kde.ufw org.kde.ufw.actions)
install(TARGETS kde_ufw_plugin_helper DESTINATION ${KAUTH_HELPER_INSTALL_DIR})
kauth_install_helper_files(kde_ufw_plugin_helper org.kde.ufw root)

# install(TARGETS kcm_ufw_helper DESTINATION ${KDE_INSTALL_LIBEXECDIR})
install(PROGRAMS ${CMAKE_BINARY_DIR}/kde_ufw_plugin_helper.py DESTINATION ${KDE_INSTALL_LIBEXECDIR})

# configure_file(org.kde.ufw.service.cmake ${CMAKE_CURRENT_BINARY_DIR}/session/org.kde.ufw.service)
# install(FILES ${CMAKE_CURRENT_BINARY_DIR}/session/org.kde.ufw.service DESTINATION ${KDE_INSTALL_DBUSSERVICEDIR})
install(FILES defaults DESTINATION ${KDE_INSTALL_DATADIR}/kcm_ufw)
