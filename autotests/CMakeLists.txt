add_executable(ipvalidatortest ipvalidatortest.cpp)
target_link_libraries(ipvalidatortest kcm_firewall_core Qt::Test)
add_test(NAME ipvalidatortest COMMAND ipvalidatortest)

set(sonic_logging_component_SRC ${CMAKE_CURRENT_SOURCE_DIR}/sonic_logging_component.cpp)

add_executable(initsystemtest initsystemtest.cpp ${sonic_logging_component_SRC})
target_link_libraries(initsystemtest kcm_firewall_initsystem Qt::Test)
add_test(NAME initsystemtest COMMAND initsystemtest)

add_executable(serviceprotocoltest serviceprotocoltest.cpp ${sonic_logging_component_SRC})
target_link_libraries(serviceprotocoltest kcm_firewall_initsystem Qt::Test)
add_test(NAME serviceprotocoltest COMMAND serviceprotocoltest)

add_executable(servicejobtest servicejobtest.cpp ${sonic_logging_component_SRC})
target_link_libraries(servicejobtest kcm_firewall_core Sonic::Ipc Sonic::Logging Qt::Test)
add_test(NAME servicejobtest COMMAND servicejobtest)

add_executable(servicedaemontest servicedaemontest.cpp ${sonic_logging_component_SRC}
    ${CMAKE_SOURCE_DIR}/kcm/core/daemon/servicedaemon.cpp ${CMAKE_SOURCE_DIR}/kcm/core/daemon/servicedaemon.h)
target_include_directories(servicedaemontest PRIVATE ${CMAKE_SOURCE_DIR}/kcm/core/daemon)
target_link_libraries(servicedaemontest kcm_firewall_initsystem Sonic::Ipc Sonic::Logging Qt::Test)
add_test(NAME servicedaemontest COMMAND servicedaemontest)

add_executable(ufwlogreadertest ufwlogreadertest.cpp ${CMAKE_SOURCE_DIR}/kcm/backends/ufw/helper/ufwlogreader.cpp)
target_include_directories(ufwlogreadertest PRIVATE ${CMAKE_SOURCE_DIR}/kcm/backends/ufw/helper)
target_link_libraries(ufwlogreadertest Qt::Core Qt::Test Sonic::InitInfo)
add_test(NAME ufwlogreadertest COMMAND ufwlogreadertest)

if(BUILD_UFW_BACKEND AND ${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    add_executable(ufwlogmodeltest ufwlogmodeltest.cpp ${sonic_logging_component_SRC}
        ${CMAKE_SOURCE_DIR}/kcm/backends/ufw/ufwlogmodel.cpp ${CMAKE_SOURCE_DIR}/kcm/backends/ufw/ufwlogmodel.h)
    target_include_directories(ufwlogmodeltest PRIVATE ${CMAKE_SOURCE_DIR}/kcm/backends/ufw)
    target_link_libraries(ufwlogmodeltest kcm_firewall_core Sonic::Logging Qt::Test)
    add_test(NAME ufwlogmodeltest COMMAND ufwlogmodeltest)
endif()
