cmake_minimum_required(VERSION 3.21)

project(phi-adapter-deco VERSION 0.1.0 DESCRIPTION "Phi TP-Link Deco adapter" LANGUAGES CXX)

include(GNUInstallDirs)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(nlohmann_json 3.11 REQUIRED)
# The Deco's envelope (RSA, AES-128-CBC, MD5) and the certificate pin.
find_package(OpenSSL REQUIRED)

set(PHI_ADAPTER_SDK_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../phi-adapter-sdk" CACHE PATH
    "Path to local phi-adapter-sdk checkout")
option(PHI_ADAPTER_DECO_USE_LOCAL_ADAPTER_SDK "Use local ../phi-adapter-sdk" ON)

if(NOT TARGET phi::adapter-sdk)
    if(PHI_ADAPTER_DECO_USE_LOCAL_ADAPTER_SDK AND EXISTS "${PHI_ADAPTER_SDK_SOURCE_DIR}/CMakeLists.txt")
        set(PHI_ADAPTER_SDK_BUILD_TESTS OFF CACHE BOOL "" FORCE)
        add_subdirectory("${PHI_ADAPTER_SDK_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/_deps/phi-adapter-sdk")
    else()
        find_package(phi-adapter-sdk CONFIG REQUIRED)
    endif()
endif()

add_library(phi_adapter_deco_core STATIC
    src/deco_cert.cpp
    src/deco_crypto.cpp
    src/deco_instance.cpp
    src/deco_json.cpp
    src/deco_model.cpp
    src/deco_schema.cpp
    src/deco_session.cpp
)
target_compile_features(phi_adapter_deco_core PUBLIC cxx_std_20)
set_target_properties(phi_adapter_deco_core PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(phi_adapter_deco_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(phi_adapter_deco_core PUBLIC phi::adapter-sdk nlohmann_json::nlohmann_json
                                                   OpenSSL::SSL OpenSSL::Crypto)

add_executable(phi_adapter_deco_ipc src/main.cpp)
target_link_libraries(phi_adapter_deco_ipc PRIVATE phi_adapter_deco_core)
set_target_properties(phi_adapter_deco_ipc PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/plugins/adapters")

enable_testing()
add_executable(deco_tests tests/deco_tests.cpp)
target_link_libraries(deco_tests PRIVATE phi_adapter_deco_core)
add_test(NAME deco_tests COMMAND deco_tests)

install(TARGETS phi_adapter_deco_ipc
    RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}/phi/plugins/adapters)
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/deco-config.json"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/phi/plugins/adapters)
