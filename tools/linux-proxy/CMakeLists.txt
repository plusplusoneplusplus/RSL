cmake_minimum_required(VERSION 3.13)
project(rsl_linux_proxy CXX)

# Linux-only supplemental proxy/model. Wire primitives use selected production
# translation units; storage, packet receive, and learn behavior are copied or
# ported models and are not production-Windows authority.

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(RSL_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../..)
set(RSL_SRC ${RSL_ROOT}/src)

add_executable(rsl-linux-proxy
    # Original engine translation units (compiled verbatim):
    ${RSL_SRC}/common/src/msn_fprint.cpp
    ${RSL_SRC}/common/src/marshal.cpp
    ${RSL_SRC}/common/src/fingerprint.cpp
    ${RSL_SRC}/common/src/utils.cpp
    ${RSL_SRC}/RSL/src/message.cpp
    # Verbatim extract of MemberSet / RSLNodeCollection / RSLNode from rsl.cpp:
    ${CMAKE_CURRENT_SOURCE_DIR}/src/engine_support.cpp
    # Copied format methods plus the Linux storage model:
    ${CMAKE_CURRENT_SOURCE_DIR}/src/storage_model.cpp
    # Copied framing methods plus the Linux packet/receive model:
    ${CMAKE_CURRENT_SOURCE_DIR}/src/packet_model.cpp
    # Ported learn server/client model:
    ${CMAKE_CURRENT_SOURCE_DIR}/src/learn_model.cpp
    # Proxy command driver:
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp
)

target_include_directories(rsl-linux-proxy PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/compat   # windows.h / strsafe.h / pal_logging.h / msg_engine_compat.h
    ${RSL_SRC}/inc                       # rsl.h
    ${RSL_SRC}/common/src                # basic_types.h, marshal.h, fingerprint.h, ...
    ${RSL_SRC}/NetworkLib/inc            # PacketHdr.h (shared packet-header types)
    ${RSL_SRC}/RSL/src                   # message.h
)

# The engine headers are full of MSVC #pragma warning(...) directives and other
# Windows-isms that are harmless on gcc; silence the noise so real diagnostics
# stand out.
target_compile_options(rsl-linux-proxy PRIVATE
    -Wno-unknown-pragmas
    -Wno-invalid-offsetof
    # msn_fprint.{h,cpp} use `unsigned __int64` without including windows.h, so
    # force-include the MSVC builtin keyword spellings into every TU.
    -include ${CMAKE_CURRENT_SOURCE_DIR}/compat/msvc_builtins.h
)

# ---------------------------------------------------------------------------
# Supplemental OpenSSL interoperability.
#
# OpenSSL checks a foreign TLS stack on Linux; it does not establish SChannel
# compatibility. A build without OpenSSL still provides the other proxy models.
find_package(OpenSSL)
if(OpenSSL_FOUND)
    target_sources(rsl-linux-proxy PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/tls_peer.cpp)
    target_compile_definitions(rsl-linux-proxy PRIVATE RSL_PROXY_TLS)
    target_link_libraries(rsl-linux-proxy PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    message(STATUS "rsl-linux-proxy: OpenSSL ${OPENSSL_VERSION} found -- --tls-peer enabled")
else()
    message(STATUS "rsl-linux-proxy: OpenSSL not found -- --tls-peer disabled")
endif()
