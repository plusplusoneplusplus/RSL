cmake_minimum_required(VERSION 3.13)
project(rsl_golden_gen CXX)

# Phase-1 golden-vector generator: builds the minimum slice of the original RSL
# C++ (marshaling + Rabin-64 fingerprint + all message types) on Linux, so we
# can emit byte-exact reference vectors for the Rust port to check against.
#
# This is a Linux-only reference build. The Windows MSBuild build is untouched;
# every Linux-specific shim lives under compat/ and is guarded by #ifndef _WIN32
# in the shared headers.

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(RSL_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../..)
set(RSL_SRC ${RSL_ROOT}/src)

add_executable(golden-gen
    # Original engine translation units (compiled verbatim):
    ${RSL_SRC}/common/src/msn_fprint.cpp
    ${RSL_SRC}/common/src/marshal.cpp
    ${RSL_SRC}/common/src/fingerprint.cpp
    ${RSL_SRC}/common/src/utils.cpp
    ${RSL_SRC}/RSL/src/message.cpp
    # Verbatim extract of MemberSet / RSLNodeCollection / RSLNode from rsl.cpp:
    ${CMAKE_CURRENT_SOURCE_DIR}/src/engine_min.cpp
    # Verbatim extract of ConfigurationInfo / CheckpointHeader from
    # legislator.cpp + Linux ports of the storage I/O paths (Phase 3a):
    ${CMAKE_CURRENT_SOURCE_DIR}/src/storage_min.cpp
    # Verbatim extract of PacketHdr/Packet + the NetCxn receive decision table
    # and Message::ReadFromSocket, plus the live TCP peer (Phase 4a):
    ${CMAKE_CURRENT_SOURCE_DIR}/src/packet_min.cpp
    # The generator driver:
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp
)

target_include_directories(golden-gen PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/compat   # windows.h / strsafe.h / pal_logging.h / msg_engine_compat.h
    ${RSL_SRC}/inc                       # rsl.h
    ${RSL_SRC}/common/src                # basic_types.h, marshal.h, fingerprint.h, ...
    ${RSL_SRC}/NetworkLib/inc            # PacketHdr.h (shared packet-header types)
    ${RSL_SRC}/RSL/src                   # message.h
)

# The engine headers are full of MSVC #pragma warning(...) directives and other
# Windows-isms that are harmless on gcc; silence the noise so real diagnostics
# stand out.
target_compile_options(golden-gen PRIVATE
    -Wno-unknown-pragmas
    -Wno-invalid-offsetof
    # msn_fprint.{h,cpp} use `unsigned __int64` without including windows.h, so
    # force-include the MSVC builtin keyword spellings into every TU.
    -include ${CMAKE_CURRENT_SOURCE_DIR}/compat/msvc_builtins.h
)
