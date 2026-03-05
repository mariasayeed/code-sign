cmake_minimum_required(VERSION 3.12)
project(hsm_pkcs11_bridge C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ── Build options ──────────────────────────────────────────────────────────
option(BUILD_SHARED "Build as shared library (.so / .dll)" ON)

# ── Find dependencies ──────────────────────────────────────────────────────
find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)

# ── Shared library target ──────────────────────────────────────────────────
if(BUILD_SHARED)
    add_library(hsm_pkcs11 SHARED hsm_pkcs11.c)
else()
    add_library(hsm_pkcs11 STATIC hsm_pkcs11.c)
endif()

target_include_directories(hsm_pkcs11 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(hsm_pkcs11
    PRIVATE
    CURL::libcurl
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Symbol visibility: only export PKCS#11 API
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_compile_options(hsm_pkcs11 PRIVATE -fvisibility=hidden)
    target_link_options(hsm_pkcs11    PRIVATE -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/exports.ldscript)
endif()

# ── Output naming ──────────────────────────────────────────────────────────
set_target_properties(hsm_pkcs11 PROPERTIES
    OUTPUT_NAME "hsm_pkcs11"
    PREFIX ""               # no "lib" prefix — CST loads by exact name
    SOVERSION 1
)

# ── Install ────────────────────────────────────────────────────────────────
install(TARGETS hsm_pkcs11
    LIBRARY  DESTINATION lib
    ARCHIVE  DESTINATION lib
    RUNTIME  DESTINATION bin   # .dll on Windows
)
install(FILES pkcs11_types.h DESTINATION include)

# ── Summary ───────────────────────────────────────────────────────────────
message(STATUS "")
message(STATUS "=== HSM PKCS#11 Bridge ===")
message(STATUS "  Build type    : ${CMAKE_BUILD_TYPE}")
message(STATUS "  CURL          : ${CURL_VERSION_STRING}")
message(STATUS "  OpenSSL       : ${OPENSSL_VERSION}")
message(STATUS "  Output        : ${CMAKE_BINARY_DIR}/hsm_pkcs11${CMAKE_SHARED_LIBRARY_SUFFIX}")
message(STATUS "")
message(STATUS "After building:")
message(STATUS "  export HSM_BASE=https://YOUR_HSM/crypto/api/v1")
message(STATUS "  export HSM_AUTH_TOKEN=YOUR_JWT")
message(STATUS "  export HSM_CSF_KEY_ID=<csf_publicKeyId>")
message(STATUS "  export HSM_IMG_KEY_ID=<img_publicKeyId>")
message(STATUS "  export HSM_SRK_CERT_PATH=/path/to/certs/SRK1.pem")
message(STATUS "  export HSM_CSF_CERT_PATH=/path/to/certs/CSF.pem")
message(STATUS "  export HSM_IMG_CERT_PATH=/path/to/certs/IMG.pem")
message(STATUS "  cst -b pkcs11 --module ./hsm_pkcs11.so -i csf.txt -o csf.bin")
message(STATUS "")
