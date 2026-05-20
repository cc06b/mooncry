cmake_minimum_required(VERSION 3.10)
project(financial_crypto C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 设置输出目录
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# 源文件列表
set(SOURCES
    src/sha256.c
    src/hmac.c
    src/aes256.c
    src/utils.c
)

# 头文件目录
include_directories(include)

# 创建动态库
add_library(financial_crypto SHARED ${SOURCES})
target_compile_definitions(financial_crypto PRIVATE CRYPTO_EXPORTS)

# 创建静态库
add_library(financial_crypto_static STATIC ${SOURCES})
set_target_properties(financial_crypto_static PROPERTIES OUTPUT_NAME financial_crypto)

# Windows特定配置
if(WIN32)
    target_link_libraries(financial_crypto PRIVATE advapi32)
endif()

# 安装配置
install(TARGETS financial_crypto financial_crypto_static
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

install(FILES include/financial_crypto.h DESTINATION include)
