cmake_minimum_required(VERSION 3.16)
project(MySQLBackendProject)

set(CMAKE_CXX_STANDARD 17)

# 添加 MySQL Connector/C++ 头文件路径
include_directories(/usr/include/mysql /usr/include/cppconn)

# 添加源文件
add_executable(MySQLBackendProject src/main.cpp)

# 查找并链接 MySQL Connector/C++ 库
find_library(MYSQLCPP_LIB mysqlcppconn)
target_link_libraries(MySQLBackendProject ${MYSQLCPP_LIB})

# 连接 OpenSSL 库（MySQL Connector 可能依赖于此）
find_package(OpenSSL REQUIRED)
target_link_libraries(MySQLBackendProject OpenSSL::SSL OpenSSL::Crypto)

