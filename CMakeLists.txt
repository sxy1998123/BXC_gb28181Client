cmake_minimum_required(VERSION 3.10.2)
project(BXC_gb28181Client)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(CMAKE_BUILD_TYPE DEBUG)
SET(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g -ggdb")
SET(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall")

set(INCLUDE_DIR /usr/local/include)
set(LIB_DIR /usr/local/lib)


include_directories(${INCLUDE_DIR})
link_directories(${LIB_DIR})

find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)

add_executable(BXC_gb28181Client
        Utils/MD5.c
        Utils/HTTPDigest.c
        SipClient.cpp
        main.cpp
        )

TARGET_LINK_DIRECTORIES(BXC_gb28181Client PRIVATE ${CJSON_INCLUDE_DIR})

TARGET_LINK_LIBRARIES(BXC_gb28181Client osip2 osipparser2 eXosip2 pthread OpenSSL::Crypto -lcjson ${CURL_LIBRARIES})






