#---------------------------------------------------------------------------#
# Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
# Copyright (c) 2022 Aleksei Moskvin <alalmoskvin@gmail.com>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

include(CMTest)

cm_test_link_libraries(${CMAKE_WORKSPACE_NAME}_${CURRENT_PROJECT_NAME}

                       crypto3::all
                       LLVMIRReader
                       LLVMCore
                       LLVMSupport

                       ${Boost_LIBRARIES})

macro(define_assigner_test test)
    string(REPLACE "/" "_" full_test_name zkllvm_assigner_${test})

    cm_test(NAME ${full_test_name} SOURCES ${test}.cpp)

    target_include_directories(${full_test_name} PRIVATE
                               "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
                               "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>"
                               ${CMAKE_CURRENT_SOURCE_DIR}/../../circifier/llvm/include
                               ${CMAKE_BINARY_DIR}/libs/circifier/llvm/include

                               ${Boost_INCLUDE_DIRS})

    set_target_properties(${full_test_name} PROPERTIES CXX_STANDARD 17)

    if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        target_compile_options(${full_test_name} PRIVATE "-fconstexpr-steps=2147483647")
    elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(${full_test_name} PRIVATE "-fconstexpr-ops-limit=4294967295")
    endif()

    get_target_property(target_type Boost::unit_test_framework TYPE)
    if(target_type STREQUAL "SHARED_LIB")
        target_compile_definitions(${full_test_name} PRIVATE BOOST_TEST_DYN_LINK)
    elseif(target_type STREQUAL "STATIC_LIB")

    endif()
endmacro()

SET(ALL_TESTS_FILES
    "signature_parser_test"
    "input_reader_test"
    )

foreach(TEST_FILE ${ALL_TESTS_FILES})
    define_assigner_test(${TEST_FILE})
endforeach()

target_compile_definitions(zkllvm_assigner_input_reader_test PRIVATE IR_FILE="${CMAKE_CURRENT_SOURCE_DIR}/ir/input_reader_test.ll")
