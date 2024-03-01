#define BOOST_TEST_MODULE memory_program_memory_test

#include <boost/test/unit_test.hpp>
#include <nil/blueprint/mem/layout.hpp>
#include <nil/blueprint/mem/memory.hpp>

using namespace nil::blueprint::mem;

BOOST_AUTO_TEST_SUITE(memory_program_memory_suite)

BOOST_AUTO_TEST_CASE(memory_program_memory_simple_test) {
    using value_type = int;

    program_memory<value_type> mem;
    value_type value = 42;
    size_type value_size = 4;

    ptr_type ptr = mem.stack_alloca(value_size);
    mem.store(ptr, value_size, value);
    value_type load_result = mem.load(ptr, value_size);

    BOOST_TEST(load_result == value);
}

BOOST_AUTO_TEST_SUITE_END()
