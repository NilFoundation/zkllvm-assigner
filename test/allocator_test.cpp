#define BOOST_TEST_MODULE allocator_test

#include <boost/test/unit_test.hpp>
#include <nil/blueprint/mem/allocator.hpp>
#include <nil/blueprint/mem/segment.hpp>
#include <nil/blueprint/mem/segment_map.hpp>

using namespace nil::blueprint::mem;

BOOST_AUTO_TEST_SUITE(allocator_suite)

BOOST_AUTO_TEST_CASE(malloc) {
    segment_map<int> storage;
    allocator<int> alloc(storage);

    BOOST_TEST(alloc.malloc(0) == NULL_PTR);

    ptr_type ptr = alloc.malloc(16);

    // Now lets use allocated memory and store array [1, 2, 3, 4]
    storage.insert(segment(ptr, 4), 1);
    storage.insert(segment(ptr + 4, 4), 2);
    storage.insert(segment(ptr + 8, 4), 3);
    storage.insert(segment(ptr + 12, 4), 4);

    BOOST_TEST(storage.get(segment(ptr, 4)) == 1);
    BOOST_TEST(storage.get(segment(ptr + 4, 4)) == 2);
    BOOST_TEST(storage.get(segment(ptr + 8, 4)) == 3);
    BOOST_TEST(storage.get(segment(ptr + 12, 4)) == 4);

    // Change value of array[3]
    storage.insert(segment(ptr + 8, 4), 42);

    BOOST_TEST(storage.get(segment(ptr, 4)) == 1);
    BOOST_TEST(storage.get(segment(ptr + 4, 4)) == 2);
    BOOST_TEST(storage.get(segment(ptr + 8, 4)) == 42);
    BOOST_TEST(storage.get(segment(ptr + 12, 4)) == 4);

    alloc.free(ptr);
}

BOOST_AUTO_TEST_CASE(realloc) {
    segment_map<int> storage;
    allocator<int> alloc(storage);

    ptr_type ptr = alloc.realloc(NULL_PTR, 4);
    storage.insert(segment(ptr, 4), 1);

    BOOST_TEST(storage.get(segment(ptr, 4)) == 1);

    ptr = alloc.realloc(ptr, 8);
    storage.insert(segment(ptr + 4, 4), 2);

    BOOST_TEST(storage.get(segment(ptr, 4)) == 1);
    BOOST_TEST(storage.get(segment(ptr + 4, 4)) == 2);

    ptr_type _placeholder = alloc.malloc(1);

    ptr = alloc.realloc(ptr, 12);
    storage.insert(segment(ptr + 8, 4), 3);

    BOOST_TEST(storage.get(segment(ptr, 4)) == 1);
    BOOST_TEST(storage.get(segment(ptr + 4, 4)) == 2);
    BOOST_TEST(storage.get(segment(ptr + 8, 4)) == 3);

    alloc.free(ptr);
    alloc.free(_placeholder);
}

BOOST_AUTO_TEST_CASE(calloc) {
    segment_map<int> storage;
    allocator<int> alloc(storage);

    ptr_type ptr = alloc.calloc(2, 4);
    BOOST_TEST(storage.get(segment(ptr, 4)) == 0);
    BOOST_TEST(storage.get(segment(ptr + 4, 4)) == 0);

    storage.insert(segment(ptr, 4), 1);
    storage.insert(segment(ptr + 4, 4), 2);

    BOOST_TEST(storage.get(segment(ptr, 4)) == 1);
    BOOST_TEST(storage.get(segment(ptr + 4, 4)) == 2);

    alloc.free(ptr);
}

BOOST_AUTO_TEST_SUITE_END()
