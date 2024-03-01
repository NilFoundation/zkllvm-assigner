#define BOOST_TEST_MODULE memory_segment_map_test

#include <boost/test/unit_test.hpp>
#include <nil/blueprint/mem/segment.hpp>
#include <nil/blueprint/mem/segment_map.hpp>

using namespace nil::blueprint::mem;

BOOST_AUTO_TEST_SUITE(memory_segment_map_suite)

BOOST_AUTO_TEST_CASE(memory_segment_map_insert_get) {
    segment_map<int> m;
    // (we show associated values in segments to illustrate the idea)
    // |--|--|--|--|--|--|--|--|--|--|--|--|...

    m.insert(segment(0, 4), 1);
    // |11|11|11|11|--|--|--|--|--|--|--|--|...

    m.insert(segment(5, 2), 2);
    // |11|11|11|11|--|22|22|--|--|--|--|--|...

    m.insert(segment(0, 1), 3);    // cuts 0+4 to 1+3
    // |33|11|11|11|--|22|22|--|--|--|--|--|...

    m.insert(segment(0, 2), 4);    // deletes 0+1 and cuts 1+3 to 2+2
    // |44|44|11|11|--|22|22|--|--|--|--|--|...

    m.insert(segment(3, 3), 5);    // cuts 2+2 to 2+1 and 5+2 to 6+1
    // |44|44|11|55|55|55|22|--|--|--|--|--|...

    BOOST_TEST(m.get(segment(0, 2)) == 4);
    BOOST_TEST(m.get(segment(2, 1)) == 1);
    BOOST_TEST(m.get(segment(3, 3)) == 5);
    BOOST_TEST(m.get(segment(6, 1)) == 2);
}

BOOST_AUTO_TEST_CASE(memory_segment_partial_get) {
    segment_map<int> m;
    m.insert(segment(0, 4), 42);
    BOOST_TEST(m.get(segment(0, 4)) == 42);
    // this is wrong and must be fixed!
    // leaving it here just to make sure the behaviour is predictable
    BOOST_TEST(m.get(segment(1, 3)) == 42);
}

BOOST_AUTO_TEST_SUITE_END()
