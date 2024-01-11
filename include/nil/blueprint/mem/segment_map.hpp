//---------------------------------------------------------------------------//
// Copyright (c) 2023 Alexander Evgin <aleasims@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//
// @file This file defines segment map, which maps segments into arbitrary data.
// This structure is used as heap memory storage in assigner memory model.
//---------------------------------------------------------------------------//

#ifndef NIL_BLUEPRINT_MEM_SEGMENT_MAP_HPP
#define NIL_BLUEPRINT_MEM_SEGMENT_MAP_HPP

#include <algorithm>
#include <map>
#include <optional>

#include <nil/blueprint/asserts.hpp>
#include <nil/blueprint/mem/layout.hpp>
#include <nil/blueprint/mem/segment.hpp>

namespace nil {
    namespace blueprint {
        namespace mem {
            /**
             * @brief Map from segments to arbitrary associated values.
             *
             * This structure guarantees to store non-overlapping segments.
             *
             * @tparam Value the type of value, associated with segment
             */
            template<typename Value>
            struct segment_map : std::map<segment, Value> {
                using typename std::map<segment, Value>::iterator;
                using typename std::map<segment, Value>::value_type;

            public:
                segment_map() {
                }

                /**
                 * @brief Insert segment into the map.
                 *
                 * At the same moment override existing segments to maintain invariant of "non-overlapping ness".
                 *
                 * @param seg segment to insert
                 * @param value value associated with new segment
                 */
                void insert(segment seg, Value value) {
                    // Idea:
                    // 1. find all segments which intersect with given
                    // 2. strip or delete them
                    // 3. insert given segment

                    auto intersects = [&seg](std::pair<segment, Value> elem) { return elem.first.intersects(seg); };
                    std::map<segment, Value> intersections;
                    std::copy_if(this->begin(), this->end(), std::inserter(intersections, intersections.end()),
                                 intersects);
                    // at this point `intersections` is a complete set of segments which somehow
                    // intersect with `seg`

                    // now we delete overwritten segments and cut splitted segments
                    for (const auto& elem : intersections) {
                        segment existing = elem.first;
                        Value value = elem.second;

                        if (seg.contains(existing)) {
                            // if new segment covers existing one completly, it has to be removed
                            // new segment:           |--|--|--|--|--|--|--|
                            // existing segment:            |--|--|--|--|
                            this->erase(existing);
                        } else {
                            // if new segment only intersects with existing one, latter has to be cut
                            segment stripped_segment = existing;
                            if (existing.pointer < seg.pointer) {
                                // new segment:                 |--|--|--|--|--|--|
                                // existing segment:      |--|--|--|--|--|
                                stripped_segment.size = (size_type)(seg.pointer - existing.pointer);
                            } else {
                                // new segment:         |--|--|--|--|--|--|
                                // existing segment:          |--|--|--|--|--|
                                stripped_segment.pointer = seg.pointer + (ptr_type)seg.size;
                                stripped_segment.size =
                                    existing.pointer + (ptr_type)existing.size - stripped_segment.pointer;
                            }

                            // we delete existing segment and insert stripped one instead
                            this->erase(existing);
                            std::map<segment, Value>::insert({stripped_segment, value});
                        }
                    }
                    // at this point we handled all segmnets intersecting with `seg` and now
                    // we are ready to insert it
                    std::map<segment, Value>::insert({seg, value});

                    // TODO: optimize this implementation (please!)
                    // TODO: recalculate new Value when cutting segments (for now we leave it as it is)
                }

                /**
                 * @brief Get value representing given segment.
                 *
                 * If segment is out of allocated memory, function aborts.
                 *
                 * @param seg segment to lookup
                 */
                Value get(segment seg) {
                    // Idea:
                    // 1. find segment X which holds given pointer
                    // 2. if none throw ERROR: access to unallocated mem
                    // 3. handle easy case: if pointers and sizes are equal, return Value
                    // 4. if `seg` is a subsegment of X, generate new Value for slice and return it
                    // 5. else: cross-segment access (slowest case, leave for now)

                    std::optional<segment> opt_seg = find_segment(seg.pointer);
                    if (!opt_seg.has_value()) {
                        UNREACHABLE("pointer out of allocated memory");
                    }
                    segment found_seg = opt_seg.value();

                    if (found_seg == seg) {
                        return this->operator[](found_seg);
                    }

                    if (found_seg.contains(seg)) {
                        // TODO: here we need to recalculate Value for a subsegment
                        // for now we return it as it is
                        return this->operator[](found_seg);
                    }

                    // cross-segment access:
                    UNREACHABLE("cross-segment access is not yet implemented");

                    // TODO: implement cross-segment access
                    // TODO: recalculate new Value for subsegment access and cross-segment access
                }

                /// Find segment containing given pointer, if some.
                std::optional<segment> find_segment(ptr_type ptr) {
                    // very dummy search iterating over all elements

                    auto contains = [&ptr](std::pair<segment, Value> elem) { return elem.first.contains(ptr); };
                    auto elem = std::find_if(this->begin(), this->end(), contains);
                    if (elem == this->end()) {
                        return std::nullopt;
                    }
                    return std::make_optional(elem->first);

                    // TODO: replace with more efficient binary search
                    // TODO: cache. We also can speed up lookup with having a `map<ptr, segment>`
                }

                // TODO: maybe instead of creating new functions we should overload something to
                // provide consistency: so one cannot create invalid state of segment map manually.
                // Right now you can break the invariant like this: `m[seg] = anything;`
            };
        }    // namespace mem
    }        // namespace blueprint
}    // namespace nil

namespace nil {
    namespace blueprint {
        namespace mem {
            namespace tests {
                void test_segment_map_insert() {
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

                    ASSERT(m.size() == 4);
                    ASSERT(m[segment(0, 2)] == 4);
                    ASSERT(m[segment(2, 1)] == 1);
                    ASSERT(m[segment(3, 3)] == 5);
                    ASSERT(m[segment(6, 1)] == 2);
                }

                void test_segment_map_get() {
                    segment_map<int> m;
                    m.insert(segment(0, 4), 42);
                    ASSERT(m.get(segment(0, 4)) == 42);
                    ASSERT(m.get(segment(1, 3)) == 42);   // this will be fixed!
                }
            }    // namespace tests
        }        // namespace mem
    }            // namespace blueprint
}    // namespace nil

#endif    // NIL_BLUEPRINT_MEM_SEGMENT_MAP_HPP
