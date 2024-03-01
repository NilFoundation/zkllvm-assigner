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
// @file This file defines segment map, which maps non-overlapping segments
// into arbitrary data.
//---------------------------------------------------------------------------//

#ifndef ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_MEM_SEGMENT_MAP_HPP_
#define ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_MEM_SEGMENT_MAP_HPP_

#include <nil/blueprint/mem/layout.hpp>
#include <nil/blueprint/mem/segment.hpp>

#include <nil/blueprint/asserts.hpp>
#include <nil/blueprint/var_concat.hpp>
#include <nil/blueprint/var_trim.hpp>

#include <algorithm>
#include <map>
#include <optional>

namespace nil {
    namespace blueprint {
        namespace mem {
            /**
             * @brief Map from non-overlapping segments to arbitrary associated values.
             *
             * @tparam T the type of value, associated with segment
             */
            template<typename T>
            struct segment_map {
            public:
                /**
                 * @brief Insert segment into the map.
                 *
                 * At the same moment override existing segments to maintain invariant of "non-overlapping ness".
                 *
                 * @param seg segment to insert
                 * @param value value associated with new segment
                 */
                void insert(segment seg, T value) {
                    // Idea:
                    // 1. find all segments which intersect with given
                    // 2. trim or delete them
                    // 3. insert given segment

                    std::map<segment, T> intersections = find_intersections(seg);
                    // at this point `intersections` is a complete set of segments which somehow
                    // intersect with `seg`

                    // now we delete overwritten segments and update trimmed segments
                    for (const auto& elem : intersections) {
                        segment existing = elem.first;
                        T existing_value = elem.second;

                        // existing segment won't stay in the map anyway
                        segment_tree.erase(existing);

                        if (seg.contains(existing)) {
                            // if new segment covers existing one completly, it has to be removed
                            // nothing needed to be done after it was removed
                            // new segment:           |--|--|--|--|--|--|--|
                            // existing segment:            |--|--|--|--|
                            // we are done with this existing segment, go to next one:
                            continue;
                        }

                        // if new segment only intersects with existing one, latter has to be trimmed
                        // and there are three cases how it can happen
                        if (existing.pointer < seg.pointer &&
                            existing.pointer + existing.size <= seg.pointer + seg.size) {
                            // new segment:                 |--|--|--|--|--|--|
                            // existing segment:      |--|--|--|--|--|
                            segment trimmed = existing;
                            trimmed.size = seg.pointer - existing.pointer;
                            T trimmed_value = trimmer_.trim(existing_value, 0, trimmed.size);
                            segment_tree.insert({trimmed, trimmed_value});
                        } else if (existing.pointer < seg.pointer) {
                            // new segment:                 |--|--|--|--|--|
                            // existing segment:      |--|--|--|--|--|--|--|--|
                            segment left = existing;
                            left.size = seg.pointer - existing.pointer;
                            T left_trimmed_value = trimmer_.trim(existing_value, 0, left.size);
                            segment_tree.insert({left, left_trimmed_value});

                            segment right = existing;
                            right.pointer = seg.pointer + seg.size;
                            right.size = existing.pointer + existing.size - right.pointer;
                            T right_trimmed_value =
                                trimmer_.trim(existing_value, right.pointer, right.pointer + right.size);
                            segment_tree.insert({right, right_trimmed_value});
                        } else {
                            // new segment:         |--|--|--|--|--|--|
                            // existing segment:          |--|--|--|--|--|
                            segment trimmed = existing;
                            trimmed.pointer = seg.pointer + seg.size;
                            trimmed.size = existing.pointer + existing.size - trimmed.pointer;
                            T trimmed_value =
                                trimmer_.trim(existing_value, trimmed.pointer, trimmed.pointer + trimmed.size);
                            segment_tree.insert({trimmed, trimmed_value});
                        }
                    }

                    // at this point we handled all segmnets intersecting with `seg` and now
                    // we are ready to insert it
                    segment_tree.insert({seg, value});

                    // TODO: optimize this implementation (please!)
                }

                /**
                 * @brief Get value representing given segment.
                 *
                 * If segment is out of allocated memory, function aborts.
                 *
                 * @param seg segment to lookup
                 */
                T get(segment seg) {
                    // Idea:
                    // 1. find segment X which holds given pointer
                    // 2. if none throw ERROR: access to unallocated mem
                    // 3. handle easy case: if pointers and sizes are equal, return T
                    // 4. if `seg` is a subsegment of X, generate new T for slice and return it
                    // 5. else: cross-segment access (slowest case, leave for now)

                    std::optional<segment> opt_seg = find_segment(seg.pointer);
                    if (!opt_seg.has_value()) {
                        UNREACHABLE("pointer to uninitialized value");
                    }
                    segment found_seg = opt_seg.value();

                    if (found_seg == seg) {
                        return segment_tree.operator[](found_seg);
                    }

                    if (found_seg.contains(seg)) {
                        // TODO: here we need to recalculate T for a subsegment
                        // for now we return it as it is
                        return segment_tree.operator[](found_seg);
                    }

                    // cross-segment access:
                    TODO("cross-segment access at load");

                    // TODO: implement cross-segment access
                    // TODO: recalculate new T for subsegment access and cross-segment access
                    // TODO: maybe this function should return `std::option<T>`, so no value
                    //       case can be handled outside this container?
                    //       Alternatively, we can return uninitialized `T()`.
                    // TODO: maybe this function should return `std::vector<T>` and return a
                    //       number of values, when multiple stored segments are requested?
                }

                void set_trimmer(VarTrim<T> trimmer) {
                    trimmer_ = trimmer;
                }

                void set_concatenator(VarConcat<T> concatenator) {
                    concatenator_ = concatenator;
                }

                /// @brief Find segment containing given pointer, if some.
                std::optional<segment> find_segment(ptr_type ptr) {
                    // very dummy search iterating over all elements

                    auto contains = [&ptr](std::pair<segment, T> elem) { return elem.first.contains(ptr); };
                    auto elem = std::find_if(segment_tree.begin(), segment_tree.end(), contains);
                    if (elem == segment_tree.end()) {
                        return std::nullopt;
                    }
                    return std::make_optional(elem->first);

                    // TODO: replace with more efficient binary search
                    // TODO: cache. We also can speed up lookup with having a `map<ptr, segment>`
                }

                /// @brief Get a map of segments intersecting with given one.
                std::map<segment, T> find_intersections(segment seg) {
                    std::map<segment, T> intersections;
                    auto intersects = [&seg](std::pair<segment, T> elem) { return elem.first.intersects(seg); };
                    std::copy_if(segment_tree.begin(), segment_tree.end(),
                                 std::inserter(intersections, intersections.end()), intersects);
                    return intersections;
                }

                /// @brief Get a map of segments contained by given one.
                std::map<segment, T> find_contained(segment seg) {
                    std::map<segment, T> contained;
                    auto contains = [&seg](std::pair<segment, T> elem) { return seg.contains(elem.first); };
                    std::copy_if(segment_tree.begin(), segment_tree.end(),
                                 std::inserter(contained, contained.end()), contains);
                    return contained;
                }

            private:
                std::map<segment, T> segment_tree;
                // TODO: we can use bare binary tree here to possibly optimize all access operations

                VarTrim<T> trimmer_;
                VarConcat<T> concatenator_;
            };
        }    // namespace mem
    }        // namespace blueprint
}    // namespace nil

#endif    // ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_MEM_SEGMENT_MAP_HPP_
