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
// @file This file defines memory segments, used in assigner memory model, and
// segment map, which maps segments into arbitrary data.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ASSIGNER_MEM_SEGMENT_MAP_HPP
#define CRYPTO3_ASSIGNER_MEM_SEGMENT_MAP_HPP

#include <algorithm>
#include <map>
#include <optional>

#include <nil/blueprint/mem/layout.hpp>
#include <nil/blueprint/mem/segment.hpp>
#include <nil/blueprint/mem/var.hpp>

namespace nil {
    namespace blueprint {
        namespace mem {
            /*
             * Map from segments to arbitrary associated values.
             *
             * This structure guarantees to store non-overlapping segments.
             *
             * We use red-black tree here to enhance the lookup by pointer proccess.
             */
            template<typename VarType>
            struct segment_map : std::map<segment, var<VarType>> {
                using var_type = var<VarType>;

                using typename std::map<segment, var_type>::iterator;
                using typename std::map<segment, var_type>::value_type;

            public:
                segment_map() {
                }

                /// Find segment containing given pointer, if some.
                std::optional<segment> find_segment(ptr_type ptr) {
                    // very dummy search
                    // TODO: replace with optimized binary search
                    // We also can speed up lookup with having a `map<ptr, segment>`

                    auto contains = [&ptr](std::pair<segment, var_type> elem) { return elem.first.contains(ptr); };
                    auto elem = std::find_if(this->begin(), this->end(), contains);
                    if (elem == this->end()) {
                        return std::nullopt;
                    }
                    return std::make_optional(elem->first);
                }

                std::pair<iterator, bool> insert(const value_type& value) {
                    auto ret = std::map<segment, var_type>::insert(value);
                    // TODO: ensure non-overlappingness of segments:
                    // `var_type` must have split interface to handle cases when we are inserting
                    // segment which overlaps with existing ones.
                    return ret;
                }
            };
        }    // namespace mem
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_ASSIGNER_MEM_SEGMENT_MAP_HPP
