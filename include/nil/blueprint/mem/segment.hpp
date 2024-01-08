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

#ifndef CRYPTO3_ASSIGNER_MEM_SEGMENT_HPP
#define CRYPTO3_ASSIGNER_MEM_SEGMENT_HPP

#include <iostream>

#include <boost/format.hpp>

#include <nil/blueprint/mem/layout.hpp>

namespace nil {
    namespace blueprint {
        namespace mem {
            /// Segment of memory defined by pointer and size of segment in bytes.
            struct segment {
            public:
                /// Pointer.
                ptr_type pointer;
                /// Size in bytes.
                size_type size;

                segment() : pointer(0), size(0) {
                }

                segment(ptr_type pointer, size_type size) : pointer(pointer), size(size) {
                }

                /// Whether this segment contains given pointer or not.
                bool contains(ptr_type& ptr) const {
                    return ((pointer <= ptr) && (pointer + size > ptr));
                }

                bool operator==(const segment& other) const {
                    return ((this->pointer == other.pointer) && (this->size == other.size));
                }

                bool operator<(const segment& other) const {
                    return (this->pointer + size < other.pointer);
                }
            };

            std::ostream& operator<<(std::ostream& out, segment const& seg) {
                out << boost::format("0x%016x+%08x") % seg.pointer % seg.size;
                return out;
            }
        }    // namespace mem
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_ASSIGNER_MEM_SEGMENT_HPP
