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
// @file This file defines memory segments, used in assigner memory model.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ASSIGNER_MEM_SEGMENT_HPP
#define CRYPTO3_ASSIGNER_MEM_SEGMENT_HPP

#include <iostream>
#include <sstream>

#include <boost/format.hpp>

#include <nil/blueprint/asserts.hpp>
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

                segment() = default;

                segment(ptr_type pointer, size_type size) : pointer(pointer), size(size) {
                }

                segment(const segment& other) {
                    pointer = other.pointer;
                    size = other.size;
                }

                bool operator==(const segment& other) const {
                    return ((this->pointer == other.pointer) && (this->size == other.size));
                }

                bool operator!=(const segment& other) const {
                    return !operator==(other);
                }

                bool operator<(const segment& other) const {
                    return (this->pointer + size <= other.pointer);
                }

                bool operator>(const segment& other) const {
                    return (other.pointer + other.size <= this->pointer);
                }

                /// Return printable view of the segment.
                std::string print_string() const {
                    std::stringstream buffer;
                    buffer << boost::format("0x%016x+%08x") % this->pointer % this->size;
                    return buffer.str();
                }

                /// Whether this segment contains given pointer or not.
                bool contains(ptr_type ptr) const {
                    return ((pointer <= ptr) && (pointer + size > ptr));
                }

                /// Whether given segment is a subsegment of this segment or not.
                bool contains(segment& other) const {
                    return ((pointer <= other.pointer) && (pointer + size >= other.pointer + other.size));
                }

                /// Whether this segment intersects with other segment.
                bool intersects(segment& other) const {
                    return !((*this < other) || (*this > other));
                }
            };

            std::ostream& operator<<(std::ostream& out, segment const& seg) {
                return out << seg.print_string();
            }
        }    // namespace mem
    }        // namespace blueprint
}    // namespace nil

namespace nil {
    namespace blueprint {
        namespace mem {
            namespace tests {
                void test_segment_equality() {
                    segment a(0, 4);
                    segment b;
                    b.pointer = 0;
                    b.size = 4;
                    segment c(0, 8);
                    ASSERT(a == b);
                    ASSERT(a != c);
                }

                void test_segment_compare() {
                    segment a(0, 4);
                    segment b(4, 4);
                    segment c(0, 8);
                    ASSERT(a < b);
                    ASSERT(b > a);
                    ASSERT(!(a < c));
                }

                void test_segment_contains() {
                    segment a(0, 4);
                    ASSERT(a.contains(0));
                    ASSERT(a.contains(1));
                    ASSERT(!a.contains(4));
                }

                void test_segment_contains_segment() {
                    segment a(0, 4);
                    segment b(1, 2);
                    segment c(0, 5);
                    ASSERT(a.contains(b));
                    ASSERT(!a.contains(c));
                }

                void test_segment_intersects() {
                    segment a(0, 4);
                    segment b(0, 16);
                    segment c(4, 4);
                    ASSERT(a.intersects(b));
                    ASSERT(!a.intersects(c));
                    ASSERT(b.intersects(c));
                }

                void test_segment_print_string() {
                    segment a(0xffffffff00000000, 0xaaaaaaaa);
                    ASSERT(a.print_string() == std::string("0xffffffff00000000+aaaaaaaa"));
                }
            }    // namespace tests
        }        // namespace mem
    }            // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_ASSIGNER_MEM_SEGMENT_HPP
