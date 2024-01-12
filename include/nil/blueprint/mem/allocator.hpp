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

#ifndef NIL_BLUEPRINT_MEM_ALLOCATOR_HPP
#define NIL_BLUEPRINT_MEM_ALLOCATOR_HPP

#include <list>
#include <unordered_map>

#include <nil/blueprint/asserts.hpp>
#include <nil/blueprint/mem/layout.hpp>
#include <nil/blueprint/mem/segment.hpp>
#include <nil/blueprint/mem/segment_map.hpp>

namespace nil {
    namespace blueprint {
        namespace mem {
            /// @brief Region in memory `[start;end]`.
            struct region {
            public:
                ptr_type start;
                ptr_type end;
                region() = default;
                region(ptr_type start, ptr_type end) : start(start), end(end) {
                }
            };

            /// @brief Simple allocator.
            template<typename VarType>
            struct allocator {
            public:
                using storage_type = segment_map<VarType>;

                allocator(storage_type* storage) : storage(storage) {
                    this->empty_regions.emplace_back(HEAP_BOTTOM, PTR_MAX);
                }

                /**
                 * @brief Free allocation at given pointer.
                 *
                 * @param ptr pointer to allocation
                 */
                void free(ptr_type ptr) {
                    // We don't actually need to modify storage here, just update mappings.

                    size_type size = allocations[ptr];
                    ptr_type right = ptr - 1 + size;
                    region new_empty_region(ptr, right);

                    // Find a region, before which we need to insert new one.
                    auto greater = [&right](region reg) { return reg.start > right; };
                    auto it = std::find_if(empty_regions.begin(), empty_regions.end(), greater);
                    empty_regions.insert(it, new_empty_region);

                    // Now we need to merge adjacent regions.
                    auto first = empty_regions.begin();
                    auto second = empty_regions.begin();
                    second++;

                    for (; second != empty_regions.end(); first++, second++) {
                        if (first->end == second->start - 1) {
                            first->end = second->end;
                            second = empty_regions.erase(second);
                        }
                    }

                    // Remove the allocation record.
                    allocations.erase(ptr);
                }

                /**
                 * @brief Allocate given number of bytes and return pointer to new allocation.
                 *
                 * @param size number of bytes to allocate
                 */
                ptr_type malloc(size_type size) {
                    auto it = find_empty_region(size);

                    if (it == empty_regions.end()) {
                        // This simple allocator does not do any fancy stuff like defragmentation.
                        // For now we just don't allocate, if we run out of regions.
                        return NULL_PTR;
                    }

                    // Shrink this region, creating new allocation
                    ptr_type ptr = it->start;
                    it->start = ptr + size;
                    if (it->start == it->end) {
                        // Remove found regions if it was allocated completly.
                        empty_regions.erase(it);
                    }

                    // Store the allocation record
                    allocations[ptr] = size;

                    return ptr;
                }

                ptr_type calloc(unsigned n, size_type size) {
                    UNREACHABLE("not yet implemented");
                }

                /**
                 * @brief Re-allocate given area of memory to new size.
                 *
                 * @param ptr pointer to reallocate
                 * @param new_size new size of the allocation
                 */
                ptr_type realloc(ptr_type ptr, size_type new_size) {
                    if (ptr == NULL_PTR) {
                        return malloc(new_size);
                    }

                    UNREACHABLE("not yet implemented");
                }

                // This function will be removed. Used only for debug purposes for now.
                void dump_content_to_stdout() {
                    std::cout << "Allocation records:" << std::endl;
                    for (const auto& elem : allocations) {
                        std::cout << "  " << segment(elem.first, elem.second) << std::endl;
                    }
                    std::cout << "Empty regions:" << std::endl;
                    for (const auto& elem : empty_regions) {
                        std::cout << "  [0x" << std::hex << elem.start << ":0x" << elem.end << "]" << std::endl;
                    }
                }

            private:
                /// @brief Pointer to the memory storage.
                storage_type* storage;

                /// @brief Records about alive allocations.
                std::unordered_map<ptr_type, size_type> allocations;

                /// @brief List of unallocated regions in memory.
                std::list<region> empty_regions;

                /// @brief Find region big enough to hold allocation of `size` bytes.
                std::list<region>::iterator find_empty_region(size_type size) {
                    auto big_enough = [&size](region reg) { return (reg.end - reg.start >= size); };
                    return std::find_if(empty_regions.begin(), empty_regions.end(), big_enough);
                }
            };
        }    // namespace mem
    }        // namespace blueprint
}    // namespace nil

namespace nil {
    namespace blueprint {
        namespace mem {
            namespace tests {
                void test_allocator() {
                    segment_map<int> storage;
                    allocator<int> alloc(&storage);

                    ptr_type ptr = alloc.malloc(16);

                    // Now lets use allocated memory and store array [1, 2, 3, 4]
                    storage.insert(segment(ptr, 4), 1);
                    storage.insert(segment(ptr + 4, 4), 2);
                    storage.insert(segment(ptr + 8, 4), 3);
                    storage.insert(segment(ptr + 12, 4), 4);

                    // Change value of array[3]
                    storage[segment(ptr + 8, 4)] = 42;

                    ASSERT(storage[segment(ptr, 4)] == 1);
                    ASSERT(storage[segment(ptr + 4, 4)] == 2);
                    ASSERT(storage[segment(ptr + 8, 4)] == 42);
                    ASSERT(storage[segment(ptr + 12, 4)] == 4);

                    alloc.free(ptr);
                }
            }    // namespace tests
        }        // namespace mem
    }            // namespace blueprint
}    // namespace nil

#endif    // NIL_BLUEPRINT_MEM_ALLOCATOR_HPP
