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
#include <vector>
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

                allocator(storage_type& storage) : storage(storage) {
                    empty_regions.emplace_back(HEAP_BOTTOM, PTR_MAX);
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
                 *
                 * @return pointer to allocated memory
                 */
                ptr_type malloc(size_type size) {
                    if (size == 0) {
                        return NULL_PTR;
                    }

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

                /**
                 * @brief Allocate given number of objects of given size and return pointer to new allocation.
                 *
                 * This function also initializes these objects with "zero" value.
                 *
                 * @param num number of objects
                 * @param size size of objects
                 *
                 * @return pointer to allocated memory
                 */
                ptr_type calloc(size_type num, size_type size) {
                    if (size == 0) {
                        return NULL_PTR;
                    }

                    if (num == 0) {
                        return NULL_PTR;
                        // FIXME: not sure this is correct, but for now let it be so.
                    }

                    size_type total_size = num * size;
                    // FIXME: not sure this check must be done
                    // But since we use `size_type` for all allocation sizes, we cannot allocate
                    // more than `size_type::max()`.
                    if (total_size / size != num) {
                        // Overflow handling
                        return NULL_PTR;
                    }

                    auto it = find_empty_region(total_size);

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

                    // Initialize allocated memory with zeros
                    for (size_type i = 0; i < num; ++i) {
                        // FIXME: right now we don't have a stable interface to create "zero" variable
                        VarType val = VarType();

                        segment seg(ptr + i * size, size);
                        storage.insert(seg, val);
                    }

                    // Create allocation record
                    allocations[ptr] = size;

                    return ptr;
                }

                /**
                 * @brief Re-allocate given area of memory to new size.
                 *
                 * @param ptr pointer to reallocate
                 * @param new_size new size of the allocation
                 *
                 * @return pointer to re-allocated memory (may be different from `ptr`)
                 */
                ptr_type realloc(ptr_type ptr, size_type new_size) {
                    if (ptr == NULL_PTR) {
                        return malloc(new_size);
                    }

                    if (new_size == 0) {
                        // TODO: do we want to free `ptr` here?
                        return NULL_PTR;
                    }

                    size_type current_size = allocations[ptr];

                    if (new_size == current_size) {
                        // No changes are needed
                        return ptr;
                    }

                    // Find first region after existing allocation
                    auto next = [&ptr](region reg) { return (reg.start > ptr); };
                    std::list<region>::iterator reg = std::find_if(empty_regions.begin(), empty_regions.end(), next);

                    if (new_size < current_size) {
                        // Trim existing allocation

                        // Mark trimmed region as empty
                        if (reg != empty_regions.end()) {
                            // Current allocation is the maximum possible
                            empty_regions.push_back(region(ptr + new_size, PTR_MAX));
                        } else {
                            reg->start = ptr + new_size;
                        }

                        // Update allocation record
                        allocations[ptr] = new_size;

                        return ptr;
                    }

                    // Try to expand existing allocation

                    // In order for existing allocation to be expandable into this region, latter
                    // must be holding the whole extra part.
                    bool expand =
                        (reg != empty_regions.end()) &&          // current allocation is the max possible
                        (reg->start == ptr + current_size) &&    // after current allocation there is an empty space
                        (reg->end >= ptr + new_size - 1);        // this space is enough big to hold new allocation

                    if (!expand) {
                        // Create new allocation
                        ptr_type new_ptr = malloc(new_size);
                        if (new_ptr == NULL_PTR) {
                            return NULL_PTR;
                        }

                        // Find all segments lying within current allocation
                        segment current_seg(ptr, current_size);
                        auto contains = [&current_seg](std::pair<segment, VarType> elem) {
                            return current_seg.contains(elem.first);
                        };
                        std::vector<std::pair<segment, VarType>> segments_to_copy;
                        std::copy_if(storage.begin(), storage.end(),
                                     std::inserter(segments_to_copy, segments_to_copy.end()), contains);

                        // Copy all data from existing allocation to new one
                        // All the expanded part of new allocation is left uninitialized
                        std::int64_t diff = new_ptr - ptr;
                        for (auto& [seg, value] : segments_to_copy) {
                            seg.pointer += diff;
                            storage.insert(seg, value);
                        }

                        // Create a record for new allocation
                        allocations[new_ptr] = new_size;

                        // Free previous allocation
                        // TODO: we can optimize this, since we already found the next empty region
                        free(ptr);

                        return new_ptr;
                    }

                    // Shrink existing empty region (and delete it if needed)
                    reg->start = ptr + new_size;
                    if (reg->start == reg->end) {
                        empty_regions.erase(reg);
                    }

                    // Update allocation record
                    allocations[ptr] = new_size;

                    // No changes in storage are reqiured

                    return ptr;
                }

            private:
                /// @brief Pointer to the memory storage.
                storage_type& storage;

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
                void test_allocator_malloc() {
                    segment_map<int> storage;
                    allocator<int> alloc(storage);

                    ASSERT(alloc.malloc(0) == NULL_PTR);

                    ptr_type ptr = alloc.malloc(16);

                    // Now lets use allocated memory and store array [1, 2, 3, 4]
                    storage.insert(segment(ptr, 4), 1);
                    storage.insert(segment(ptr + 4, 4), 2);
                    storage.insert(segment(ptr + 8, 4), 3);
                    storage.insert(segment(ptr + 12, 4), 4);

                    ASSERT(storage[segment(ptr, 4)] == 1);
                    ASSERT(storage[segment(ptr + 4, 4)] == 2);
                    ASSERT(storage[segment(ptr + 8, 4)] == 3);
                    ASSERT(storage[segment(ptr + 12, 4)] == 4);

                    // Change value of array[3]
                    storage.insert(segment(ptr + 8, 4), 42);

                    ASSERT(storage[segment(ptr, 4)] == 1);
                    ASSERT(storage[segment(ptr + 4, 4)] == 2);
                    ASSERT(storage[segment(ptr + 8, 4)] == 42);
                    ASSERT(storage[segment(ptr + 12, 4)] == 4);

                    alloc.free(ptr);
                }

                void test_allocator_realloc() {
                    segment_map<int> storage;
                    allocator<int> alloc(storage);

                    ptr_type ptr = alloc.realloc(NULL_PTR, 4);
                    storage.insert(segment(ptr, 4), 1);

                    ASSERT(storage[segment(ptr, 4)] == 1);

                    ptr = alloc.realloc(ptr, 8);
                    storage.insert(segment(ptr + 4, 4), 2);

                    ASSERT(storage[segment(ptr, 4)] == 1);
                    ASSERT(storage[segment(ptr + 4, 4)] == 2);

                    ptr_type _placeholder = alloc.malloc(1);

                    ptr = alloc.realloc(ptr, 12);
                    storage.insert(segment(ptr + 8, 4), 3);

                    ASSERT(storage[segment(ptr, 4)] == 1);
                    ASSERT(storage[segment(ptr + 4, 4)] == 2);
                    ASSERT(storage[segment(ptr + 8, 4)] == 3);

                    alloc.free(ptr);
                    alloc.free(_placeholder);
                }

                void test_allocator_calloc() {
                    segment_map<int> storage;
                    allocator<int> alloc(storage);

                    ptr_type ptr = alloc.calloc(2, 4);
                    ASSERT(storage[segment(ptr, 4)] == 0);
                    ASSERT(storage[segment(ptr + 4, 4)] == 0);

                    storage.insert(segment(ptr, 4), 1);
                    storage.insert(segment(ptr + 4, 4), 2);

                    ASSERT(storage[segment(ptr, 4)] == 1);
                    ASSERT(storage[segment(ptr + 4, 4)] == 2);

                    alloc.free(ptr);
                }
            }    // namespace tests
        }        // namespace mem
    }            // namespace blueprint
}    // namespace nil

#endif    // NIL_BLUEPRINT_MEM_ALLOCATOR_HPP
