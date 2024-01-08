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
// @file This file defines variable representation in assigner memory.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ASSIGNER_MEM_VAR_HPP
#define CRYPTO3_ASSIGNER_MEM_VAR_HPP

#include <nil/blueprint/mem/layout.hpp>

namespace nil {
    namespace blueprint {
        namespace mem {
            /*
             * Representation of a variable in memory.
             *
             * This is essentially a slice of an arbitrary type `VarType` with `[start:end)` bytes
             * of real variable included.
             */
            template<typename VarType>
            struct var {
                VarType value;
                /// Start of the slice.
                size_type start;
                /// End of the slice.
                size_type end;

                var() {
                }

                var(VarType value, size_type size) : value(value), start(0), end(size) {
                }

                var(VarType value, size_type start, size_type end) : value(value), start(start), end(end) {
                }

                /*
                 * Slice this var at given offset, returning left and right parts:
                 *
                 * `[start;offset)` and `[offset;end)`
                 */
                std::pair<var, var> slice_at(size_type offset) {
                    // TODO: check offset to be in [start;end)
                    return std::make_pair(var(value, start, offset), var(value, offset, end));
                }
            };
        }    // namespace mem
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_ASSIGNER_MEM_VAR_HPP
