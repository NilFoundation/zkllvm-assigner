//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ASSIGNER_NIL_BLUEPRINT_ASSERTS_HPP
#define CRYPTO3_ASSIGNER_NIL_BLUEPRINT_ASSERTS_HPP

#include <iostream>
#include <cstring>

#define UNREACHABLE(msg) ::nil::blueprint::unreachable((msg), __FILE__, __LINE__)

#define ASSERT(expr) ::nil::blueprint::assert_check((expr), #expr, __FILE__, __LINE__)

#define ASSERT_MSG(expr, msg) ::nil::blueprint::assert_check((expr), #expr, __FILE__, __LINE__, (msg))

namespace nil {
    namespace blueprint {
        [[noreturn]] void abort_process() {
            std::abort();
        }

        [[noreturn]] void unreachable(const char *msg, const char *filename, unsigned line) {
            std::cerr << "UNREACHABLE at " << filename << ":" << line << std::endl;
            std::cerr <<'\t' << msg << std::endl;
            abort_process();
        }

        void assert_check(bool expr, const char *expr_str, const char *filename, unsigned line, const char *msg = "") {
            if (!expr) {
                std::cerr << "Assertion failed at " << filename << ":" << line << ":" << std::endl;
                std::cerr << '\t' << expr_str;
                if (strlen(msg) != 0) {
                    std::cerr << " -> " << msg;
                }
                std::cerr << std::endl;
                abort_process();
            }
        }
    }
}

#endif  // CRYPTO3_ASSIGNER_NIL_BLUEPRINT_ASSERTS_HPP
