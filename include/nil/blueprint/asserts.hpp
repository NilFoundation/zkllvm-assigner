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

#ifndef ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_ASSERTS_HPP_
#define ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_ASSERTS_HPP_

#include <iostream>
#include <cstring>
#include <string>

#define UNREACHABLE(msg) ::nil::blueprint::unreachable((msg), __FILE__, __LINE__)

#define ASSERT(expr) ::nil::blueprint::assert_check((expr), #expr, __FILE__, __LINE__)

#define ASSERT_MSG(expr, msg) ::nil::blueprint::assert_check((expr), #expr, __FILE__, __LINE__, (msg))

#define TODO(msg) ::nil::blueprint::todo((msg), __FILE__, __LINE__)

#define TODO_WITH_LINK(msg, link) ::nil::blueprint::todo_with_link((msg), (link), __FILE__, __LINE__)

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

        [[noreturn]] void unreachable(const std::string &msg, const char *filename, unsigned line) {
            unreachable(msg.c_str(),filename, line);
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

        [[noreturn]] void todo(const char *msg, const char *filename, unsigned line) {
            std::cerr << "NOT YET IMPLEMENTED at " << filename << ":" << line << std::endl;
            std::cerr << '\t' << msg << std::endl;
            abort_process();
        }

        [[noreturn]] void todo_with_link(const char *msg, const char *link, const char *filename, unsigned line) {
            std::string new_msg(msg);
            new_msg += "\n\tTracking issue: ";
            new_msg += link;
            todo(new_msg.c_str(), filename, line);
        }

        [[noreturn]] void todo_with_link(const std::string &msg, const std::string &link, const char *filename, unsigned line) {
            todo_with_link(msg.c_str(), link.c_str(), filename, line);
        }
    }
}

#endif  // ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_ASSERTS_HPP_
