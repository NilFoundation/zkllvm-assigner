//---------------------------------------------------------------------------//
// Copyright (c) 2024 Mikhail Aksenov <maksenov@nil.foundation>
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

#ifndef CRYPTO3_ASSIGNER_SIGNATURE_PARSER_HPP
#define CRYPTO3_ASSIGNER_SIGNATURE_PARSER_HPP

#include <string>
#include <vector>

namespace nil {
    namespace blueprint {
        enum class json_elem {
            UNDEFINED,
            FIELD,
            CURVE,
            ARRAY,
            STRUCT,
            VECTOR,
            INT,
            STRING,
            PALLAS_BASE,
            BLS12381_BASE,
            ED25519_BASE,
            PALLAS,
            BLS12381,
            ED25519,
        };

        struct signature_node {
            json_elem elem = json_elem::UNDEFINED;
            std::vector<signature_node> children;
            std::string_view type_string;
        };

        class signature_parser {
        public:
            bool parse(const std::string &str) {
                iter = str.begin();
                end_iter = str.end();
                if (recursion(tree) && iter == str.end()) {
                    return true;
                }
                return false;
            }

            const signature_node &get_tree() {
                return tree;
            }


        private:
            bool take_elem(signature_node &node) {
                // Skip whitespaces
                while (iter != end_iter && (*iter == ' ' || *iter == '\t')) {
                    ++iter;
                }
                auto begin = iter;
                size_t count = 0;
                while (iter != end_iter && ((*iter >= 'a' && *iter <= 'z') || *iter == '_')) {
                    ++count;
                    ++iter;
                }
                if (count == 0) {
                    return false;
                }
                std::string_view elem(&*begin, count);
                if (elem == "field") {
                    node.elem = json_elem::FIELD;
                } else if (elem == "curve") {
                    node.elem = json_elem::CURVE;
                } else if (elem == "array") {
                    node.elem = json_elem::ARRAY;
                } else if (elem == "struct") {
                    node.elem = json_elem::STRUCT;
                } else if (elem == "vector") {
                    node.elem = json_elem::VECTOR;
                } else if (elem == "int") {
                    node.elem = json_elem::INT;
                } else if (elem == "string") {
                    node.elem = json_elem::STRING;
                } else if (elem == "pallas_base") {
                    node.elem = json_elem::PALLAS_BASE;
                } else if (elem == "pallas") {
                    node.elem = json_elem::PALLAS;
                } else if (elem == "bls12381_base") {
                    node.elem = json_elem::BLS12381_BASE;
                } else if (elem == "bls12381") {
                    node.elem = json_elem::BLS12381;
                } else if (elem == "ed25519_base") {
                    node.elem = json_elem::ED25519_BASE;
                } else if (elem == "ed25519") {
                    node.elem = json_elem::ED25519;
                } else {
                    return false;
                }
                return true;
            }

            bool take_symbol(char expected) {
                // Skip whitespaces
                while (iter != end_iter && (*iter == ' ' || *iter == '\t')) {
                    ++iter;
                }
                if (iter == end_iter || *iter != expected) {
                    return false;
                }
                ++iter;
                return true;
            }

            bool recursion(signature_node &node) {
                const char *node_start = iter.base();
                auto node_start_iter = iter;
                if (!take_elem(node)) {
                    return false;
                }
                if (take_symbol('<')) {
                    node.children.emplace_back();
                    if (!recursion(node.children.back())) {
                        return false;
                    }
                    while (take_symbol(',')) {
                        node.children.emplace_back();
                        if (!recursion(node.children.back())) {
                            return false;
                        }
                    }
                    if (!take_symbol('>')) {
                        return false;
                    }
                }
                node.type_string = std::string_view(node_start, iter - node_start_iter);
                return true;
            }

        private:
            signature_node tree;
            std::string::const_iterator iter;
            std::string::const_iterator end_iter;
        };
    }
}

#endif  // CRYPTO3_ASSIGNER_SIGNATURE_PARSER_HPP
