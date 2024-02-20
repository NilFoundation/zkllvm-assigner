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

#ifndef NIL_BLUEPRINT_SIGNATURE_PARSER_HPP
#define NIL_BLUEPRINT_SIGNATURE_PARSER_HPP

#include <nil/blueprint/asserts.hpp>

#include <boost/spirit/include/qi.hpp>
#include <boost/phoenix/core.hpp>
#include <boost/phoenix/operator.hpp>
#include <boost/phoenix/fusion.hpp>
#include <boost/phoenix/stl.hpp>
#include <boost/phoenix/object.hpp>
#include <boost/fusion/include/adapt_struct.hpp>

#include <string>
#include <vector>
#include <iostream>

namespace nil {
    namespace blueprint {
        namespace fusion = boost::fusion;
        namespace phoenix = boost::phoenix;
        namespace qi = boost::spirit::qi;
        namespace ascii = boost::spirit::ascii;

        /// @brief Kind of element in signature AST.
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
            PALLAS_SCALAR,
            BLS12381_SCALAR,
            ED25519_SCALAR,
            PALLAS,
            BLS12381,
            ED25519,
        };

        std::ostream& operator<<(std::ostream& os, const json_elem& elem) {
            switch (elem) {
                case json_elem::UNDEFINED:
                    return os << "undefined";
                case json_elem::FIELD:
                    return os << "field";
                case json_elem::CURVE:
                    return os << "curve";
                case json_elem::ARRAY:
                    return os << "array";
                case json_elem::STRUCT:
                    return os << "struct";
                case json_elem::VECTOR:
                    return os << "vector";
                case json_elem::INT:
                    return os << "int";
                case json_elem::STRING:
                    return os << "string";
                case json_elem::PALLAS_BASE:
                    return os << "pallas_base";
                case json_elem::BLS12381_BASE:
                    return os << "bls12381_base";
                case json_elem::ED25519_BASE:
                    return os << "ed25519_base";
                case json_elem::PALLAS_SCALAR:
                    return os << "pallas_scalar";
                case json_elem::BLS12381_SCALAR:
                    return os << "bls12381_base";
                case json_elem::ED25519_SCALAR:
                    return os << "ed25519_base";
                case json_elem::PALLAS:
                    return os << "pallas";
                case json_elem::BLS12381:
                    return os << "bls12381";
                case json_elem::ED25519:
                    return os << "ed25519";
                default:
                    UNREACHABLE("invalid `json_elem` value");
            }
            return os;
        }

        /// @brief Signature AST node.
        struct signature_node {
            /// @brief Kind of node.
            json_elem elem = json_elem::UNDEFINED;

            /// @brief Nodes children.
            std::vector<signature_node> children;

            signature_node() = default;

            signature_node(json_elem elem_) : elem(elem_) {
            }
        };

        std::ostream& operator<<(std::ostream& os, const signature_node& s) {
            os << s.elem;
            if (!s.children.empty()) {
                os << "<";
                for (auto i = 0; i < s.children.size(); i++) {
                    if (i != 0) {
                        std::cout << ", ";
                    }
                    std::cout << s.children[i];
                }
                os << ">";
            }
            return os;
        }
    }    // namespace blueprint
}    // namespace nil

BOOST_FUSION_ADAPT_STRUCT(::nil::blueprint::signature_node,
                          (auto, elem)(std::vector<::nil::blueprint::signature_node>, children))

namespace nil {
    namespace blueprint {
        /// @brief Grammar describing signature syntax.
        template<typename Iterator>
        struct signature_grammar : qi::grammar<Iterator, signature_node(), ascii::space_type> {
            signature_grammar() : signature_grammar::base_type(root, "signature") {
                using qi::_1;
                using qi::_val;
                using qi::fail;
                using qi::lit;
                using qi::on_error;
                using namespace qi::labels;

                using phoenix::at_c;
                using phoenix::construct;
                using phoenix::push_back;
                using phoenix::val;

                int_ = lit("int")[_val = signature_node(json_elem::INT)];

                string_ = lit("string")[_val = signature_node(json_elem::STRING)];

                field_kind = lit("pallas_base")[_val = signature_node(json_elem::PALLAS_BASE)] |
                             lit("bls12381_base")[_val = signature_node(json_elem::BLS12381_BASE)] |
                             lit("ed25519_base")[_val = signature_node(json_elem::ED25519_BASE)] |
                             lit("pallas_scalar")[_val = signature_node(json_elem::PALLAS_SCALAR)] |
                             lit("bls12381_scalar")[_val = signature_node(json_elem::BLS12381_SCALAR)] |
                             lit("ed25519_scalar")[_val = signature_node(json_elem::ED25519_SCALAR)];

                curve_kind = lit("pallas")[_val = signature_node(json_elem::PALLAS)] |
                             lit("bls12381")[_val = signature_node(json_elem::BLS12381)] |
                             lit("ed25519")[_val = signature_node(json_elem::ED25519)];

                field = lit("field")[_val = signature_node(json_elem::FIELD)] >>
                        -("<" > field_kind > ">")[push_back(at_c<1>(_val), _1)];

                curve = lit("curve")[_val = signature_node(json_elem::CURVE)] >>
                        -("<" > curve_kind > ">")[push_back(at_c<1>(_val), _1)];

                array = lit("array")[_val = signature_node(json_elem::ARRAY)] > "<" >
                        type[push_back(at_c<1>(_val), _1)] > ">";

                vector = lit("vector")[_val = signature_node(json_elem::VECTOR)] > "<" >
                         type[push_back(at_c<1>(_val), _1)] > ">";

                struct_ =
                    lit("struct")[_val = signature_node(json_elem::STRUCT)] >>
                    -("<" > *(type[push_back(at_c<1>(_val), _1)] > ",") > -type[push_back(at_c<1>(_val), _1)] > ">");

                type = array | vector | field | struct_ | curve | int_ | string_;
                root = type;

                int_.name("int");
                string_.name("string");
                field_kind.name("field kind");
                curve_kind.name("curve kind");
                field.name("field");
                curve.name("curve");
                array.name("array");
                vector.name("vector");
                struct_.name("struct");
                type.name("type");
                root.name("root");

                on_error<fail>(root, std::cout << val("Error when parsing signature: expecting ") << _4
                                               << val(" before: \"") << construct<std::string>(_3, _2) << val("\"")
                                               << std::endl);
            }

            qi::rule<Iterator, signature_node(), ascii::space_type> int_;
            qi::rule<Iterator, signature_node(), ascii::space_type> string_;
            qi::rule<Iterator, signature_node(), ascii::space_type> field_kind;
            qi::rule<Iterator, signature_node(), ascii::space_type> curve_kind;
            qi::rule<Iterator, signature_node(), ascii::space_type> field;
            qi::rule<Iterator, signature_node(), ascii::space_type> curve;
            qi::rule<Iterator, signature_node(), ascii::space_type> array;
            qi::rule<Iterator, signature_node(), ascii::space_type> vector;
            qi::rule<Iterator, signature_node(), ascii::space_type> struct_;
            qi::rule<Iterator, signature_node(), ascii::space_type> type;
            qi::rule<Iterator, signature_node(), ascii::space_type> root;
        };

        /// @brief Parser of signature string.
        class signature_parser {
        public:
            /// @brief Parse input string into AST. Return `true` on success.
            bool parse(const std::string& str) {
                std::string::const_iterator it = str.begin();
                bool matched = phrase_parse(it, str.end(), grammar, ascii::space, tree);
                return matched && it == str.end();
            }

            /// @brief Signature AST.
            const signature_node& get_tree() {
                return tree;
            }

        private:
            signature_grammar<std::string::const_iterator> grammar;
            signature_node tree;
        };
    }    // namespace blueprint
}    // namespace nil

#endif    // NIL_BLUEPRINT_SIGNATURE_PARSER_HPP
