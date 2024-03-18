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

#ifndef ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_LOGGER_HPP_
#define ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_LOGGER_HPP_

#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>

#include <llvm/IR/Instructions.h>

namespace nil {
    namespace blueprint {
        class logger {
            const llvm::BasicBlock *current_block = nullptr;
            const llvm::Function *current_function = nullptr;
        public:

            logger(boost::log::trivial::severity_level lvl = boost::log::trivial::info) {
                boost::log::core::get()->set_filter(boost::log::trivial::severity >= lvl);
            }

            void set_level(boost::log::trivial::severity_level lvl) {
                boost::log::core::get()->set_filter(boost::log::trivial::severity >= lvl);
            }

            // TODO: these two functions can be substituted by one when std::format is widely supported
            void debug(boost::basic_format<char> formated_debug_message) {
                BOOST_LOG_TRIVIAL(debug) << boost::str(formated_debug_message);
            }

            void debug(std::string_view debug_message) {
                BOOST_LOG_TRIVIAL(debug) << debug_message;
            }
            
            void log_instruction(const llvm::Instruction *inst) {
                if (inst->getFunction() != current_function) {
                    current_function = inst->getFunction();
                    BOOST_LOG_TRIVIAL(debug) << current_function->getName().str();
                }
                if (inst->getParent() != current_block) {
                    current_block = inst->getParent();
                    BOOST_LOG_TRIVIAL(debug) << "\t" << current_block->getNameOrAsOperand();
                }
                std::string str;
                llvm::raw_string_ostream ss(str);
                inst->print(ss);
                BOOST_LOG_TRIVIAL(debug) << "\t\t" << str;
            }
        };
    }    // namespace blueprint
}    // namespace nil

#endif    // ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_LOGGER_HPP_