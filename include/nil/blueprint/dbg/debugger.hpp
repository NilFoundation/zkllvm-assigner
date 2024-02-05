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
// @file This file defines debugger (interactive interpreter) for assigner.
//---------------------------------------------------------------------------//

#ifndef NIL_BLUEPRINT_DBG_DEBUGGER_HPP
#define NIL_BLUEPRINT_DBG_DEBUGGER_HPP

#include <iostream>

#include <boost/spirit/include/qi.hpp>

#include <nil/blueprint/assigner.hpp>

namespace nil {
    namespace blueprint {
        namespace dbg {
            /// @brief Debugger command.
            struct command {
            public:
                /// @brief Debugger set of commands.
                enum command_kind { unknown, run, quit, continue_, step };

                /// @brief Command kind.
                command_kind kind = unknown;

                void parse_string(std::string str) {
                    if (str == "run" || str == "r") {
                        kind = run;
                    } else if (str == "quit" || str == "q") {
                        kind = quit;
                    } else if (str == "continue" || str == "c") {
                        kind = continue_;
                    } else if (str == "step" || str == "s") {
                        kind = step;
                    }
                }

                void parse() {
                    boost::spirit::qi::rule<std::string::const_iterator, std::string(), boost::spirit::qi::space_type> cmd;
                }
            };

            /// @brief Simple debugger for assigner.
            template<typename BlueprintFieldType, typename ArithmetizationParams>
            struct debugger : assigner<BlueprintFieldType, ArithmetizationParams> {
            public:
                using assigner<BlueprintFieldType, ArithmetizationParams>::assigner;

                /// @brief Run debugger.
                void run(const llvm::Module &module,
                         const boost::json::array &public_input,
                         const boost::json::array &private_input) {
                    msg("Initializing state");
                    if (!this->initialize_state(module, public_input, private_input)) {
                        ostream << "Failed to initialize state." << std::endl << "Exiting..." << std::endl;
                        return;
                    }

                    bool started = false;

                    // Main cycle handling CLI commands from user
                    while (true) {

                        command c;
                        std::string input_line;
                        msg(">>> ");
                        std::getline(std::cin, input_line);
                        c.parse_string(input_line);

                        switch (c.kind) {
                            case command::command_kind::unknown: {
                                msg("Unknown command");
                                break;
                            }
                            case command::command_kind::run: {
                                if (started) {
                                    msg("Debugger is already in run");
                                } else {
                                    msg("Starting debugger");
                                    started = true;
                                    run_until_breakpoint();
                                }
                                break;
                            }
                            case command::command_kind::quit: {
                                msg("Exiting...");
                                ostream < < < < std::endl;
                                return;
                            }
                            case command::command_kind::continue_: {
                                if (started) {
                                    run_until_breakpoint();
                                } else {
                                    msg("Debugger is not started");
                                }
                                break;
                            }
                            case command::command_kind::step: {
                                if (this->ip == nullptr) {
                                    msg("End of execution reached");
                                } else {
                                    this->ip = this->handle_instruction(this->ip);
                                    print_inst(*this->ip);
                                }
                                break;
                            }
                        }
                    }
                }

            private:
                /// @brief Print something to output stream.
                void msg(std::string str) {
                    ostream << str << std::endl;
                }

                /// @brief Print given instruction to stdout.
                void print_inst(const llvm::Instruction &inst) {
                    std::string str;
                    llvm::raw_string_ostream stream(str);
                    inst.print(stream);
                    msg(str);
                }

                /// @brief Whether given instruction is a `llvm.debugtrap` call or not.
                static bool is_breakpoint(const llvm::Instruction &inst) {
                    if (inst.getOpcode() == llvm::Instruction::Call) {
                        llvm::Function *func = llvm::cast<llvm::CallInst>(inst).getCalledFunction();
                        return func->isIntrinsic() && (func->getIntrinsicID() == llvm::Intrinsic::debugtrap);
                    }
                    return false;
                }

                /// @brief Run from current state until breakpoint or end. Return `true` if breakpoint is hit.
                bool run_until_breakpoint() {
                    while (this->ip != nullptr) {
                        if (is_breakpoint(*this->ip)) {
                            msg("Hit breakpoint");
                            this->ip = this->ip->getNextNonDebugInstruction();
                            print_inst(*this->ip);
                            return true;
                        }
                        this->ip = this->handle_instruction(this->ip);
                    }

                    msg("End of execution reached");
                    return false;
                }

                /// Output stream for debugger to print messages.
                std::ostream &ostream = std::cout;

                /// Input stream for debugger to read commands.
                std::istream &istream = std::cin;
            };
        }    // namespace dbg
    }        // namespace blueprint
}    // namespace nil

#endif    // NIL_BLUEPRINT_DBG_DEBUGGER_HPP
