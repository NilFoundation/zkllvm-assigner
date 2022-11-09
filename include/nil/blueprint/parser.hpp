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

#ifndef CRYPTO3_BLUEPRINT_COMPONENT_INSTRUCTION_PARSER_HPP
#define CRYPTO3_BLUEPRINT_COMPONENT_INSTRUCTION_PARSER_HPP

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/addition.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/subtraction.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/multiplication.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/division.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/multiplication_by_constant.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/division_or_zero.hpp>
#include <nil/blueprint/components/hashes/poseidon/plonk/poseidon_15_wires.hpp>

#include <llvm/IRReader/IRReader.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instructions.h>

namespace nil {
    namespace blueprint {

        template<typename BlueprintFieldType, typename ArithmetizationParams>
        struct parser {

            using ArithmetizationType =
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
            using var = crypto3::zk::snark::plonk_variable<BlueprintFieldType>;

            circuit<ArithmetizationType> bp;
            assignment<ArithmetizationType> assignmnt;

        private:
            const llvm::Instruction *handle_instruction(std::map<const llvm::Value *, var> &variables, const llvm::Instruction *inst) {

                std::size_t start_row = assignmnt.allocated_rows();

                const unsigned POSEIDON_OPCODE = 6666;  // TODO(maksenov: implement poseidon in clang)

                switch (inst->getOpcode()) {
                    case llvm::Instruction::Add: {
                        using component_type = components::addition<ArithmetizationType, 3>;

                        var x = variables[inst->getOperand(0)];
                        var y = variables[inst->getOperand(1)];

                        typename component_type::input_type instance_input = {x, y};

                        component_type component_instance({0, 1, 2}, {}, {});

                        components::generate_circuit<BlueprintFieldType, ArithmetizationParams>(
                            component_instance, bp, assignmnt, instance_input, start_row);
                        typename component_type::result_type component_result =
                            components::generate_assignments<BlueprintFieldType, ArithmetizationParams>(
                                component_instance, assignmnt, instance_input, start_row);

                        variables[inst] = component_result.output;

                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Sub: {
                        using component_type = components::subtraction<ArithmetizationType, 3>;

                        var x = variables[inst->getOperand(0)];
                        var y = variables[inst->getOperand(1)];

                        typename component_type::input_type instance_input = {x, y};

                        component_type component_instance({0, 1, 2}, {}, {});

                        components::generate_circuit<BlueprintFieldType, ArithmetizationParams>(
                            component_instance, bp, assignmnt, instance_input, start_row);
                        typename component_type::result_type component_result =
                            components::generate_assignments<BlueprintFieldType, ArithmetizationParams>(
                                component_instance, assignmnt, instance_input, start_row);

                        variables[inst] = component_result.output;
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Mul: {
                        using component_type = components::multiplication<ArithmetizationType, 3>;

                        var x = variables[inst->getOperand(0)];
                        var y = variables[inst->getOperand(1)];

                        typename component_type::input_type instance_input = {x, y};

                        component_type component_instance({0, 1, 2}, {}, {});

                        components::generate_circuit<BlueprintFieldType, ArithmetizationParams>(
                            component_instance, bp, assignmnt, instance_input, start_row);
                        typename component_type::result_type component_result =
                            components::generate_assignments<BlueprintFieldType, ArithmetizationParams>(
                                component_instance, assignmnt, instance_input, start_row);

                        variables[inst] = component_result.output;
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::SDiv: {
                        using component_type = components::division<ArithmetizationType, 4>;

                        var x = variables[inst->getOperand(0)];
                        var y = variables[inst->getOperand(1)];

                        typename component_type::input_type instance_input = {x, y};

                        component_type component_instance({0, 1, 2, 3}, {}, {});

                        components::generate_circuit<BlueprintFieldType, ArithmetizationParams>(
                            component_instance, bp, assignmnt, instance_input, start_row);
                        typename component_type::result_type component_result =
                            components::generate_assignments<BlueprintFieldType, ArithmetizationParams>(
                                component_instance, assignmnt, instance_input, start_row);

                        variables[inst] = component_result.output;
                        return inst->getNextNonDebugInstruction();
                    }
                    case POSEIDON_OPCODE: {
                        using component_type = components::poseidon<ArithmetizationType, BlueprintFieldType, 15>;

                        std::array<var, component_type::state_size> input_state_var;
                        for (std::uint32_t i = 0; i < component_type::state_size; i++) {
                            input_state_var[i] = variables[inst->getOperand(i)];
                        }

                        typename component_type::input_type instance_input = {input_state_var};

                        component_type component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, {}, {});

                        components::generate_circuit<BlueprintFieldType, ArithmetizationParams>(
                            component_instance, bp, assignmnt, instance_input, start_row);

                        typename component_type::result_type component_result =
                            components::generate_assignments<BlueprintFieldType, ArithmetizationParams>(
                                component_instance, assignmnt, instance_input, start_row);

                        for (std::uint32_t i = 0; i < component_type::state_size; i++) {
                            // variables[instruction.arguments[component_type::state_size + i]] =
                            //     component_result.output_state[i];
                        }
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::ICmp: {
                        var x = variables[inst->getOperand(0)];
                        var y = variables[inst->getOperand(1)];
                        auto predicate = llvm::cast<llvm::ICmpInst>(inst)->getPredicate();
                        auto next_inst = inst->getNextNonDebugInstruction();
                        if (next_inst->getOpcode() == llvm::Instruction::Br && next_inst->getNumOperands() == 3) {
                            // Handle if
                            auto false_bb = llvm::cast<llvm::BasicBlock>(next_inst->getOperand(1));
                            auto true_bb = llvm::cast<llvm::BasicBlock>(next_inst->getOperand(2));
                            // ...
                            predecessor = inst->getParent();
                            return &true_bb->front();
                        }

                        assert(false && "Unhandled cmp instruction");
                    }
                    case llvm::Instruction::Br: {
                        if (inst->getNumOperands() != 1) {
                            std::cerr << "Unexpected if" << std::endl;
                            return nullptr;
                        }
                        auto bb_to_jump = llvm::cast<llvm::BasicBlock>(inst->getOperand(0));
                        predecessor = inst->getParent();
                        return &bb_to_jump->front();
                    }
                    case llvm::Instruction::PHI: {
                        auto phi_node = llvm::cast<llvm::PHINode>(inst);
                        for (int i = 0; i < phi_node->getNumIncomingValues(); ++i) {
                            if (phi_node->getIncomingBlock(i) == predecessor) {
                                llvm::Value *incoming_value = phi_node->getIncomingValue(i);
                                // Take found incoming value as instruction result
                                variables[phi_node] = variables[incoming_value];
                                return phi_node->getNextNonDebugInstruction();
                            }
                        }
                        assert(false && "Incoming value for phi was not found");
                        break;
                    }

                    default:
                        assert(1 == 0 && "unsupported opcode type");
                }
            }

        public:
            std::unique_ptr<llvm::Module> parseIRFile(const char *ir_file) {
                llvm::SMDiagnostic diagnostic;
                std::unique_ptr<llvm::Module> module = llvm::parseIRFile(ir_file, diagnostic, context);
                if (module == nullptr) {
                    std::cout << "Unable to parse IR file: " + diagnostic.getMessage().str() << std::endl;
                }
                return module;
            }

            template<typename PublicInputContainerType>
            bool evaluate(const llvm::Module &module, const PublicInputContainerType &public_input) {

                std::map<const llvm::Value *, var> variables;
                if (module.size() != 1) {
                    std::cerr << "IR module must contain only one function" << std::endl;
                    return false;
                }
                const llvm::Function &function = *module.begin();
                if (function.arg_size() != public_input.size()) {
                    std::cerr << "Public input must match the size of arguments" << std::endl;
                    return false;
                }

                for (std::size_t i = 0; i < public_input.size(); i++) {
                    assignmnt.public_input(0, i) = (public_input[i]);
                    variables[function.getArg(i)] = var(0, i, false, var::column_type::public_input);
                }

                // for (std::int32_t instruction_index = 0; instruction_index < code.instructions.size(); instruction_index++) {
                //     parse_instruction(variables, code.instructions[instruction_index]);
                // }

                const llvm::Instruction *next_inst = &function.begin()->front();
                while (next_inst->getOpcode() != llvm::Instruction::Ret) {
                    next_inst = handle_instruction(variables, next_inst);
                    if (next_inst == nullptr) {
                        return false;
                    }
                }
                return true;
            }

        private:
            llvm::LLVMContext context;
            const llvm::BasicBlock *predecessor = nullptr;
        };

    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENT_INSTRUCTION_PARSER_HPP
