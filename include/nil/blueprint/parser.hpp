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

#include <variant>
#include <stack>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/components/hashes/poseidon/plonk/poseidon_15_wires.hpp>
#include <nil/blueprint/components/hashes/sha256/plonk/sha256.hpp>

#include <llvm/IRReader/IRReader.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/IR/Value.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instructions.h>
#include "llvm/IR/Constants.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/TypeFinder.h"
#include "llvm/IR/TypedPointerType.h"

#include <nil/blueprint/stack.hpp>
#include <nil/blueprint/fields/addition.hpp>
#include <nil/blueprint/fields/subtraction.hpp>
#include <nil/blueprint/fields/multiplication.hpp>
#include <nil/blueprint/fields/division.hpp>

#include <nil/blueprint/curves/addition.hpp>
#include <nil/blueprint/curves/subtraction.hpp>
#include <nil/blueprint/curves/multiplication.hpp>

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
            // TODO(maksenov): handle it properly and move to another file
            template <typename map_type>
            void handle_int_addition(const llvm::Instruction *inst, map_type &variables) {
                assert(inst->getOperand(0)->getType()->isIntegerTy());
                assert(inst->getOperand(1)->getType()->isIntegerTy());

                var x = std::get<0>(variables[inst->getOperand(0)]);
                var y = std::get<0>(variables[inst->getOperand(1)]);
                auto res = var_value(assignmnt, x) + var_value(assignmnt, y);
                assignmnt.public_input(0, public_input_idx) = res;
                variables[inst] = var(0, public_input_idx++, false, var::column_type::public_input);
            }

            // TODO(maksenov): handle it properly and move to another file
            template<typename map_type>
            void handle_int_cmp(const llvm::ICmpInst *inst, map_type &variables) {
                var x = std::get<0>(variables[inst->getOperand(0)]);
                var y = std::get<0>(variables[inst->getOperand(1)]);
                bool res = false;
                switch (inst->getPredicate()) {
                    case llvm::CmpInst::ICMP_EQ:
                        res = var_value(assignmnt, x) == var_value(assignmnt, y);
                        break;
                    case llvm::CmpInst::ICMP_NE:
                        res = var_value(assignmnt, x) != var_value(assignmnt, y);
                        break;
                    case llvm::CmpInst::ICMP_SGE:
                    case llvm::CmpInst::ICMP_UGE:
                        res = var_value(assignmnt, x) >= var_value(assignmnt, y);
                        break;
                    case llvm::CmpInst::ICMP_SGT:
                    case llvm::CmpInst::ICMP_UGT:
                        res = var_value(assignmnt, x) > var_value(assignmnt, y);
                        break;
                    case llvm::CmpInst::ICMP_SLE:
                    case llvm::CmpInst::ICMP_ULE:
                        res = var_value(assignmnt, x) <= var_value(assignmnt, y);
                        break;
                    case llvm::CmpInst::ICMP_SLT:
                    case llvm::CmpInst::ICMP_ULT:
                        res = var_value(assignmnt, x) < var_value(assignmnt, y);
                        break;
                    default:
                        assert(false && "Unsupported predicate");
                        break;
                }
                assignmnt.public_input(0, public_input_idx) = res;
                variables[inst] = var(0, public_input_idx++, false, var::column_type::public_input);
            }

            const llvm::Instruction *handle_instruction(const llvm::Instruction *inst) {

                typename stack_frame<var>::map_type &variables = call_stack.top().frame_variables;
                std::uint32_t start_row = assignmnt.allocated_rows();

                // Put constant operands to public input
                for (int i = 0; i < inst->getNumOperands(); ++i) {
                    llvm::Value *op = inst->getOperand(i);
                    if ((llvm::isa<llvm::ConstantField>(op) || llvm::isa<llvm::ConstantInt>(op)) &&
                        variables.find(op) == variables.end()) {
                        llvm::APInt IntVal;
                        if (llvm::isa<llvm::ConstantField>(op)) {
                            IntVal = llvm::cast<llvm::ConstantField>(op)->getValue();
                        } else {
                            IntVal = llvm::cast<llvm::ConstantInt>(op)->getValue();
                        }
                        unsigned words = IntVal.getNumWords();
                        typename BlueprintFieldType::value_type field_constant;
                        if (words == 1) {
                            field_constant = IntVal.getZExtValue();
                        } else {
                            // TODO(maksenov): avoid copying here
                            const char *APIntData = reinterpret_cast<const char *>(IntVal.getRawData());
                            std::vector<char> bytes(APIntData, APIntData + words * 8);
                            nil::marshalling::status_type status;
                            field_constant = nil::marshalling::pack<nil::marshalling::option::little_endian>(bytes, status);
                            assert(status == nil::marshalling::status_type::success);
                        }
                        assignmnt.public_input(0, public_input_idx) = field_constant;
                        variables[op] = var(0, public_input_idx++, false, var::column_type::public_input);
                    }
                }

                switch (inst->getOpcode()) {
                    case llvm::Instruction::Add: {

                        if (inst->getOperand(0)->getType()->isIntegerTy()) {
                            handle_int_addition(inst, variables);
                            return inst->getNextNonDebugInstruction();
                        }
                        if (inst->getOperand(0)->getType()->isFieldTy()) {
                            handle_field_addition_component<BlueprintFieldType, ArithmetizationParams>(
                                        inst, variables, bp, assignmnt, start_row);
                            return inst->getNextNonDebugInstruction();
                        }
                        if (inst->getOperand(0)->getType()->isCurveTy()) {
                            handle_curve_addition_component<BlueprintFieldType, ArithmetizationParams>(
                                        inst, variables, bp, assignmnt, start_row);
                            return inst->getNextNonDebugInstruction();
                        }
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Sub: {

                        if (inst->getOperand(0)->getType()->isFieldTy()) {
                            handle_field_subtraction_component<BlueprintFieldType, ArithmetizationParams>(
                                inst, variables, bp, assignmnt, start_row);
                            return inst->getNextNonDebugInstruction();
                        }
                        if (inst->getOperand(0)->getType()->isCurveTy()) {
                            handle_curve_subtraction_component<BlueprintFieldType, ArithmetizationParams>(
                                inst, variables, bp, assignmnt, start_row);
                            return inst->getNextNonDebugInstruction();
                        }

                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Mul: {

                        if (inst->getOperand(0)->getType()->isFieldTy() && inst->getOperand(1)->getType()->isFieldTy()) {
                            handle_field_multiplication_component<BlueprintFieldType, ArithmetizationParams>(
                                inst, variables, bp, assignmnt, start_row);
                            return inst->getNextNonDebugInstruction();
                        }
                        if (
                            (inst->getOperand(0)->getType()->isCurveTy() && inst->getOperand(1)->getType()->isFieldTy()) || 
                            (inst->getOperand(1)->getType()->isCurveTy() && inst->getOperand(0)->getType()->isFieldTy())) {

                            unsigned curve_nr, field_nr;
                            for (unsigned i = 0; i < 2; i++) {
                                if (inst->getOperand(i)->getType()->isFieldTy()) {
                                    field_nr = i;
                                }
                                if (inst->getOperand(i)->getType()->isCurveTy()) {
                                    curve_nr = i;
                                }
                            }
                            
                            handle_curve_multiplication_component<BlueprintFieldType, ArithmetizationParams>(
                                inst, variables, bp, assignmnt, start_row);
                            return inst->getNextNonDebugInstruction();
                        }

                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::SDiv: {

                        handle_field_division_component<BlueprintFieldType, ArithmetizationParams>(
                            inst, variables, bp, assignmnt, start_row);

                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Call: {
                        auto *call_inst = llvm::cast<llvm::CallInst>(inst);
                        auto *fun = call_inst->getCalledFunction();
                        if (fun == nullptr) {
                            std::cerr << "Unresolved call";
                            return nullptr;
                        }
                        unsigned fun_idx = call_inst->getNumOperands() - 1;
                        llvm::StringRef fun_name = fun->getName();
                        assert(fun->arg_size() == call_inst->getNumOperands() - 1);
                        if (fun_name.find("nil7crypto36hashes8poseidon") != std::string::npos) {
                            // Poseidon handling
                            using component_type = components::poseidon<ArithmetizationType, BlueprintFieldType, 15>;

                            auto &input_block = std::get<1>(variables[inst->getOperand(0)]);
                            std::array<var, component_type::state_size> input_state_var;
                            std::copy(input_block.begin(), input_block.end(), input_state_var.begin());

                            typename component_type::input_type instance_input = {input_state_var};

                            component_type component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, {},
                                                              {});

                            components::generate_circuit<BlueprintFieldType, ArithmetizationParams>(
                                component_instance, bp, assignmnt, instance_input, start_row);

                            typename component_type::result_type component_result =
                                components::generate_assignments<BlueprintFieldType, ArithmetizationParams>(
                                    component_instance, assignmnt, instance_input, start_row);

                            std::vector<var> output(component_result.output_state.begin(),
                                                    component_result.output_state.end());
                            variables[inst] = output;
                            return inst->getNextNonDebugInstruction();
                        }
                        if (fun_name.find("nil7crypto36hashes6sha256") != std::string::npos) {
                            // SHA256 handling
                            using component_type = components::sha256<ArithmetizationType, 9>;

                            constexpr const std::int32_t block_size = 2;
                            constexpr const std::int32_t input_blocks_amount = 2;

                            auto &block_arg = std::get<1>(variables[inst->getOperand(0)]);
                            std::array<var, input_blocks_amount * block_size> input_block_vars;
                            std::copy(block_arg.begin(), block_arg.end(), input_block_vars.begin());

                            typename component_type::input_type instance_input = {input_block_vars};

                            component_type component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8}, {0}, {});

                            components::generate_circuit<BlueprintFieldType, ArithmetizationParams>(
                                component_instance, bp, assignmnt, instance_input, start_row);

                            typename component_type::result_type component_result =
                                components::generate_assignments<BlueprintFieldType, ArithmetizationParams>(
                                    component_instance, assignmnt, instance_input, start_row);

                            std::vector<var> output(component_result.output.begin(), component_result.output.end());
                            variables[inst] = output;
                            return inst->getNextNonDebugInstruction();
                        }
                        if (fun->empty()) {
                            std::cerr << "Function " << fun_name.str() << " has no implementation." << std::endl;
                            return nullptr;
                        }
                        stack_frame<var> new_frame;
                        auto &new_variables = new_frame.frame_variables;
                        for (int i = 0; i < fun->arg_size(); ++i) {
                            new_variables[fun->getArg(i)] = variables[call_inst->getOperand(i)];
                        }
                        new_frame.caller = call_inst;
                        call_stack.emplace(std::move(new_frame));
                        return &fun->begin()->front();
                    }
                    case llvm::Instruction::ICmp: {
                        handle_int_cmp(llvm::cast<const llvm::ICmpInst>(inst), variables);
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Select: {

                        var condition = std::get<0>(variables[inst->getOperand(0)]);
                        llvm::Value *true_val = inst->getOperand(1);
                        llvm::Value *false_val = inst->getOperand(2);
                        if (var_value(assignmnt, condition) != 0) {
                            variables[inst] = variables[true_val];
                        } else {
                            variables[inst] = variables[false_val];
                        }
                        return inst->getNextNonDebugInstruction();
                    }

                    case llvm::Instruction::Br: {
                        // Save current basic block to resolve PHI inst further
                        predecessor = inst->getParent();

                        if (inst->getNumOperands() != 1) {
                            assert(inst->getNumOperands() == 3);
                            auto false_bb = llvm::cast<llvm::BasicBlock>(inst->getOperand(1));
                            auto true_bb = llvm::cast<llvm::BasicBlock>(inst->getOperand(2));
                            var cond = std::get<0>(variables[inst->getOperand(0)]);
                            if (var_value(assignmnt, cond) != 0)
                                return &true_bb->front();
                            return &false_bb->front();
                        }
                        auto bb_to_jump = llvm::cast<llvm::BasicBlock>(inst->getOperand(0));
                        return &bb_to_jump->front();
                    }
                    case llvm::Instruction::PHI: {
                        auto phi_node = llvm::cast<llvm::PHINode>(inst);
                        for (int i = 0; i < phi_node->getNumIncomingValues(); ++i) {
                            if (phi_node->getIncomingBlock(i) == predecessor) {
                                llvm::Value *incoming_value = phi_node->getIncomingValue(i);
                                assert(variables.find(incoming_value) != variables.end());
                                // Take found incoming value as instruction result
                                variables[phi_node] = variables[incoming_value];
                                return phi_node->getNextNonDebugInstruction();
                            }
                        }
                        assert(false && "Incoming value for phi was not found");
                        break;
                    }
                    case llvm::Instruction::InsertElement: {
                        auto insert_inst = llvm::cast<llvm::InsertElementInst>(inst);
                        llvm::Value *vec = insert_inst->getOperand(0);
                        llvm::Value *index_value = insert_inst->getOperand(2);
                        if (!llvm::isa<llvm::ConstantInt>(index_value)) {
                            std::cerr << "Only constant indices for a vector are supported" << std::endl;
                            return nullptr;
                        }

                        int index = llvm::cast<llvm::ConstantInt>(index_value)->getZExtValue();
                        if (llvm::isa<llvm::UndefValue>(vec)) {
                            llvm::Type *vector_type = vec->getType();
                            assert(llvm::isa<llvm::FixedVectorType>(vector_type));
                            unsigned size = llvm::cast<llvm::FixedVectorType>(vector_type)->getNumElements();
                            std::vector<var> result_vector(size);
                            result_vector[index] = std::get<0>(variables[inst->getOperand(1)]);
                            variables[inst] = result_vector;
                        } else {
                            std::vector<var> result_vector(std::get<1>(variables[vec]));
                            result_vector[index] = std::get<0>(variables[inst->getOperand(1)]);
                            variables[inst] = result_vector;
                        }
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::ExtractElement: {
                        auto extract_inst = llvm::cast<llvm::ExtractElementInst>(inst);
                        llvm::Value *vec = extract_inst->getOperand(0);
                        llvm::Value *index_value = extract_inst->getOperand(1);
                        if (!llvm::isa<llvm::ConstantInt>(index_value)) {
                            std::cerr << "Only constant indices for a vector are supported" << std::endl;
                            return nullptr;
                        }
                        int index = llvm::cast<llvm::ConstantInt>(index_value)->getZExtValue();
                        variables[inst] = std::get<1>(variables[vec])[index];
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Ret: {
                        auto extracted_frame = std::move(call_stack.top());
                        call_stack.pop();
                        if (extracted_frame.caller == nullptr) {
                            // Final return
                            assert(call_stack.size() == 0);
                            finished = true;
                            return nullptr;
                        }
                        llvm::Value *ret_val = inst->getOperand(0);
                        if (ret_val != nullptr) {
                            auto &upper_frame_variables = call_stack.top().frame_variables;
                            upper_frame_variables[extracted_frame.caller] = extracted_frame.frame_variables[ret_val];
                        }
                        return extracted_frame.caller->getNextNonDebugInstruction();
                    }

                    default:
                        std::cerr << inst->getOpcodeName() << std::endl;
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

                typename stack_frame<var>::map_type variables;
                auto entry_point_it = module.end();
                for (auto function_it = module.begin(); function_it != module.end(); ++function_it) {
                    if (function_it->hasFnAttribute(llvm::Attribute::Circuit)) {
                        if (entry_point_it != module.end()) {
                            std::cerr << "More then one functions with [[circuit]] attribute in the module"
                                      << std::endl;
                            return false;
                        }
                        entry_point_it = function_it;
                    }
                }
                if (entry_point_it == module.end()) {
                    std::cerr << "Entry point is not found" << std::endl;
                    return false;
                }
                auto &function = *entry_point_it;

                // Fill in the public input
                bool overflow = false;
                size_t public_input_counter = 0;
                for (size_t i = 0; i < function.arg_size(); ++i) {
                    if (public_input_counter >= public_input.size()) {
                        overflow = true;
                        break;
                    }
                    llvm::Value *current_arg = function.getArg(i);
                    llvm::Type *arg_type = current_arg->getType();
                    if (llvm::isa<llvm::FixedVectorType>(arg_type)) {
                        size_t size = llvm::cast<llvm::FixedVectorType>(arg_type)->getNumElements();
                        if (size + public_input_counter > public_input.size()) {
                            overflow = true;
                            break;
                        }
                        std::vector<var> input_vector(size);
                        for (size_t j = 0; j < size; ++j) {
                            assignmnt.public_input(0, public_input_counter) = public_input[public_input_counter];
                            input_vector[j] = var(0, public_input_counter++, false, var::column_type::public_input);
                        }
                        variables[current_arg] = input_vector;
                    } else {
                        assert(llvm::isa<llvm::GaloisFieldType>(arg_type));
                        assignmnt.public_input(0, public_input_counter) = public_input[public_input_counter];
                        variables[current_arg] = var(0, public_input_counter++, false, var::column_type::public_input);
                        ;
                    }
                }
                if (public_input_counter != public_input.size() || overflow) {
                    std::cerr << "Public input must match the size of arguments" << std::endl;
                    return false;
                }
                public_input_idx = public_input.size();
                call_stack.emplace(stack_frame<var> {std::move(variables), nullptr});

                const llvm::Instruction *next_inst = &function.begin()->front();
                while (true) {
                    next_inst = handle_instruction(next_inst);
                    if (finished) {
                        return true;
                    }
                    if (next_inst == nullptr) {
                        return false;
                    }
                }
            }

        private:
            llvm::LLVMContext context;
            const llvm::BasicBlock *predecessor = nullptr;
            std::stack<stack_frame<var>> call_stack;
            bool finished = false;
            size_t public_input_idx = 0;
        };

    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENT_INSTRUCTION_PARSER_HPP
