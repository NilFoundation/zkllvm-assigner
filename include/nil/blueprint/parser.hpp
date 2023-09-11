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
#include <nil/blueprint/components/hashes/poseidon/plonk/poseidon.hpp>
#include <nil/blueprint/components/hashes/sha2/plonk/sha256.hpp>
#include <nil/blueprint/components/hashes/sha2/plonk/sha512.hpp>

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
#include "llvm/IR/Intrinsics.h"

#include <nil/blueprint/logger.hpp>
#include <nil/blueprint/layout_resolver.hpp>
#include <nil/blueprint/public_input.hpp>
#include <nil/blueprint/stack.hpp>
#include <nil/blueprint/integers/addition.hpp>
#include <nil/blueprint/integers/subtraction.hpp>
#include <nil/blueprint/integers/multiplication.hpp>
#include <nil/blueprint/integers/division.hpp>
#include <nil/blueprint/integers/division_remainder.hpp>
#include <nil/blueprint/integers/bit_shift.hpp>
#include <nil/blueprint/integers/bit_de_composition.hpp>

#include <nil/blueprint/comparison/comparison.hpp>
#include <nil/blueprint/bitwise/and.hpp>
#include <nil/blueprint/bitwise/or.hpp>
#include <nil/blueprint/bitwise/xor.hpp>

#include <nil/blueprint/fields/addition.hpp>
#include <nil/blueprint/fields/subtraction.hpp>
#include <nil/blueprint/fields/multiplication.hpp>
#include <nil/blueprint/fields/division.hpp>

#include <nil/blueprint/curves/addition.hpp>
#include <nil/blueprint/curves/subtraction.hpp>
#include <nil/blueprint/curves/multiplication.hpp>
#include <nil/blueprint/curves/init.hpp>

#include <nil/blueprint/hashes/sha2_256.hpp>
#include <nil/blueprint/hashes/sha2_512.hpp>

namespace nil {
    namespace blueprint {

        template<typename BlueprintFieldType, typename ArithmetizationParams, bool PrintCircuitOutput>
        struct parser {

            parser(long stack_size, bool detailed_logging) : stack_memory(stack_size) {
                if (detailed_logging) {
                    log.set_level(logger::level::DEBUG);
                }
            }

            using ArithmetizationType =
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
            using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

            circuit<ArithmetizationType> bp;
            assignment<ArithmetizationType> assignmnt;

        private:

            template<typename map_type>
            void handle_scalar_cmp(const llvm::ICmpInst *inst, map_type &variables) {
                const var &lhs = variables[inst->getOperand(0)];
                const var &rhs = variables[inst->getOperand(1)];

                std::size_t bitness = inst->getOperand(0)->getType()->getPrimitiveSizeInBits();
                variables[inst] = handle_comparison_component<BlueprintFieldType, ArithmetizationParams>(
                    inst->getPredicate(), lhs, rhs, bitness,
                    bp, assignmnt, assignmnt.allocated_rows(), public_input_idx);
            }

            void handle_vector_cmp(const llvm::ICmpInst *inst, stack_frame<var> &frame) {
                const std::vector<var> &lhs = frame.vectors[inst->getOperand(0)];
                const std::vector<var> &rhs = frame.vectors[inst->getOperand(1)];
                ASSERT(lhs.size() == rhs.size());
                std::vector<var> res;

                auto vector_ty = llvm::cast<llvm::FixedVectorType>(inst->getOperand(0)->getType());
                size_t bitness = 0;
                if (auto field_ty = llvm::dyn_cast<llvm::GaloisFieldType>(vector_ty->getElementType())) {
                    bitness = field_ty->getBitWidth();
                } else {
                    bitness = llvm::cast<llvm::IntegerType>(vector_ty->getElementType())->getBitWidth();
                }

                for (size_t i = 0; i < lhs.size(); ++i) {
                    auto v = handle_comparison_component<BlueprintFieldType, ArithmetizationParams>(
                        inst->getPredicate(), lhs[i], rhs[i], bitness,
                        bp, assignmnt, assignmnt.allocated_rows(), public_input_idx);

                    res.emplace_back(v);
                }
                frame.vectors[inst] = res;
            }

            void handle_ptr_cmp(const llvm::ICmpInst *inst, stack_frame<var> &frame) {
                ptr_type lhs = resolve_number<ptr_type>(frame, inst->getOperand(0));
                ASSERT(frame.scalars.find(inst->getOperand(1)) != frame.scalars.end());
                ptr_type rhs = resolve_number<ptr_type>(frame, inst->getOperand(1));
                bool res = false;
                switch (inst->getPredicate()) {
                    case llvm::CmpInst::ICMP_EQ:
                        res = lhs == rhs;
                        break;
                    case llvm::CmpInst::ICMP_NE:
                        res = !(lhs == rhs);
                        break;
                    default:
                        UNREACHABLE("Unsupported predicate");
                        break;
                }
                assignmnt.public_input(0, public_input_idx) = res;
                frame.scalars[inst] = var(0, public_input_idx++, false, var::column_type::public_input);
            }

            typename BlueprintFieldType::value_type marshal_int_val(const llvm::Value *val) {
                ASSERT(llvm::isa<llvm::ConstantField>(val) || llvm::isa<llvm::ConstantInt>(val));
                llvm::APInt int_val;
                if (llvm::isa<llvm::ConstantField>(val)) {
                    int_val = llvm::cast<llvm::ConstantField>(val)->getValue();
                } else {
                    int_val = llvm::cast<llvm::ConstantInt>(val)->getValue();
                }
                unsigned words = int_val.getNumWords();
                typename BlueprintFieldType::value_type field_constant;
                if (words == 1) {
                    field_constant = int_val.getSExtValue();
                } else {
                    // TODO(maksenov): avoid copying here
                    const char *APIntData = reinterpret_cast<const char *>(int_val.getRawData());
                    std::vector<char> bytes(APIntData, APIntData + words * 8);
                    nil::marshalling::status_type status;
                    field_constant = nil::marshalling::pack<nil::marshalling::option::little_endian>(bytes, status);
                    ASSERT(status == nil::marshalling::status_type::success);
                }
                return field_constant;
            }

            template <typename NumberType>
            NumberType resolve_number(stack_frame<var> &frame, const llvm::Value *value) {
                var scalar = frame.scalars[value];
                auto scalar_value = var_value(assignmnt, scalar);
                NumberType number = (NumberType)static_cast<typename BlueprintFieldType::integral_type>(scalar_value.data);
                return number;
            }

            template<typename VarType>
            ptr_type store_constant(const llvm::Constant *constant_init) {
                if (auto operation = llvm::dyn_cast<llvm::ConstantExpr>(constant_init)) {
                    if (operation->isCast())
                        constant_init = operation->getOperand(0);
                    else if (operation->getOpcode() == llvm::Instruction::GetElementPtr) {
                        for (int i = 1; i < operation->getNumOperands(); ++i) {
                            int64_t idx = llvm::cast<llvm::ConstantInt>(operation->getOperand(i))->getSExtValue();
                            ASSERT_MSG(idx == 0, "Only trivial GEP constant expressions are supported");
                        }
                        constant_init = operation->getOperand(0);
                    } else {
                        UNREACHABLE("Unsupported constant expression");
                    }
                }
                if (auto CS = llvm::dyn_cast<llvm::GlobalVariable>(constant_init)) {
                    ASSERT(CS->isConstant());
                    constant_init = CS->getInitializer();
                }

                // We need to flatten a complex struct to put it into the memory
                // So we use deep-first search for scalar elements of the struct (or array)
                std::stack<const llvm::Constant *> component_stack;
                component_stack.push(constant_init);
                ptr_type ptr = stack_memory.add_cells(layout_resolver->get_type_layout<BlueprintFieldType>(constant_init->getType()));
                ptr_type res = ptr;
                while (!component_stack.empty()) {
                    const llvm::Constant *constant = component_stack.top();
                    component_stack.pop();
                    llvm::Type *type = constant->getType();
                    if (type->isPointerTy()) {
                        ASSERT_MSG(constant->isZeroValue(), "Only zero initializers are supported for pointers");
                        // TODO: single zero
                        assignmnt.public_input(0, public_input_idx) = 0;
                        stack_memory.store(ptr++, var(0, public_input_idx++, false, var::column_type::public_input));
                        continue;
                    }
                    if (!type->isAggregateType() && !type->isVectorTy()) {
                        assignmnt.public_input(0, public_input_idx) = marshal_int_val(constant);
                        auto variable = var(0, public_input_idx++, false, var::column_type::public_input);
                        stack_memory.store(ptr++, variable);
                        continue;
                    }
                    unsigned num_elements = 0;
                    if (type->isStructTy()) {
                        num_elements = type->getStructNumElements();
                    } else if (type->isVectorTy()) {
                        num_elements = llvm::cast<llvm::FixedVectorType>(type)->getNumElements();
                    } else {
                        ASSERT(type->isArrayTy());
                        num_elements = type->getArrayNumElements();
                    }
                    // Start element must always be on the top of the stack,
                    // so put elements on top in reverse order
                    for (int i = num_elements - 1; i >= 0; --i) {
                        component_stack.push(constant->getAggregateElement(i));
                    }
                }
                return res;
            }

            void memcpy(ptr_type dst, ptr_type src, unsigned offset) {
                size_t border = stack_memory[src - 1].offset + offset;
                while (stack_memory[src - 1].offset < border) {
                    ASSERT(stack_memory[dst].offset - stack_memory[dst - 1].offset ==
                            stack_memory[src].offset - stack_memory[src - 1].offset);
                    stack_memory[dst++].v = stack_memory[src++].v;
                }
            }

            bool handle_intrinsic(const llvm::CallInst *inst, llvm::Intrinsic::ID id, stack_frame<var> &frame, uint32_t start_row) {
                switch (id) {
                    case llvm::Intrinsic::assigner_malloc: {
                        size_t bytes = resolve_number<size_t>(frame, inst->getOperand(0));
                        assignmnt.public_input(0, public_input_idx) = stack_memory.malloc(bytes);
                        frame.scalars[inst] = var(0, public_input_idx++, false, var::column_type::public_input);
                        return true;
                    }
                    case llvm::Intrinsic::assigner_free: {
                        // TODO(maksenov): implement allocator
                        return true;
                    }
                    case llvm::Intrinsic::assigner_poseidon: {
                        using component_type = components::poseidon<ArithmetizationType, BlueprintFieldType>;

                        auto &input_block = frame.vectors[inst->getOperand(0)];
                        std::array<var, component_type::state_size> input_state_var;
                        std::copy(input_block.begin(), input_block.end(), input_state_var.begin());

                        typename component_type::input_type instance_input = {input_state_var};

                        component_type component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, {},
                                                            {});

                        components::generate_circuit(component_instance, bp, assignmnt, instance_input, start_row);

                        typename component_type::result_type component_result =
                            components::generate_assignments(component_instance, assignmnt, instance_input, start_row);

                        std::vector<var> output(component_result.output_state.begin(),
                                                component_result.output_state.end());
                        frame.vectors[inst] = output;
                        return true;
                    }
                    case llvm::Intrinsic::assigner_sha2_256: {
                        handle_sha2_256_component<BlueprintFieldType, ArithmetizationParams>(inst, frame, bp, assignmnt, start_row);
                        return true;
                    }
                    case llvm::Intrinsic::assigner_sha2_512: {
                        handle_sha2_512_component<BlueprintFieldType, ArithmetizationParams>(inst, frame, bp, assignmnt, start_row);
                        return true;
                    }
                    case llvm::Intrinsic::assigner_bit_decomposition64: {
                        handle_integer_bit_decomposition_component<BlueprintFieldType, ArithmetizationParams>(inst, frame, bp, assignmnt, start_row);
                        return true;
                    }
                    case llvm::Intrinsic::assigner_bit_composition128: {
                        handle_integer_bit_composition128_component<BlueprintFieldType, ArithmetizationParams>(inst, frame, bp, assignmnt, start_row);
                        return true;
                    }
                    case llvm::Intrinsic::memcpy: {
                        llvm::Value *src_val = inst->getOperand(1);
                        ptr_type dst = resolve_number<ptr_type>(frame, inst->getOperand(0));
                        ptr_type src = resolve_number<ptr_type>(frame, src_val);
                        unsigned offset = resolve_number<unsigned>(frame, inst->getOperand(2));
                        memcpy(dst, src, offset);
                        return true;
                    }
                    case llvm::Intrinsic::assigner_zkml_convolution: {
                        UNREACHABLE("zkml_convolution intrinsic is not implemented yet");
                        return false;
                    }
                    case llvm::Intrinsic::assigner_zkml_pooling: {
                        UNREACHABLE("zkml_pooling intrinsic is not implemented yet");
                        return false;
                    }
                    case llvm::Intrinsic::assigner_zkml_ReLU: {
                        UNREACHABLE("zkml_ReLU intrinsic is not implemented yet");
                        return false;
                    }
                    case llvm::Intrinsic::assigner_zkml_batch_norm: {
                        UNREACHABLE("zkml_batch_norm intrinsic is not implemented yet");
                        return false;
                    }
                    case llvm::Intrinsic::expect: {
                        var x = frame.scalars[inst->getOperand(0)];
                        frame.scalars[inst] = x;
                        return true;
                    }
                    case llvm::Intrinsic::lifetime_start:
                    case llvm::Intrinsic::lifetime_end:
                        // Nothing to do
                        return true;
                    case llvm::Intrinsic::assigner_curve_init: {
                        handle_curve_init(inst, frame);
                        return true;
                    }
                    default:
                        UNREACHABLE("Unexpected intrinsic!");
                }
                return false;
            }

            void handle_store(ptr_type ptr, const llvm::Value *val, stack_frame<var> & frame) {
                stack_memory[ptr].v = frame.scalars[val];
            }

            void handle_load(ptr_type ptr, const llvm::Value *dest, stack_frame<var> &frame) {
                auto &cell = stack_memory[ptr];
                size_t num_cells = layout_resolver->get_type_layout<BlueprintFieldType>(dest->getType()).size();
                if (num_cells == 1)
                    frame.scalars[dest] = cell.v;
                else {
                    std::vector<var> res;
                    for (size_t i = 0; i < num_cells; ++i) {
                        res.push_back(stack_memory[ptr + i].v);
                        frame.vectors[dest] = res;
                    }
                }
            }


            ptr_type handle_gep(const llvm::GetElementPtrInst* gep, stack_frame<var> &frame) {
                // Collect GEP indices
                std::vector<int> gep_indices;
                for (unsigned i = 0; i < gep->getNumIndices(); ++i) {
                    var idx_var = frame.scalars[gep->getOperand(i + 1)];
                    auto idx_vv = var_value(assignmnt, idx_var);
                    int gep_index = (int)static_cast<typename BlueprintFieldType::integral_type>(idx_vv.data);
                    gep_indices.push_back(gep_index);
                }
                llvm::Type *gep_ty = gep->getSourceElementType();
                ptr_type ptr = resolve_number<ptr_type>(frame, gep->getPointerOperand());

                int initial_ptr_adjustment = layout_resolver->get_type_layout<BlueprintFieldType>(gep_ty).size() * gep_indices[0];
                ptr += initial_ptr_adjustment;
                gep_indices.erase(gep_indices.begin());

                if (!gep_indices.empty()) {
                    if (!gep_ty->isAggregateType()) {
                        std::cerr << "GEP instruction with > 1 indices must operate on aggregate type!"
                                    << std::endl;
                        return 0;
                    }
                    int resolved_index = layout_resolver->get_flat_index<BlueprintFieldType>(gep_ty, gep_indices);
                    ptr += resolved_index;
                }
                return ptr;
            }

            const llvm::Instruction *handle_instruction(const llvm::Instruction *inst) {
                log.log_instruction(inst);
                stack_frame<var> &frame = call_stack.top();
                auto &variables = frame.scalars;
                std::uint32_t start_row = assignmnt.allocated_rows();

                // Put constant operands to public input
                for (int i = 0; i < inst->getNumOperands(); ++i) {
                    llvm::Value *op = inst->getOperand(i);
                    if (variables.find(op) != variables.end()) {
                        continue;
                    }
                    if (llvm::isa<llvm::ConstantField>(op) || llvm::isa<llvm::ConstantInt>(op)) {
                        assignmnt.public_input(0, public_input_idx) = marshal_int_val(op);
                        variables[op] = var(0, public_input_idx++, false, var::column_type::public_input);
                    }
                    if (llvm::isa<llvm::UndefValue>(op)) {
                        llvm::Type *undef_type = op->getType();
                        if (undef_type->isIntegerTy() || undef_type->isFieldTy()) {
                            frame.scalars[op] = undef_var;
                        } else if (auto vector_type = llvm::dyn_cast<llvm::FixedVectorType>(undef_type)) {
                            frame.vectors[op] = std::vector<var>(vector_type->getNumElements(), undef_var);
                        } else {
                            ASSERT(undef_type->isAggregateType());
                            auto layout = layout_resolver->get_type_layout<BlueprintFieldType>(undef_type);
                            ptr_type ptr = stack_memory.add_cells(layout);
                            for (size_t i = 0; i < layout.size(); ++i) {
                                stack_memory.store(ptr+i, undef_var);
                            }
                            assignmnt.public_input(0, public_input_idx) = ptr;
                            frame.scalars[op] = var(0, public_input_idx++, false, var::column_type::public_input);
                        }
                    } else if (llvm::isa<llvm::ConstantPointerNull>(op)) {
                        assignmnt.public_input(0, public_input_idx) = 0;
                        frame.scalars[op] = var(0, public_input_idx++, false, var::column_type::public_input);
                    } else if (llvm::isa<llvm::GlobalValue>(op)) {
                        frame.scalars[op] = globals[op];
                    }
                }

                switch (inst->getOpcode()) {
                    case llvm::Instruction::Add: {

                        if (inst->getOperand(0)->getType()->isIntegerTy()) {
                            handle_integer_addition_component<BlueprintFieldType, ArithmetizationParams>(
                                        inst, frame, bp, assignmnt, start_row);
                            return inst->getNextNonDebugInstruction();
                        }

                        if (inst->getOperand(0)->getType()->isFieldTy() && inst->getOperand(1)->getType()->isFieldTy()) {
                            handle_field_addition_component<BlueprintFieldType, ArithmetizationParams>(
                                        inst, frame, bp, assignmnt, start_row);
                            return inst->getNextNonDebugInstruction();
                        } else if (inst->getOperand(0)->getType()->isCurveTy() && inst->getOperand(1)->getType()->isCurveTy()) {
                            handle_curve_addition_component<BlueprintFieldType, ArithmetizationParams>(
                                        inst, frame, bp, assignmnt, start_row);
                            return inst->getNextNonDebugInstruction();
                        } else {
                            UNREACHABLE("curve + scalar is undefined");
                        }

                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Sub: {
                        if (inst->getOperand(0)->getType()->isIntegerTy()) {
                            handle_integer_subtraction_component<BlueprintFieldType, ArithmetizationParams>(
                                inst, frame, bp, assignmnt, start_row);
                            return inst->getNextNonDebugInstruction();
                        }

                        if (inst->getOperand(0)->getType()->isFieldTy() && inst->getOperand(1)->getType()->isFieldTy()) {
                            handle_field_subtraction_component<BlueprintFieldType, ArithmetizationParams>(
                                inst, frame, bp, assignmnt, start_row);
                            return inst->getNextNonDebugInstruction();
                        } else if (inst->getOperand(0)->getType()->isCurveTy() && inst->getOperand(1)->getType()->isCurveTy()) {
                            handle_curve_subtraction_component<BlueprintFieldType, ArithmetizationParams>(
                                inst, frame, bp, assignmnt, start_row);
                            return inst->getNextNonDebugInstruction();
                        } else {
                            UNREACHABLE("curve - scalar is undefined");
                        }

                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Mul: {

                        if (inst->getOperand(0)->getType()->isIntegerTy()) {
                            handle_integer_multiplication_component<BlueprintFieldType, ArithmetizationParams>(
                                inst, frame, bp, assignmnt, start_row);
                            return inst->getNextNonDebugInstruction();
                        }

                        if (inst->getOperand(0)->getType()->isFieldTy() && inst->getOperand(1)->getType()->isFieldTy()) {
                            handle_field_multiplication_component<BlueprintFieldType, ArithmetizationParams>(
                                inst, frame, bp, assignmnt, start_row);
                            return inst->getNextNonDebugInstruction();
                        }

                        UNREACHABLE("Mul opcode is defined only for fieldTy and integerTy");

                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::CMul: {
                        if (
                            (inst->getOperand(0)->getType()->isCurveTy() && inst->getOperand(1)->getType()->isFieldTy()) ||
                            (inst->getOperand(1)->getType()->isCurveTy() && inst->getOperand(0)->getType()->isFieldTy())) {

                            handle_curve_multiplication_component<BlueprintFieldType, ArithmetizationParams>(
                                inst, frame, bp, assignmnt, start_row);
                            return inst->getNextNonDebugInstruction();
                        } else {
                            UNREACHABLE("cmul opcode is defined only for curveTy * fieldTy");
                        }
                    }
                    case llvm::Instruction::UDiv: {
                        if (inst->getOperand(0)->getType()->isIntegerTy() && inst->getOperand(1)->getType()->isIntegerTy()) {
                            handle_integer_division_remainder_component<BlueprintFieldType, ArithmetizationParams>(
                                inst, frame, bp, assignmnt, start_row, true);
                            return inst->getNextNonDebugInstruction();
                        }
                        else if (inst->getOperand(0)->getType()->isFieldTy() && inst->getOperand(1)->getType()->isFieldTy()) {
                            handle_field_division_component<BlueprintFieldType, ArithmetizationParams>(
                                inst, frame, bp, assignmnt, start_row);
                            return inst->getNextNonDebugInstruction();
                        }
                        else {
                            UNREACHABLE("UDiv opcode is defined only for integerTy and fieldTy");
                        }
                    }
                    case llvm::Instruction::URem: {
                        if (inst->getOperand(0)->getType()->isIntegerTy() && inst->getOperand(1)->getType()->isIntegerTy()) {
                            handle_integer_division_remainder_component<BlueprintFieldType, ArithmetizationParams>(
                                inst, frame, bp, assignmnt, start_row, false);
                            return inst->getNextNonDebugInstruction();
                        } else {
                            UNREACHABLE("URem opcode is defined only for integerTy");
                        }
                    }
                    case llvm::Instruction::Shl: {
                        if (inst->getOperand(0)->getType()->isIntegerTy() && inst->getOperand(1)->getType()->isIntegerTy()) {
                            handle_integer_bit_shift_constant_component<BlueprintFieldType, ArithmetizationParams>(
                                inst, frame, bp, assignmnt, start_row,
                                        nil::blueprint::components::detail::bit_shift_mode::LEFT);
                            return inst->getNextNonDebugInstruction();
                        } else {
                            UNREACHABLE("shl opcode is defined only for integerTy");
                        }
                    }
                    case llvm::Instruction::LShr: {
                        if (inst->getOperand(0)->getType()->isIntegerTy() && inst->getOperand(1)->getType()->isIntegerTy()) {
                            handle_integer_bit_shift_constant_component<BlueprintFieldType, ArithmetizationParams>(
                                inst, frame, bp, assignmnt, start_row,
                                        nil::blueprint::components::detail::bit_shift_mode::RIGHT);
                            return inst->getNextNonDebugInstruction();
                        } else {
                            UNREACHABLE("LShr opcode is defined only for integerTy");
                        }
                    }
                    case llvm::Instruction::SDiv: {

                        if (inst->getOperand(0)->getType()->isIntegerTy()) {
                            handle_integer_division_component<BlueprintFieldType, ArithmetizationParams>(
                                inst, frame, bp, assignmnt, start_row);
                            return inst->getNextNonDebugInstruction();
                        }

                        if (inst->getOperand(0)->getType()->isFieldTy() && inst->getOperand(1)->getType()->isFieldTy()) {
                            handle_field_division_component<BlueprintFieldType, ArithmetizationParams>(
                                inst, frame, bp, assignmnt, start_row);
                            return inst->getNextNonDebugInstruction();
                        }

                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Call: {
                        auto *call_inst = llvm::cast<llvm::CallInst>(inst);
                        auto *fun = call_inst->getCalledFunction();
                        if (fun == nullptr) {
                            std::cerr << "Unresolved call";
                            return nullptr;
                        }
                        llvm::StringRef fun_name = fun->getName();
                        ASSERT(fun->arg_size() == call_inst->getNumOperands() - 1);
                        if (fun->isIntrinsic()) {
                            if (!handle_intrinsic(call_inst, fun->getIntrinsicID(), frame, start_row))
                                return nullptr;
                            return inst->getNextNonDebugInstruction();
                        }
                        if (fun->empty()) {
                            UNREACHABLE("Function " + fun_name.str() + " has no implementation.");
                        }
                        stack_frame<var> new_frame;
                        auto &new_variables = new_frame.scalars;
                        for (int i = 0; i < fun->arg_size(); ++i) {
                            llvm::Argument *arg = fun->getArg(i);
                            llvm::Type *arg_type = arg->getType();
                            if (arg->getType()->isVectorTy() || arg->getType()->isCurveTy() ||
                                (arg->getType()->isFieldTy() && field_arg_num<BlueprintFieldType>(arg_type) > 1))
                                new_frame.vectors[arg] = frame.vectors[call_inst->getOperand(i)];
                            else
                                new_variables[arg] = variables[call_inst->getOperand(i)];

                        }
                        new_frame.caller = call_inst;
                        call_stack.emplace(std::move(new_frame));
                        stack_memory.push_frame();
                        return &fun->begin()->front();
                    }
                    case llvm::Instruction::ICmp: {
                        auto cmp_inst = llvm::cast<const llvm::ICmpInst>(inst);
                        llvm::Type *cmp_type = cmp_inst->getOperand(0)->getType();
                        if (cmp_type->isIntegerTy()|| cmp_type->isFieldTy())
                            handle_scalar_cmp(cmp_inst, variables);
                        else if (cmp_type->isPointerTy())
                            handle_ptr_cmp(cmp_inst, frame);
                        else if (cmp_type->isVectorTy()) {
                            handle_vector_cmp(cmp_inst, frame);
                        }
                        else {
                            UNREACHABLE("Unsupported icmp operand type");
                        }
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Select: {

                        var condition = variables[inst->getOperand(0)];
                        llvm::Value *true_val = inst->getOperand(1);
                        llvm::Value *false_val = inst->getOperand(2);
                        if (var_value(assignmnt, condition) != 0) {
                            variables[inst] = variables[true_val];
                        } else {
                            variables[inst] = variables[false_val];
                        }
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::And: {

                        const var &lhs = variables[inst->getOperand(0)];
                        const var &rhs = variables[inst->getOperand(1)];

                        variables[inst] = handle_bitwise_and_component<BlueprintFieldType, ArithmetizationParams>(
                            lhs, rhs,
                            bp, assignmnt, assignmnt.allocated_rows(), public_input_idx);

                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Or: {

                        const var &lhs = variables[inst->getOperand(0)];
                        const var &rhs = variables[inst->getOperand(1)];

                        variables[inst] = handle_bitwise_or_component<BlueprintFieldType, ArithmetizationParams>(
                            lhs, rhs,
                            bp, assignmnt, assignmnt.allocated_rows(), public_input_idx);

                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Xor: {

                        const var &lhs = variables[inst->getOperand(0)];
                        const var &rhs = variables[inst->getOperand(1)];

                        variables[inst] = handle_bitwise_xor_component<BlueprintFieldType, ArithmetizationParams>(
                            lhs, rhs,
                            bp, assignmnt, assignmnt.allocated_rows(), public_input_idx);

                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Br: {
                        // Save current basic block to resolve PHI inst further
                        predecessor = inst->getParent();

                        if (inst->getNumOperands() != 1) {
                            ASSERT(inst->getNumOperands() == 3);
                            auto false_bb = llvm::cast<llvm::BasicBlock>(inst->getOperand(1));
                            auto true_bb = llvm::cast<llvm::BasicBlock>(inst->getOperand(2));
                            var cond = variables[inst->getOperand(0)];
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
                                llvm::Type *value_type = incoming_value->getType();
                                if (value_type->isIntegerTy() || value_type->isPointerTy() ||
                                           (value_type->isFieldTy() && field_arg_num<BlueprintFieldType>(value_type) == 1)) {
                                    ASSERT(variables.find(incoming_value) != variables.end());
                                    variables[phi_node] = variables[incoming_value];
                                } else {
                                    ASSERT(frame.vectors.find(incoming_value) != frame.vectors.end());
                                    frame.vectors[phi_node] = frame.vectors[incoming_value];
                                }
                                return phi_node->getNextNonDebugInstruction();
                            }
                        }
                        UNREACHABLE("Incoming value for phi was not found");
                        break;
                    }
                    case llvm::Instruction::Switch: {
                        // Save current basic block to resolve PHI inst further
                        predecessor = inst->getParent();

                        auto switch_inst = llvm::cast<llvm::SwitchInst>(inst);
                        llvm::Value *cond = switch_inst->getCondition();
                        ASSERT(cond->getType()->isIntegerTy());
                        unsigned bit_width = llvm::cast<llvm::IntegerType>(cond->getType())->getBitWidth();
                        ASSERT(bit_width <= 64);
                        auto cond_var = var_value(assignmnt, frame.scalars[cond]);
                        auto cond_val = llvm::APInt(
                            bit_width,
                            (int64_t) static_cast<typename BlueprintFieldType::integral_type>(cond_var.data));
                        for (auto Case : switch_inst->cases()) {
                            if (Case.getCaseValue()->getValue().eq(cond_val)) {
                                return &Case.getCaseSuccessor()->front();
                            }
                        }
                        return &switch_inst->getDefaultDest()->front();
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
                        std::vector<var> result_vector;
                        if (llvm::isa<llvm::Constant>(vec)) {
                            auto *vector_type = llvm::cast<llvm::FixedVectorType>(vec->getType());
                            ASSERT(vector_type->getElementType()->isFieldTy());
                            unsigned size = vector_type->getNumElements();
                            result_vector = std::vector<var>(size);
                            if (auto *cv = llvm::dyn_cast<llvm::ConstantVector>(vec)) {
                                for (int i = 0; i < size; ++i) {
                                    llvm::Constant *elem = cv->getAggregateElement(i);
                                    if (llvm::isa<llvm::UndefValue>(elem))
                                        continue;
                                    assignmnt.public_input(0, public_input_idx) = marshal_int_val(elem);
                                    result_vector[i] = var(0, public_input_idx++, false, var::column_type::public_input);
                                }
                            } else {
                                ASSERT_MSG(llvm::isa<llvm::UndefValue>(vec), "Unexpected constant value!");
                            }
                        } else {
                            result_vector = frame.vectors[vec];
                        }
                        result_vector[index] = variables[inst->getOperand(1)];
                        frame.vectors[inst] = result_vector;
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
                        variables[inst] = frame.vectors[vec][index];
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Alloca: {
                        auto *alloca = llvm::cast<llvm::AllocaInst>(inst);
                        auto vec = layout_resolver->get_type_layout<BlueprintFieldType>(alloca->getAllocatedType());

                        ptr_type res_ptr = stack_memory.add_cells(vec);
                        log.debug("Alloca: {}", res_ptr);
                        assignmnt.public_input(0, public_input_idx) = res_ptr;
                        frame.scalars[inst] = var(0, public_input_idx++, false, var::column_type::public_input);
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::GetElementPtr: {
                        auto *gep = llvm::cast<llvm::GetElementPtrInst>(inst);
                        ptr_type gep_res = handle_gep(gep, frame);
                        if (gep_res == 0) {
                            std::cerr << "Incorrect GEP result!" << std::endl;
                            return nullptr;
                        }
                        log.debug("GEP: {}", gep_res);
                        assignmnt.public_input(0, public_input_idx) = gep_res;
                        frame.scalars[gep] = var(0, public_input_idx++, false, var::column_type::public_input);
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Load: {
                        auto *load_inst = llvm::cast<llvm::LoadInst>(inst);
                        ptr_type ptr = resolve_number<ptr_type>(frame, load_inst->getPointerOperand());
                        log.debug("Load: {}", ptr);
                        handle_load(ptr, load_inst, frame);
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Store: {
                        auto *store_inst = llvm::cast<llvm::StoreInst>(inst);
                        ptr_type ptr = resolve_number<ptr_type>(frame, store_inst->getPointerOperand());
                        log.debug("Store ", ptr);
                        const llvm::Value *val = store_inst->getValueOperand();
                        handle_store(ptr, val, frame);
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::InsertValue: {
                        auto *insert_inst = llvm::cast<llvm::InsertValueInst>(inst);
                        ptr_type ptr = resolve_number<ptr_type>(frame, insert_inst->getAggregateOperand());
                        ptr += layout_resolver->get_flat_index<BlueprintFieldType>(
                            insert_inst->getAggregateOperand()->getType(), insert_inst->getIndices());
                        stack_memory.store(ptr, frame.scalars[insert_inst->getInsertedValueOperand()]);
                        frame.scalars[inst] = frame.scalars[insert_inst->getAggregateOperand()];
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::ExtractValue: {
                        auto *extract_inst = llvm::cast<llvm::ExtractValueInst>(inst);
                        ptr_type ptr = resolve_number<ptr_type>(frame, extract_inst->getAggregateOperand());
                        ptr += layout_resolver->get_flat_index<BlueprintFieldType>(
                            extract_inst->getAggregateOperand()->getType(), extract_inst->getIndices());
                        frame.scalars[inst] = stack_memory.load(ptr);
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::PtrToInt: {
                        ptr_type ptr = resolve_number<ptr_type>(frame, inst->getOperand(0));
                        assignmnt.public_input(0, public_input_idx) = stack_memory[ptr - 1].offset;
                        frame.scalars[inst] = var(0, public_input_idx++, false, var::column_type::public_input);
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Trunc: {
                        // FIXME: Handle trunc properly. For now just leave value as it is.
                        var x = frame.scalars[inst->getOperand(0)];
                        frame.scalars[inst] = x;
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::SExt:
                    case llvm::Instruction::ZExt: {
                        // FIXME: Handle extensions properly. For now just leave value as it is.
                        var x = frame.scalars[inst->getOperand(0)];
                        frame.scalars[inst] = x;
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Ret: {
                        auto extracted_frame = std::move(call_stack.top());
                        call_stack.pop();
                        stack_memory.pop_frame();
                        if (extracted_frame.caller == nullptr) {
                            // Final return
                            ASSERT(call_stack.size() == 0);
                            finished = true;

                            if(PrintCircuitOutput) {
                                if (inst->getNumOperands() != 0) {
                                    llvm::Value *ret_val = inst->getOperand(0);
                                    if (ret_val->getType()->isPointerTy()) {
                                        // TODO(maksenov): support printing complex results
                                    } else if (ret_val->getType()->isVectorTy()) {
                                        std::vector<var> res = extracted_frame.vectors[ret_val];
                                        for (var x : res) {
                                            std::cout << var_value(assignmnt, x).data << " ";
                                        }
                                        std::cout << std::endl;
                                    } else {
                                        std::cout << var_value(assignmnt, extracted_frame.scalars[ret_val]).data << std::endl;
                                    }
                                }
                            }

                            return nullptr;
                        }
                        if (inst->getNumOperands() != 0) {
                            llvm::Value *ret_val = inst->getOperand(0);
                            llvm::Type *ret_type= ret_val->getType();
                            if (ret_type->isVectorTy()) {
                                auto &upper_frame_vectors = call_stack.top().vectors;
                                auto res = extracted_frame.vectors[ret_val];
                                upper_frame_vectors[extracted_frame.caller] = res;
                            } else if (ret_type->isAggregateType()) {
                                ptr_type ret_ptr = resolve_number<ptr_type>(extracted_frame, ret_val);
                                ptr_type allocated_copy = stack_memory.add_cells(
                                    layout_resolver->get_type_layout<BlueprintFieldType>(ret_type));
                                auto size = layout_resolver->get_type_size(ret_type);
                                // TODO(maksenov): check if overwriting is possible here
                                //                 (looks like it is not)
                                memcpy(allocated_copy, ret_ptr, size);
                                auto &upper_frame_variables = call_stack.top().scalars;

                                upper_frame_variables[extracted_frame.caller] = extracted_frame.scalars[ret_val];
                                assignmnt.public_input(0, public_input_idx) = allocated_copy;
                                upper_frame_variables[extracted_frame.caller] = var(0, public_input_idx++, false, var::column_type::public_input);
                            } else {
                                auto &upper_frame_variables = call_stack.top().scalars;
                                upper_frame_variables[extracted_frame.caller] = extracted_frame.scalars[ret_val];
                            }
                        }
                        return extracted_frame.caller->getNextNonDebugInstruction();
                    }

                    default:
                        UNREACHABLE(std::string("Unsupported opcode type: ") + inst->getOpcodeName());
                }
                return nullptr;
            }

        public:
            std::unique_ptr<llvm::Module> parseIRFile(const char *ir_file) {
                llvm::SMDiagnostic diagnostic;
                std::unique_ptr<llvm::Module> module = llvm::parseIRFile(ir_file, diagnostic, context);
                if (module == nullptr) {
                    diagnostic.print("assigner", llvm::errs());
                }
                return module;
            }

            bool evaluate(const llvm::Module &module, const boost::json::array &public_input) {
                layout_resolver = std::make_unique<LayoutResolver>(module.getDataLayout());
                stack_frame<var> base_frame;
                auto &variables = base_frame.scalars;
                base_frame.caller = nullptr;
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

                auto public_input_reader = PublicInputReader<BlueprintFieldType, var, assignment<ArithmetizationType>>(
                    base_frame, stack_memory, assignmnt, *layout_resolver);
                if (!public_input_reader.fill_public_input(function, public_input)) {
                    std::cerr << "Public input does not match the circuit signature";
                    const std::string &error = public_input_reader.get_error();
                    if (!error.empty()) {
                        std::cout << ": " << error;
                    }
                    std::cout << std::endl;
                    return false;
                }
                public_input_idx = public_input_reader.get_idx();
                call_stack.emplace(std::move(base_frame));

                for (const llvm::GlobalVariable &global : module.getGlobalList()) {

                    const llvm::Constant *initializer = global.getInitializer();
                    if (initializer->getType()->isAggregateType()) {
                        ptr_type ptr = store_constant<var>(initializer);
                        assignmnt.public_input(0, public_input_idx) = ptr;
                        globals[&global] = var(0, public_input_idx++, false, var::column_type::public_input);
                    } else if (initializer->getType()->isIntegerTy() || initializer->getType()->isFieldTy()) {
                        ptr_type ptr = stack_memory.add_cells({layout_resolver->get_type_size(initializer->getType())});
                        assignmnt.public_input(0, public_input_idx) = marshal_int_val(initializer);
                        stack_memory.store(ptr, var(0, public_input_idx++, false, var::column_type::public_input));
                        assignmnt.public_input(0, public_input_idx) = ptr;
                        globals[&global] = var(0, public_input_idx++, false, var::column_type::public_input);
                    } else {
                        UNREACHABLE("Unhandled global variable");
                    }
                }

                // Initialize undef var once
                assignmnt.public_input(0, public_input_idx) = typename BlueprintFieldType::value_type();
                undef_var = var(0, public_input_idx++, false, var::column_type::public_input);

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
            program_memory<var> stack_memory;
            std::map<const llvm::Value *, var> globals;
            bool finished = false;
            size_t public_input_idx = 0;
            std::unique_ptr<LayoutResolver> layout_resolver;
            var undef_var;
            logger log;
        };

    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENT_INSTRUCTION_PARSER_HPP
