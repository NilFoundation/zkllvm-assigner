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
#include <nil/blueprint/gep_resolver.hpp>
#include <nil/blueprint/public_input.hpp>
#include <nil/blueprint/non_native_marshalling.hpp>
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

            parser(bool detailed_logging) {
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

                // Todo: this either isn't a proper way to handle vector element size or it's not implemented correctly
                std::size_t bitness = inst->getOperand(0)->getType()->getScalarType()->getPrimitiveSizeInBits();
                for (size_t i = 0; i < lhs.size(); ++i) {
                    res.emplace_back(handle_comparison_component<BlueprintFieldType, ArithmetizationParams>(
                        inst->getPredicate(), lhs[i], rhs[i], bitness,
                        bp, assignmnt, assignmnt.allocated_rows(), public_input_idx));
                }
                frame.vectors[inst] = res;
            }

            void handle_curve_cmp(const llvm::ICmpInst *inst, stack_frame<var> &frame) {
                switch (inst->getPredicate()) {
                case llvm::CmpInst::ICMP_EQ: {
                    handle_vector_cmp(inst, frame);
                }
                case llvm::CmpInst::ICMP_NE:{
                    handle_vector_cmp(inst, frame);
                    break;
                }
                default:
                    UNREACHABLE("Curve element cmp is inplemented only for EQ and NE");
                    break;
                }
            }

            void handle_ptr_cmp(const llvm::ICmpInst *inst, stack_frame<var> &frame) {
                Pointer<var> lhs = frame.pointers[inst->getOperand(0)];
                Pointer<var> rhs = frame.pointers[inst->getOperand(1)];
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

            template<typename FieldType>
            std::vector<typename BlueprintFieldType::value_type> field_dependent_marshal_val(const llvm::Value *val) {
                ASSERT(llvm::isa<llvm::ConstantField>(val) || llvm::isa<llvm::ConstantInt>(val));
                llvm::APInt int_val;
                if (llvm::isa<llvm::ConstantField>(val)) {
                    int_val = llvm::cast<llvm::ConstantField>(val)->getValue();
                } else {
                    int_val = llvm::cast<llvm::ConstantInt>(val)->getValue();
                }
                unsigned words = int_val.getNumWords();
                typename FieldType::value_type field_constant;
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
                return value_into_vector<BlueprintFieldType, FieldType>(field_constant);
            }

            std::vector<typename BlueprintFieldType::value_type> marshal_field_val(const llvm::Value *val) {

                ASSERT(llvm::isa<llvm::ConstantField>(val) || llvm::isa<llvm::ConstantInt>(val));
                if (llvm::isa<llvm::ConstantInt>(val)) {
                    return field_dependent_marshal_val<BlueprintFieldType>(val);
                } else {
                    switch (llvm::cast<llvm::GaloisFieldType>(val->getType())->getFieldKind()) {
                        case llvm::GALOIS_FIELD_CURVE25519_BASE: {
                            using operating_field_type = typename nil::crypto3::algebra::curves::ed25519::base_field_type;
                            return field_dependent_marshal_val<operating_field_type>(val);
                        }
                        case llvm::GALOIS_FIELD_CURVE25519_SCALAR: {
                            using operating_field_type = typename nil::crypto3::algebra::curves::ed25519::scalar_field_type;
                            return field_dependent_marshal_val<operating_field_type>(val);
                        }
                        case llvm::GALOIS_FIELD_PALLAS_BASE: {
                            using operating_field_type = typename nil::crypto3::algebra::curves::pallas::base_field_type;
                            return field_dependent_marshal_val<operating_field_type>(val);
                        }
                        case llvm::GALOIS_FIELD_PALLAS_SCALAR: {
                            using operating_field_type = typename nil::crypto3::algebra::curves::pallas::scalar_field_type;
                            return field_dependent_marshal_val<operating_field_type>(val);
                        }
                        default:
                            UNREACHABLE("unsupported field operand type");
                    }
                }
            }

            typename BlueprintFieldType::integral_type unmarshal_field_val(const llvm::GaloisFieldKind field_type, std::vector<typename BlueprintFieldType::value_type> input) {
                switch (field_type) {
                    case llvm::GALOIS_FIELD_CURVE25519_BASE: {
                        using operating_field_type = typename nil::crypto3::algebra::curves::ed25519::base_field_type;
                        return typename BlueprintFieldType::integral_type(vector_into_value<BlueprintFieldType, operating_field_type>(input).data);
                    }
                    case llvm::GALOIS_FIELD_CURVE25519_SCALAR: {
                        using operating_field_type = typename nil::crypto3::algebra::curves::ed25519::scalar_field_type;
                        return typename BlueprintFieldType::integral_type(vector_into_value<BlueprintFieldType, operating_field_type>(input).data);
                    }
                    case llvm::GALOIS_FIELD_PALLAS_BASE: {
                        using operating_field_type = typename nil::crypto3::algebra::curves::pallas::base_field_type;
                        return typename BlueprintFieldType::integral_type(vector_into_value<BlueprintFieldType, operating_field_type>(input).data);
                    }
                    case llvm::GALOIS_FIELD_PALLAS_SCALAR: {
                        using operating_field_type = typename nil::crypto3::algebra::curves::pallas::scalar_field_type;
                        return typename BlueprintFieldType::integral_type(vector_into_value<BlueprintFieldType, operating_field_type>(input).data);
                    }
                    default:
                        UNREACHABLE("unsupported field operand type");
                }
            }


            Pointer<var> resolve_pointer(stack_frame<var> &frame, const llvm::Value *ptr_value) {
                if (llvm::isa<llvm::GlobalVariable>(ptr_value)) {
                    return globals[ptr_value];
                }
                ASSERT(frame.pointers.find(ptr_value) != frame.pointers.end());
                return frame.pointers[ptr_value];
            }

            template<typename VarType>
            Chunk<VarType> store_constant(const llvm::Constant *constant_init) {
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

                // We need to flatten a complex struct to put it into a chunk
                // So we use deep-first search for scalar elements of the struct (or array)
                Chunk<var> chunk;
                unsigned idx = 0;
                std::stack<const llvm::Constant *> component_stack;
                component_stack.push(constant_init);
                while (!component_stack.empty()) {
                    const llvm::Constant *constant = component_stack.top();
                    component_stack.pop();
                    llvm::Type *type = constant->getType();
                    if (!type->isAggregateType()) {
                        std::vector<typename BlueprintFieldType::value_type> marshalled_field_val = marshal_field_val(constant);
                        if (marshalled_field_val.size() == 1) {
                            assignmnt.public_input(0, public_input_idx) = marshalled_field_val[0];
                            auto variable = var(0, public_input_idx++, false, var::column_type::public_input);
                            chunk.store_var(variable, idx++);
                            continue;
                        } else {
                            std::vector<var> non_native_var(marshalled_field_val.size());
                            for(std::size_t i = 0; i < marshalled_field_val.size(); i++) {
                                assignmnt.public_input(0, public_input_idx) = marshalled_field_val[i];
                                non_native_var[i] = var(0, public_input_idx++, false, var::column_type::public_input);
                            }
                            chunk.store_vector(non_native_var, idx++);
                            continue;
                        }
                    }
                    unsigned num_elements = 0;
                    if (llvm::isa<llvm::StructType>(type)) {
                        num_elements = type->getStructNumElements();
                    } else {
                        num_elements = type->getArrayNumElements();
                    }
                    // Start element must always be on the top of the stack,
                    // so put elements on top in reverse order
                    for (int i = num_elements - 1; i >= 0; --i) {
                        component_stack.push(constant->getAggregateElement(i));
                    }
                }
                return chunk;
            }

            bool handle_intrinsic(const llvm::CallInst *inst, llvm::Intrinsic::ID id, stack_frame<var> &frame, uint32_t start_row) {
                switch (id) {
                    case llvm::Intrinsic::assigner_malloc: {
                        global_data.emplace_back();
                        frame.pointers[inst] = Pointer<var>{&global_data.back(), 0};
                        return true;
                    }
                    case llvm::Intrinsic::assigner_free: {
                        Pointer<var> ptr = resolve_pointer(frame, inst->getOperand(0));
                        Chunk<var> *chunk = ptr.get_base();
                        auto entry = std::find_if(global_data.begin(), global_data.end(),
                                  [chunk](const Chunk<var> &elem) { return &elem == chunk; });
                        global_data.erase(entry);
                        return true;
                    }
                    case llvm::Intrinsic::assigner_poseidon: {
                        using component_type = components::poseidon<ArithmetizationType, BlueprintFieldType, 15>;

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
                        Pointer<var> dst = resolve_pointer(frame, inst->getOperand(0));
                        llvm::Value *src_val = inst->getOperand(1);
                        if (auto constant = llvm::dyn_cast<llvm::Constant>(src_val)) {
                            auto chunk = store_constant<var>(constant);
                            dst.memcpy(&chunk);
                        } else {
                            Pointer<var> src = resolve_pointer(frame, src_val);
                            dst.memcpy(src);
                        }
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

            void handle_store(Pointer<var> ptr, const llvm::Value *val, stack_frame<var> & frame) {
                llvm::Type *store_type = val->getType();
                if (store_type->isPointerTy()) {
                    ptr.store_pointer(frame.pointers[val]);
                } else if (store_type->isIntegerTy() ||
                            (store_type->isFieldTy() && field_arg_num<BlueprintFieldType>(store_type) == 1)) {
                    ptr.store_var(frame.scalars[val]);
                } else {
                    ptr.store_vector(frame.vectors[val]);
                }
            }
            void handle_load(Pointer<var> ptr, const llvm::Value *dest, stack_frame<var> & frame) {
                llvm::Type *load_type = dest->getType();
                if (load_type->isPointerTy()) {
                    frame.pointers[dest] = ptr.load_pointer();
                } else if (load_type->isIntegerTy() ||
                            (load_type->isFieldTy() && field_arg_num<BlueprintFieldType>(load_type) == 1)) {
                    frame.scalars[dest] = ptr.load_var();
                } else {
                    frame.vectors[dest] = ptr.load_vector();
                }
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
                        std::vector<typename BlueprintFieldType::value_type> marshalled_field_val = marshal_field_val(op);
                        if (marshalled_field_val.size() == 1) {
                            assignmnt.public_input(0, public_input_idx) = marshalled_field_val[0];
                            variables[op] = var(0, public_input_idx++, false, var::column_type::public_input);
                        }
                        else {
                            for (std::size_t i = 0; i < marshalled_field_val.size(); i++) {
                                assignmnt.public_input(0, public_input_idx) = marshalled_field_val[i];
                                frame.vectors[op].push_back(var(0, public_input_idx++, false, var::column_type::public_input));
                            }
                        }
                    }
                    if (llvm::isa<llvm::UndefValue>(op)) {
                        llvm::Type *undef_type = op->getType();
                        if (undef_type->isIntegerTy() || undef_type->isFieldTy()) {
                            variables[op] = undef_var;
                        } else if (auto vector_type = llvm::dyn_cast<llvm::FixedVectorType>(undef_type)) {
                            frame.vectors[op] = std::vector<var>(vector_type->getNumElements(), undef_var);
                        } else {
                            ASSERT(undef_type->isAggregateType());
                            frame.memory.emplace_back();
                            frame.pointers[op] = Pointer<var>{&frame.memory.back(), 0};
                        }
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
                            if (arg->getType()->isPointerTy())
                                new_frame.pointers[arg] = frame.pointers[call_inst->getOperand(i)];
                            else if (arg->getType()->isVectorTy() || arg->getType()->isCurveTy() ||
                                    (arg->getType()->isFieldTy() && field_arg_num<BlueprintFieldType>(arg->getType()) > 1)) {
                                new_frame.vectors[arg] = frame.vectors[call_inst->getOperand(i)];
                            }
                            else
                                new_variables[arg] = variables[call_inst->getOperand(i)];

                        }
                        new_frame.caller = call_inst;
                        call_stack.emplace(std::move(new_frame));
                        return &fun->begin()->front();
                    }
                    case llvm::Instruction::ICmp: {
                        auto cmp_inst = llvm::cast<const llvm::ICmpInst>(inst);
                        llvm::Type *cmp_type = cmp_inst->getOperand(0)->getType();
                        if (cmp_type->isIntegerTy()|| cmp_type->isFieldTy())
                            handle_scalar_cmp(cmp_inst, variables);
                        else if (cmp_type->isPointerTy())
                            handle_ptr_cmp(cmp_inst, frame);
                        else if (cmp_type->isVectorTy())
                            handle_vector_cmp(cmp_inst, frame);
                        else if (cmp_type->isCurveTy())
                            handle_curve_cmp(cmp_inst, frame);
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
                                if (value_type->isPointerTy()) {
                                    ASSERT(frame.pointers.find(incoming_value) != frame.pointers.end());
                                    frame.pointers[phi_node] = frame.pointers[incoming_value];
                                } else if (value_type->isIntegerTy() ||
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
                                    std::vector<typename BlueprintFieldType::value_type> marshalled_field_val = marshal_field_val(elem);
                                    if (marshalled_field_val.size() != 1) {
                                        UNREACHABLE("not implemented yet"); //TODO implement
                                    }
                                    assignmnt.public_input(0, public_input_idx) = marshalled_field_val[0];
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
                    case llvm::Instruction::Alloca:
                        frame.memory.emplace_back();
                        frame.pointers[inst] = Pointer<var>{&frame.memory.back(), 0};
                        return inst->getNextNonDebugInstruction();
                    case llvm::Instruction::GetElementPtr: {
                        auto *gep = llvm::cast<llvm::GetElementPtrInst>(inst);
                        // Collect GEP indices
                        std::vector<int> gep_indices;
                        for (unsigned i = 0; i < gep->getNumIndices(); ++i) {
                            var idx_var = variables[gep->getOperand(i + 1)];
                            auto idx_vv = var_value(assignmnt, idx_var);
                            int gep_index = (int)static_cast<typename BlueprintFieldType::integral_type>(idx_vv.data);
                            gep_indices.push_back(gep_index);
                        }
                        const llvm::Type *gep_ty = gep->getSourceElementType();
                        Pointer<var> ptr = resolve_pointer(frame, gep->getPointerOperand());

                        int initial_ptr_adjustment = gep_resolver.get_type_size(gep_ty) * gep_indices[0];
                        ptr = ptr.adjust(initial_ptr_adjustment);
                        gep_indices.erase(gep_indices.begin());

                        if (!gep_indices.empty()) {
                            if (!gep_ty->isAggregateType()) {
                                std::cerr << "GEP instruction with > 1 indices must operate on aggregate type!"
                                          << std::endl;
                                return nullptr;
                            }
                            int resolved_index = gep_resolver.get_flat_index(gep_ty, gep_indices);
                            ptr = ptr.adjust(resolved_index);
                        }
                        frame.pointers[gep] = ptr;
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Load: {
                        auto *load_inst = llvm::cast<llvm::LoadInst>(inst);
                        Pointer<var> ptr = resolve_pointer(frame, load_inst->getPointerOperand());
                        handle_load(ptr, load_inst, frame);
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Store: {
                        auto *store_inst = llvm::cast<llvm::StoreInst>(inst);
                        Pointer<var> ptr = resolve_pointer(frame, store_inst->getPointerOperand());
                        const llvm::Value *val = store_inst->getValueOperand();
                        handle_store(ptr, val, frame);
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::InsertValue: {
                        auto *insert_val_inst = llvm::cast<llvm::InsertValueInst>(inst);
                        frame.memory.emplace_back();
                        auto res = Pointer<var>{&frame.memory.back(), 0};
                        frame.pointers[inst] = res;
                        Pointer<var> src = frame.pointers[inst->getOperand(0)];
                        res.memcpy(src);
                        int idx = gep_resolver.get_flat_index(inst->getType(), insert_val_inst->getIndices());
                        handle_store(res.adjust(idx), inst->getOperand(1), frame);
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::ExtractValue: {
                        auto *extract_val_inst = llvm::cast<llvm::ExtractValueInst>(inst);
                        const llvm::Value *aggregate = extract_val_inst->getAggregateOperand();
                        Pointer<var> ptr = frame.pointers[aggregate];
                        int idx = gep_resolver.get_flat_index(aggregate->getType(), extract_val_inst->getIndices());
                        handle_load(ptr.adjust(idx), extract_val_inst, frame);
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::BitCast: {
                        // just return pointer argument as is
                        frame.pointers[inst] = resolve_pointer(frame, inst->getOperand(0));
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
                        if (extracted_frame.caller == nullptr) {
                            // Final return
                            ASSERT(call_stack.size() == 0);
                            finished = true;

                            if(PrintCircuitOutput) {
                                if (inst->getNumOperands() != 0) {
                                    llvm::Value *ret_val = inst->getOperand(0);
                                    if (ret_val->getType()->isPointerTy()) {
                                        auto res = extracted_frame.pointers[ret_val];
                                    } else if (ret_val->getType()->isVectorTy()) {
                                        std::vector<var> res = extracted_frame.vectors[ret_val];
                                        for (var x : res) {
                                            std::cout << var_value(assignmnt, x).data << " ";
                                        }
                                        std::cout << std::endl;
                                    } else if (ret_val->getType()->isFieldTy() && field_arg_num<BlueprintFieldType>(ret_val->getType()) > 1) {
                                        std::vector<var> res = extracted_frame.vectors[ret_val];
                                        std::vector<typename BlueprintFieldType::value_type> chopped_field;
                                        for (std::size_t i = 0; i < res.size(); i++) {
                                            chopped_field.push_back(var_value(assignmnt, res[i]));
                                        }
                                        llvm::GaloisFieldKind ret_field_type;
                                        if (llvm::isa<llvm::GaloisFieldType>(ret_val->getType())) {
                                            ret_field_type = llvm::cast<llvm::GaloisFieldType>(ret_val->getType())->getFieldKind();
                                        }
                                        else {UNREACHABLE("public input reader take_field can handle only fields");}

                                        std::cout << unmarshal_field_val(ret_field_type, chopped_field) << std::endl;

                                    } else if (ret_val->getType()->isCurveTy()) {
                                        std::size_t curve_len = curve_arg_num<BlueprintFieldType>(ret_val->getType());
                                        if (curve_len == 2) {
                                            std::cout << var_value(assignmnt, extracted_frame.vectors[ret_val][0]).data << "\n";
                                            std::cout << var_value(assignmnt, extracted_frame.vectors[ret_val][1]).data << "\n";
                                        }
                                        else if(curve_len > 2) {
                                            llvm::GaloisFieldKind ret_field_type;
                                            if (llvm::isa<llvm::EllipticCurveType>(ret_val->getType())) {
                                                ret_field_type  = llvm::cast<llvm::EllipticCurveType>(ret_val->getType())->GetBaseFieldKind();
                                            }
                                            else {UNREACHABLE("public input reader take_field can handle only fields");}

                                            std::vector<var> res = extracted_frame.vectors[ret_val];

                                            std::vector<typename BlueprintFieldType::value_type> chopped_field_x;
                                            std::vector<typename BlueprintFieldType::value_type> chopped_field_y;
                                            for (std::size_t i = 0; i < curve_len / 2; i++) {
                                                chopped_field_x.push_back(var_value(assignmnt, res[i]));
                                                chopped_field_y.push_back(var_value(assignmnt, res[i + (curve_len/2)]));
                                            }
                                            std::cout << unmarshal_field_val(ret_field_type, chopped_field_x) << std::endl;
                                            std::cout << unmarshal_field_val(ret_field_type, chopped_field_y) << std::endl;

                                        }
                                        else {
                                            UNREACHABLE("curve_arg_num mest be >= 2");
                                        }
                                    } else {
                                        std::cout << var_value(assignmnt, extracted_frame.scalars[ret_val]).data << std::endl;
                                    }
                                }
                            }

                            return nullptr;
                        }
                        if (inst->getNumOperands() != 0) {
                            llvm::Value *ret_val = inst->getOperand(0);
                            if (ret_val->getType()->isPointerTy()) {
                                auto &upper_frame_pointers = call_stack.top().pointers;
                                auto res = extracted_frame.pointers[ret_val];
                                upper_frame_pointers[extracted_frame.caller] = res;
                            } else if (ret_val->getType()->isVectorTy() || ret_val->getType()->isCurveTy()
                                    || (ret_val->getType()->isFieldTy() && field_arg_num<BlueprintFieldType>(ret_val->getType()) > 1)) {
                                auto &upper_frame_vectors = call_stack.top().vectors;
                                auto res = extracted_frame.vectors[ret_val];
                                upper_frame_vectors[extracted_frame.caller] = res;
                            } else if (ret_val->getType()->isAggregateType()) {
                                auto &upper_frame_pointers = call_stack.top().pointers;
                                call_stack.top().memory.emplace_back();
                                Pointer<var> new_ptr = Pointer<var> {&call_stack.top().memory.back(), 0};
                                new_ptr.memcpy(extracted_frame.pointers[ret_val]);
                                upper_frame_pointers[extracted_frame.caller] = new_ptr;
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

                stack_frame<var> base_frame;
                auto &variables = base_frame.scalars;
                auto &pointers = base_frame.pointers;
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
                    base_frame, assignmnt);
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

                    Pointer<var> ptr;
                    const llvm::Constant *initializer = global.getInitializer();
                    if (initializer->getType()->isAggregateType()) {
                        auto r = store_constant<var>(initializer);
                        global_data.push_back(r);
                        ptr = Pointer<var>(&global_data.back(), 0);
                    } else if (initializer->getType()->isIntegerTy() || initializer->getType()->isFieldTy()) {
                        global_data.emplace_back();
                        ptr = Pointer<var>(&global_data.back(), 0);
                        std::vector<typename BlueprintFieldType::value_type> marshalled_field_val = marshal_field_val(initializer);
                        if (marshalled_field_val.size() != 1) {
                            UNREACHABLE("not implemented yet"); //TODO implement
                        }
                        assignmnt.public_input(0, public_input_idx) = marshalled_field_val[0];
                        ptr.store_var(var(0, public_input_idx++, false, var::column_type::public_input));
                    } else {
                        // Unhandled global variable type
                        // We don't want to panic right here, because this value is likely unused
                        // So just store null pointer to crash on its usage
                        ptr = Pointer<var>(nullptr, 0);
                    }
                    globals[&global] = ptr;
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
            std::map<const llvm::Value *, Pointer<var>> globals;
            std::list<Chunk<var>> global_data;
            bool finished = false;
            size_t public_input_idx = 0;
            GepResolver gep_resolver;
            var undef_var;
            logger log;
        };

    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENT_INSTRUCTION_PARSER_HPP
