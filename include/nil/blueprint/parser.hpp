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

#include <boost/format.hpp>
#include <boost/log/trivial.hpp>

#include <nil/blueprint/blueprint/plonk/assignment_proxy.hpp>
#include <nil/blueprint/blueprint/plonk/circuit_proxy.hpp>
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
#include "llvm/IR/GetElementPtrTypeIterator.h"

#include <nil/blueprint/logger.hpp>
#include <nil/blueprint/layout_resolver.hpp>
#include <nil/blueprint/input_reader.hpp>
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

#include <nil/blueprint/boolean/logic_ops.hpp>

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

#include <nil/blueprint/handle_component.hpp>

#include <nil/blueprint/recursive_prover/fri_lin_inter.hpp>
#include <nil/blueprint/recursive_prover/fri_cosets.hpp>
#include <nil/blueprint/recursive_prover/gate_arg_verifier.hpp>
#include <nil/blueprint/recursive_prover/permutation_arg_verifier.hpp>
#include <nil/blueprint/recursive_prover/lookup_arg_verifier.hpp>
#include <nil/blueprint/recursive_prover/fri_array_swap.hpp>

#include <nil/blueprint/bls_signature/bls12_381_pairing.hpp>
#include <nil/blueprint/bls_signature/fp12_multiplication.hpp>
#include <nil/blueprint/bls_signature/is_in_g1.hpp>
#include <nil/blueprint/bls_signature/is_in_g2.hpp>
#include <nil/blueprint/bls_signature/h2c.hpp>
#include <nil/blueprint/component_mockups/comparison.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/pairing/bls12.hpp>
#include <nil/crypto3/algebra/algorithms/pair.hpp>

namespace nil {
    namespace blueprint {

        enum print_format {
            no_print,
            dec,
            hex
        };

        template<typename BlueprintFieldType, typename ArithmetizationParams>
        struct parser {

            parser(long stack_size, boost::log::trivial::severity_level log_level, std::uint32_t max_num_provers, std::uint32_t target_prover_idx, generation_mode gen_mode,
                   const std::string &kind = "", print_format output_print_format = no_print, bool check_validity = false, bool size_estimation = false) :
                stack_memory(stack_size),
                maxNumProvers(max_num_provers),
                targetProverIdx(target_prover_idx),
                currProverIdx(0),
                log(log_level),
                print_output_format(output_print_format),
                validity_check(check_validity),
                estimate_size(size_estimation),
                gen_mode(gen_mode)
            {

                detail::PolicyManager::set_policy(kind);

                assignment_ptr = std::make_shared<assignment<ArithmetizationType>>();
                bp_ptr = std::make_shared<circuit<ArithmetizationType>>();
                assignments.emplace_back(assignment_ptr, currProverIdx);
                circuits.emplace_back(bp_ptr, currProverIdx);
            }

            using ArithmetizationType =
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
            using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
            using branch_desc = std::pair<bool/*is true branch*/, std::uint32_t/*size of call_stack on start branch*/>;

            std::vector<circuit_proxy<ArithmetizationType>> circuits;
            std::vector<assignment_proxy<ArithmetizationType>> assignments;

        private:

            struct ParserState {
                ParserState(const parser& p) {
                    predecessor = p.predecessor;
                    currProverIdx = p.currProverIdx;
                    cpp_values = p.cpp_values;
                    gen_mode = p.gen_mode;
                    finished = p.finished;
                }
                const llvm::BasicBlock *predecessor;
                std::uint32_t currProverIdx;
                std::vector<const void *> cpp_values;
                generation_mode gen_mode;
                bool finished;
            };

            bool check_operands_constantness(const llvm::CallInst *inst, std::vector<std::size_t> constants_positions, stack_frame<var> &frame) {
                bool is_const;
                for (std::size_t i = 0; i < inst->getNumOperands() - 1; i++) {
                    is_const = false;
                    for (std::size_t j = 0; j < constants_positions.size(); j++) {
                        if(i == constants_positions[j]) {
                            ASSERT(constants_positions[j] < inst->getNumOperands() - 1);
                            is_const = true;
                            if(!llvm::isa<llvm::Constant>(inst->getOperand(i))) {
                                std::cerr << "\noperand " << i << " must be constant, but it is not\n";
                                return false;
                            }
                            break;
                        }
                    }
                    if(!is_const && llvm::isa<llvm::Constant>(inst->getOperand(i))) {
                        put_constant(llvm::cast<llvm::Constant>(inst->getOperand(i)), frame);
                    }
                }
                return true;
            }


            std::uint32_t extract_prover_idx_metadata(const llvm::Instruction *inst) {
                const llvm::MDNode* metaDataNode = inst->getMetadata("zk_multi_prover");
                if (metaDataNode) {
                    const llvm::MDString *MDS = llvm::dyn_cast<llvm::MDString>(metaDataNode->getOperand(0));
                    return std::stoi(MDS->getString().str());
                }
                return currProverIdx;
            }

            template<typename map_type>
            void handle_scalar_cmp(const llvm::ICmpInst *inst, map_type &frame) {
                auto &variables = frame.scalars;
                const var &lhs = variables[inst->getOperand(0)];
                const var &rhs = variables[inst->getOperand(1)];

                llvm::CmpInst::Predicate p = inst->getPredicate();

                using eq_component_type = components::equality_flag<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, BlueprintFieldType>;
                using comp_component_type = components::comparison<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, BlueprintFieldType>;

                if (p == llvm::CmpInst::ICMP_EQ || p ==llvm::CmpInst::ICMP_NE) {
                    std::size_t bitness = inst->getOperand(0)->getType()->getPrimitiveSizeInBits();
                    const common_component_parameters param = {assignments[currProverIdx].allocated_rows(), targetProverIdx, gen_mode};
                    const auto v = handle_comparison_component_eq_neq<BlueprintFieldType, ArithmetizationParams, eq_component_type>(
                        p, lhs, rhs, bitness,
                        circuits[currProverIdx], assignments[currProverIdx], param);
                    handle_component_result<BlueprintFieldType, ArithmetizationParams, eq_component_type>
                            (assignments[currProverIdx], inst, frame, v, gen_mode);
                } else {
                    std::size_t bitness = inst->getOperand(0)->getType()->getPrimitiveSizeInBits();
                    const common_component_parameters param = {assignments[currProverIdx].allocated_rows(), targetProverIdx, gen_mode};

                    const auto v = handle_comparison_component_others<BlueprintFieldType, ArithmetizationParams, comp_component_type>(
                        p, lhs, rhs, bitness,
                        circuits[currProverIdx], assignments[currProverIdx], param);
                    handle_component_result<BlueprintFieldType, ArithmetizationParams, comp_component_type>
                            (assignments[currProverIdx], inst, frame, v, gen_mode);
                }
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

                using eq_component_type = components::equality_flag<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, BlueprintFieldType>;

                for (size_t i = 0; i < lhs.size(); ++i) {
                    const common_component_parameters param = {assignments[currProverIdx].allocated_rows(), targetProverIdx, gen_mode};
                    auto v = handle_comparison_component_eq_neq<BlueprintFieldType, ArithmetizationParams, eq_component_type>(
                        inst->getPredicate(), lhs[i], rhs[i], bitness,
                        circuits[currProverIdx], assignments[currProverIdx], param);

                    res.emplace_back(v.output);
                }
                handle_result<BlueprintFieldType, ArithmetizationParams>
                        (assignments[currProverIdx], inst, frame, res, gen_mode);
            }

            void handle_curve_cmp(const llvm::ICmpInst *inst, stack_frame<var> &frame) {
                ASSERT(llvm::cast<llvm::EllipticCurveType>(inst->getOperand(0)->getType())->getCurveKind() ==
                   llvm::cast<llvm::EllipticCurveType>(inst->getOperand(1)->getType())->getCurveKind());

                const std::vector<var> &lhs = frame.vectors[inst->getOperand(0)];
                const std::vector<var> &rhs = frame.vectors[inst->getOperand(1)];
                ASSERT(lhs.size() != 0 && lhs.size() == rhs.size());

                ASSERT_MSG(inst->getPredicate() == llvm::CmpInst::ICMP_EQ, "only == comparison is implemented for curve elements");

                std::vector<var> res;

                using eq_component_type = components::equality_flag<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, BlueprintFieldType>;

                for (size_t i = 0; i < lhs.size(); ++i) {
                    const common_component_parameters param = {assignments[currProverIdx].allocated_rows(), targetProverIdx, gen_mode};
                    auto v = handle_comparison_component_eq_neq<BlueprintFieldType, ArithmetizationParams, eq_component_type>(
                        inst->getPredicate(), lhs[i], rhs[i], 0,
                        circuits[currProverIdx], assignments[currProverIdx], param);
                    res.emplace_back(v.output);
                }

                var are_curves_equal = res[0];

                using component_type = components::logic_and<ArithmetizationType>;

                for (size_t i = 1; i < lhs.size(); ++i) {
                    const common_component_parameters param = {assignments[currProverIdx].allocated_rows(), targetProverIdx, gen_mode};
                    are_curves_equal = handle_logic_and<BlueprintFieldType, ArithmetizationParams>(
                        are_curves_equal, res[i], circuits[currProverIdx], assignments[currProverIdx],
                        param);
                }
                handle_result<BlueprintFieldType, ArithmetizationParams>
                    (assignments[currProverIdx], inst, frame, {are_curves_equal}, gen_mode);
            }

            void handle_ptr_cmp(const llvm::ICmpInst *inst, stack_frame<var> &frame) {
                if (std::uint8_t(gen_mode & generation_mode::ASSIGNMENTS)) {
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
                    frame.scalars[inst] = put_into_assignment(res);
                } else {
                    frame.scalars[inst] = put_into_assignment(0);
                }
            }

            template <typename NumberType>
            NumberType resolve_number(stack_frame<var> &frame, const llvm::Value *value) {
                var scalar = frame.scalars[value];
                return resolve_number<NumberType>(scalar);
            }

            template <typename NumberType>
            NumberType resolve_number(var scalar) {
                auto scalar_value = var_value(assignments[currProverIdx], scalar);
                static constexpr auto limit_value = typename BlueprintFieldType::integral_type(std::numeric_limits<NumberType>::max());
                auto integral_value = static_cast<typename BlueprintFieldType::integral_type>(scalar_value.data);
                ASSERT_MSG(integral_value < limit_value, "");
                NumberType number = static_cast<NumberType>(integral_value);
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
                        if (constant->isZeroValue()) {
                            stack_memory.store(ptr++, zero_var);
                            continue;
                        }
                        if (globals.find(constant) != globals.end()) {
                            stack_memory.store(ptr++, globals[constant]);
                            continue;
                        }
                        UNREACHABLE("Unsupported pointer initialization!");
                    }
                    if (!type->isAggregateType() && !type->isVectorTy()) {
                        std::vector<typename BlueprintFieldType::value_type> marshalled_field_val = marshal_field_val<BlueprintFieldType>(constant);
                        for (int i = 0; i < marshalled_field_val.size(); i++) {
                            auto variable = put_into_assignment(marshalled_field_val[i]);
                            stack_memory.store(ptr++, variable);
                        }
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

            void memcpy(ptr_type dst, ptr_type src, unsigned width) {
                unsigned copied = 0;
                while (copied < width) {
                    ASSERT(stack_memory[dst].size == stack_memory[src].size);
                    unsigned following = stack_memory[dst].following;
                    copied += stack_memory[dst].size;
                    stack_memory[dst++].v = stack_memory[src++].v;
                    while (following != 0) {
                        stack_memory[dst++].v = stack_memory[src++].v;
                        --following;
                    }
                }
            }

            void memset(ptr_type dst, var val, unsigned width) {
                unsigned filled = 0;
                while (filled < width) {
                    filled += stack_memory[dst].size;
                    stack_memory[dst++].v = val;
                }
            }

            bool handle_intrinsic(const llvm::CallInst *inst, llvm::Intrinsic::ID id, stack_frame<var> &frame, uint32_t start_row) {
                // Passing constants to component directly is only supported for components below
                if (
                    id != llvm::Intrinsic::assigner_bit_decomposition &&
                    id != llvm::Intrinsic::assigner_bit_decomposition_field &&
                    id != llvm::Intrinsic::assigner_bit_composition &&
                    id != llvm::Intrinsic::assigner_gate_arg_verifier &&
                    id != llvm::Intrinsic::assigner_permutation_arg_verifier &&
                    id != llvm::Intrinsic::assigner_lookup_arg_verifier &&
                    id != llvm::Intrinsic::assigner_fri_array_swap &&
                    id != llvm::Intrinsic::assigner_fri_cosets
                    ) {
                    for (int i = 0; i < inst->getNumOperands(); ++i) {
                        llvm::Value *op = inst->getOperand(i);
                        if (llvm::isa<llvm::Constant>(op)) {
                            put_constant(llvm::cast<llvm::Constant>(op), frame);
                        }
                    }
                }

                const common_component_parameters param = {start_row, targetProverIdx, gen_mode};

                switch (id) {
                    case llvm::Intrinsic::assigner_malloc: {
                        if (std::uint8_t(gen_mode & generation_mode::ASSIGNMENTS)) {
                            size_t bytes = resolve_number<size_t>(frame, inst->getOperand(0));
                            frame.scalars[inst] = put_into_assignment(stack_memory.malloc(bytes));
                        } else {
                            frame.scalars[inst] = put_into_assignment(0);
                        }
                        return true;
                    }
                    case llvm::Intrinsic::assigner_free: {
                        // TODO(maksenov): implement allocator
                        return true;
                    }
                    case llvm::Intrinsic::assigner_poseidon: {
                        if constexpr (std::is_same<BlueprintFieldType, typename nil::crypto3::algebra::curves::pallas::base_field_type>::value) {

                        using component_type = components::poseidon<ArithmetizationType, BlueprintFieldType>;

                        auto &input_block = frame.vectors[inst->getOperand(0)];
                        ASSERT(input_block.size() == component_type::state_size);

                        std::array<var, component_type::state_size> input_state_var;
                        std::copy(input_block.begin(), input_block.end(), input_state_var.begin());

                        typename component_type::input_type instance_input = {input_state_var};

                        handle_component<BlueprintFieldType, ArithmetizationParams, component_type>
                                (circuits[currProverIdx], assignments[currProverIdx], param, instance_input, inst, frame);
                        return true;
                        }
                        else {
                            UNREACHABLE("poseidon is implemented only for pallas native field");
                        }
                    }
                    case llvm::Intrinsic::assigner_sha2_256: {
                        handle_sha2_256_component<BlueprintFieldType, ArithmetizationParams>(inst, frame,
                                                                                             circuits[currProverIdx],
                                                                                             assignments[currProverIdx],
                                                                                             param);
                        return true;
                    }
                    case llvm::Intrinsic::assigner_sha2_512: {
                        if constexpr (std::is_same<BlueprintFieldType, typename nil::crypto3::algebra::curves::pallas::base_field_type>::value) {
                            handle_sha2_512_component<BlueprintFieldType, ArithmetizationParams>(inst, frame, circuits[currProverIdx], assignments[currProverIdx], param);
                            return true;
                        }
                        else {
                            UNREACHABLE("sha512 is implemented only for pallas native field");
                        }
                    }
                    case llvm::Intrinsic::assigner_optimal_ate_pairing: {
                        if constexpr (std::is_same<BlueprintFieldType, typename nil::crypto3::algebra::fields::bls12_base_field<381>>::value) {

                            handle_bls12381_pairing<BlueprintFieldType, ArithmetizationParams>(inst, frame, circuits[currProverIdx], assignments[currProverIdx], param);
                            return true;
                        }
                        else {
                            UNREACHABLE("bls12_optimal_ate_pairing is implemented only for bls12381_base native field");
                        }
                    }
                    case llvm::Intrinsic::assigner_hash_to_curve: {
                        if constexpr (std::is_same<BlueprintFieldType, typename nil::crypto3::algebra::fields::bls12_base_field<381>>::value) {

                            handle_h2c<BlueprintFieldType, ArithmetizationParams>(inst, frame, circuits[currProverIdx], assignments[currProverIdx], param);
                            return true;
                        }
                        else {
                            UNREACHABLE("assigner_hash_to_curve is implemented only for bls12381_base native field");
                        }
                    }
                    case llvm::Intrinsic::assigner_is_in_g1_check: {
                        if constexpr (std::is_same<BlueprintFieldType, typename nil::crypto3::algebra::fields::bls12_base_field<381>>::value) {

                            handle_is_in_g1<BlueprintFieldType, ArithmetizationParams>(inst, frame, circuits[currProverIdx], assignments[currProverIdx], param);
                            return true;
                        }
                        else {
                            UNREACHABLE("__builtin_assigner_is_in_g1_check is implemented only for bls12381_base native field");
                        }
                    }
                    case llvm::Intrinsic::assigner_is_in_g2_check: {
                        if constexpr (std::is_same<BlueprintFieldType, typename nil::crypto3::algebra::fields::bls12_base_field<381>>::value) {

                            handle_is_in_g2<BlueprintFieldType, ArithmetizationParams>(inst, frame, circuits[currProverIdx], assignments[currProverIdx], param);
                            return true;
                        }
                        else {
                            UNREACHABLE("__builtin_assigner_is_in_g2_check is implemented only for bls12381_base native field");
                        }
                    }
                    case llvm::Intrinsic::assigner_gt_multiplication: {
                        if constexpr (std::is_same<BlueprintFieldType, typename nil::crypto3::algebra::fields::bls12_base_field<381>>::value) {

                            handle_fp12_mul<BlueprintFieldType, ArithmetizationParams>(inst, frame, circuits[currProverIdx], assignments[currProverIdx], param);
                            return true;
                        }
                        else {
                            UNREACHABLE("__builtin_assigner_gt_multiplication is implemented only for bls12381_base native field");
                        }
                    }
                    case llvm::Intrinsic::assigner_bit_decomposition_field:
                    case llvm::Intrinsic::assigner_bit_decomposition: {
                        ASSERT(check_operands_constantness(inst, {1, 3}, frame));
                        handle_integer_bit_decomposition_component<BlueprintFieldType, ArithmetizationParams>(inst, frame, stack_memory, circuits[currProverIdx], assignments[currProverIdx], param);
                        return true;
                    }
                    case llvm::Intrinsic::assigner_bit_composition: {
                        ASSERT(check_operands_constantness(inst, {1, 2}, frame));
                        handle_integer_bit_composition_component<BlueprintFieldType, ArithmetizationParams>(inst, frame, stack_memory, circuits[currProverIdx], assignments[currProverIdx], param);
                        return true;
                    }
                    case llvm::Intrinsic::assigner_print_native_pallas_field: {
                        llvm::Value *input = inst->getOperand(0);
                        ASSERT(field_arg_num<BlueprintFieldType>(input->getType()) == 1);
                        if (std::uint8_t(gen_mode & generation_mode::ASSIGNMENTS)) {
                            std::cout << var_value(assignments[currProverIdx], frame.scalars[input]).data << std::endl;
                        }
                        return true;
                    }
                    case llvm::Intrinsic::memcpy: {
                        if (std::uint8_t(gen_mode & generation_mode::ASSIGNMENTS)) {
                            llvm::Value *src_val = inst->getOperand(1);
                            ptr_type dst = resolve_number<ptr_type>(frame, inst->getOperand(0));
                            ptr_type src = resolve_number<ptr_type>(frame, src_val);
                            unsigned width = resolve_number<unsigned>(frame, inst->getOperand(2));
                            memcpy(dst, src, width);
                        }
                        return true;
                    }
                    case llvm::Intrinsic::memset: {
                        if (std::uint8_t(gen_mode & generation_mode::ASSIGNMENTS)) {
                            ptr_type dst = resolve_number<ptr_type>(frame, inst->getOperand(0));
                            unsigned width = resolve_number<unsigned>(frame, inst->getOperand(2));
                            ASSERT(frame.scalars.find(inst->getOperand(1)) != frame.scalars.end());
                            const auto value_var = frame.scalars[inst->getOperand(1)];
                            memset(dst, value_var, width);
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
                        handle_curve_init<var, BlueprintFieldType>(inst, frame);
                        return true;
                    }

                    case llvm::Intrinsic::assigner_exit_check: {
                        const var &logical_statement = frame.scalars[inst->getOperand(0)];

                        std::size_t bitness = inst->getOperand(0)->getType()->getPrimitiveSizeInBits();

                        using eq_component_type = components::equality_flag<
                        crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, BlueprintFieldType>;

                        var comparison_result = handle_comparison_component_eq_neq<BlueprintFieldType, ArithmetizationParams, eq_component_type>(
                            llvm::CmpInst::ICMP_EQ, logical_statement, zero_var, bitness,
                            circuits[currProverIdx], assignments[currProverIdx], param).output;

                        if (validity_check && std::uint8_t(gen_mode & generation_mode::ASSIGNMENTS)) {
                            bool assigner_exit_check_input = var_value(assignments[currProverIdx], comparison_result) == 0;
                            ASSERT_MSG(assigner_exit_check_input,
                                      "assigner_exit_check input is false, verification will fail!\n");
                        }

                        circuits[currProverIdx].add_copy_constraint({comparison_result, zero_var});

                        return true;
                    }
                    case llvm::Intrinsic::assigner_fri_lin_inter: {
                        handle_fri_lin_inter_component<BlueprintFieldType, ArithmetizationParams>(inst, frame, stack_memory, circuits[currProverIdx], assignments[currProverIdx], param);
                        return true;
                    }
                    case llvm::Intrinsic::assigner_fri_cosets: {
                        ASSERT_MSG(check_operands_constantness(inst, {1, 2}, frame), "result length, omega and total_bits must be constants");
                        handle_fri_cosets_component<BlueprintFieldType, ArithmetizationParams>(inst, frame, stack_memory, circuits[currProverIdx], assignments[currProverIdx], param);
                        return true;
                    }
                    case llvm::Intrinsic::assigner_gate_arg_verifier: {
                        ASSERT_MSG(check_operands_constantness(inst, {1, 2, 4}, frame), "gates_sizes, gates and selectors amount must be constants");
                        handle_gate_arg_verifier_component<BlueprintFieldType, ArithmetizationParams>(inst, frame, stack_memory, circuits[currProverIdx], assignments[currProverIdx], param);
                        return true;
                    }
                    case llvm::Intrinsic::assigner_permutation_arg_verifier: {
                        ASSERT_MSG(check_operands_constantness(inst, {3}, frame), "f, se, sigma size must be constant");
                        handle_permutation_arg_verifier_component<BlueprintFieldType, ArithmetizationParams>(inst, frame, stack_memory, circuits[currProverIdx], assignments[currProverIdx], param);
                        return true;
                    }
                    case llvm::Intrinsic::assigner_lookup_arg_verifier: {
                        std::vector<std::size_t> constants_positions = {};
                        for (std::size_t i = 0; i < 8; i++) { constants_positions.push_back(i);}
                        for (std::size_t i = 4; i < 13; i++) { constants_positions.push_back(2*i + 1);}
                        ASSERT_MSG(check_operands_constantness(inst, constants_positions, frame), "vectors sizes must be constants");
                        handle_lookup_arg_verifier_component<BlueprintFieldType, ArithmetizationParams>(inst, frame, stack_memory, circuits[currProverIdx], assignments[currProverIdx], param);
                        return true;
                    }
                    case llvm::Intrinsic::assigner_fri_array_swap: {
                        ASSERT_MSG(check_operands_constantness(inst, {1}, frame), "array size must be constant");
                        handle_fri_array_swap_component<BlueprintFieldType, ArithmetizationParams>(inst, frame, stack_memory, circuits[currProverIdx], assignments[currProverIdx], param);
                        return true;
                    }

                    default:
                        UNREACHABLE("Unexpected intrinsic!");
                }
                return false;
            }

            void handle_store(ptr_type ptr, const llvm::Value *val, stack_frame<var> &frame) {
                auto store_scalar = [this](ptr_type ptr, var v, size_t type_size) ->ptr_type {
                    auto &cell = stack_memory[ptr];
                    size_t cur_offset = cell.offset;
                    size_t cell_size = cell.size;
                    if (cell_size != type_size) {
                        ASSERT_MSG(cell_size == 1, "Unequal stores are only supported for malloc case");
                        cell.size = type_size;
                        cell.v = v;

                        for (int i = 1; i < type_size; ++i) {
                            auto &idle_cell = stack_memory[ptr + i];
                            ASSERT(idle_cell.offset == ++cur_offset);
                            idle_cell.offset = cell.offset;
                            idle_cell.size = 0;
                        }
                        return ptr + cell_size;
                    } else {
                        cell.v = v;
                        return ptr + 1;
                    }
                };

                if (auto vec_type = llvm::dyn_cast<llvm::FixedVectorType>(val->getType())) {
                    std::vector<var> var_vec = frame.vectors[val];
                    ASSERT_MSG(var_vec.size() == vec_type->getNumElements(), "Complex vectors are not supported");
                    unsigned elem_size = layout_resolver->get_type_size(vec_type->getElementType());
                    for (var v : var_vec) {
                        ptr = store_scalar(ptr, v, elem_size);
                    }
                } else {
                    unsigned type_size = layout_resolver->get_type_size(val->getType());
                    store_scalar(ptr, frame.scalars[val], type_size);
                }
            }

            void handle_load(ptr_type ptr, const llvm::Value *dest, stack_frame<var> &frame) {
                size_t num_cells = layout_resolver->get_cells_num<BlueprintFieldType>(dest->getType());
                if (num_cells == 1) {
                    if (std::uint8_t(gen_mode & generation_mode::ASSIGNMENTS)) {
                        auto &cell = stack_memory[ptr];
                        frame.scalars[dest] = put_into_assignment(var_value(assignments[currProverIdx], cell.v));
                    } else {
                        frame.scalars[dest] = put_into_assignment(0);
                    }
                } else {
                    std::vector<var> res;
                    if (std::uint8_t(gen_mode & generation_mode::ASSIGNMENTS)) {
                        for (size_t i = 0; i < num_cells; ++i) {
                            res.push_back(put_into_assignment(var_value(assignments[currProverIdx], stack_memory[ptr + i].v)));
                        }
                    } else {
                        for (size_t i = 0; i < num_cells; ++i) {
                            res.push_back(put_into_assignment(0));
                        }
                    }
                    frame.vectors[dest] = res;
                }
            }

            ptr_type find_offset(ptr_type left_border, ptr_type right_border, size_t offset) {
                for (ptr_type i = left_border; i <= right_border; ++i) {
                    if (stack_memory[i].offset == offset) {
                        return i;
                    }
                }
                UNREACHABLE("Offset does not match memory");
            }

            // Handle pointer adjustment specified by the first GEP index
            ptr_type handle_initial_gep_adjustment(const llvm::Value *pointer_operand, const llvm::Value *initial_idx_operand,
                                                   stack_frame<var> &frame,
                                                   llvm::Type *gep_ty) {
                typename BlueprintFieldType::value_type base_ptr =
                    var_value(assignments[currProverIdx], frame.scalars[pointer_operand]);
                auto base_ptr_number = resolve_number<ptr_type>(frame.scalars[pointer_operand]);
                var gep_initial_idx = frame.scalars[initial_idx_operand];
                size_t cells_for_type = layout_resolver->get_cells_num<BlueprintFieldType>(gep_ty);

                auto naive_ptr_adjustment = cells_for_type * var_value(assignments[currProverIdx], gep_initial_idx);
                auto adjusted_ptr = base_ptr + naive_ptr_adjustment;
                if (adjusted_ptr == base_ptr) {
                    // The index is zero, the ptr remains unchanged
                    return base_ptr_number;
                }
                int resolved_idx = 0;
                // The index could be negative, so we need to take the difference with the modulus in this case
                if (adjusted_ptr < base_ptr) {
                    auto sub = BlueprintFieldType::modulus - static_cast<typename BlueprintFieldType::integral_type>(var_value(assignments[currProverIdx], gep_initial_idx).data);
                    resolved_idx = static_cast<int>(sub) * -1;
                } else {
                    resolved_idx = resolve_number<int>(gep_initial_idx);
                }
                size_t type_size = layout_resolver->get_type_size(gep_ty);
                size_t offset_diff = resolved_idx * type_size;
                size_t desired_offset = stack_memory[base_ptr_number].offset + offset_diff;

                if (resolved_idx < 0) {
                    ptr_type left_border = base_ptr_number + resolved_idx * type_size;
                    ptr_type right_border = base_ptr_number;
                    return find_offset(left_border, right_border, desired_offset);
                } else {
                    ptr_type left_border = base_ptr_number;
                    ptr_type right_border = base_ptr_number + resolved_idx * type_size;
                    return find_offset(left_border, right_border, desired_offset);
                }
            }

            typename BlueprintFieldType::value_type handle_gep(const llvm::Value *pointer_operand,
                                                               const llvm::Value *initial_idx_operand,
                                                               llvm::Type* gep_ty,
                                                               const std::vector<int> &gep_indices,
                                                               stack_frame<var> &frame) {
                auto ptr_number = handle_initial_gep_adjustment(pointer_operand, initial_idx_operand, frame, gep_ty);
                ASSERT(stack_memory[ptr_number].size != 0);

                if (gep_indices.size() > 0) {
                    if (!gep_ty->isAggregateType()) {
                        std::cerr << "GEP instruction with > 1 indices must operate on aggregate type!"
                                  << std::endl;
                        return 0;
                    }
                    auto [resolved_offset, hint] = layout_resolver->resolve_offset_with_index_hint<BlueprintFieldType>(gep_ty, gep_indices);
                    size_t expected_offset = stack_memory[ptr_number].offset + resolved_offset;
                    while (stack_memory[ptr_number + hint].size == 0) {
                        ++hint;
                    };
                    size_t desired_offset = stack_memory[ptr_number].offset + resolved_offset;
                    size_t type_size = layout_resolver->get_type_size(gep_ty);
                    ptr_number = find_offset(ptr_number + hint, ptr_number + type_size, desired_offset);
                }
                return ptr_number;
            }

            void handle_ptrtoint(const llvm::Value *inst, llvm::Value *operand, stack_frame<var> &frame) {
                if (std::uint8_t(gen_mode & generation_mode::ASSIGNMENTS)) {
                    ptr_type ptr = resolve_number<ptr_type>(frame, operand);
                    size_t offset = stack_memory.ptrtoint(ptr);
                    log.debug(boost::format("PtrToInt %1% %2%") % ptr % offset);
                    frame.scalars[inst] = put_into_assignment(offset);
                } else {
                    log.debug(boost::format("Skip PtrToInt"));
                    frame.scalars[inst] = put_into_assignment(0);
                }
            }

            void put_global(const llvm::GlobalVariable *global) {
                if (globals.find(global) != globals.end()) {
                    return;
                }
                const llvm::Constant *initializer = global->getInitializer();
                if (initializer->getType()->isAggregateType()) {
                    ptr_type ptr = store_constant<var>(initializer);
                    globals[global] = put_into_assignment(ptr, true);
                } else if (initializer->getType()->isIntegerTy() ||
                           (initializer->getType()->isFieldTy() &&
                            field_arg_num<BlueprintFieldType>(initializer->getType()) == 1)) {
                    unsigned constant_width = layout_resolver->get_type_size(initializer->getType());
                    ptr_type ptr = stack_memory.add_cells({{constant_width, 0}});
                    std::vector<typename BlueprintFieldType::value_type> marshalled_field_val =
                        marshal_field_val<BlueprintFieldType>(initializer);
                    stack_memory.store(ptr, put_into_assignment(marshalled_field_val[0], true));
                    globals[global] = put_into_assignment(ptr, true);
                } else if (llvm::isa<llvm::ConstantPointerNull>(initializer)) {
                    unsigned ptr_width = layout_resolver->get_type_size(initializer->getType());
                    ptr_type ptr = stack_memory.add_cells({{ptr_width, 0}});
                    stack_memory.store(ptr, zero_var);
                    globals[global] = put_into_assignment(ptr, true);
                } else {
                    UNREACHABLE("Unhandled global variable");
                }
            }

            void put_constant(llvm::Constant *c, stack_frame<var> &frame) {
                if (llvm::isa<llvm::ConstantField>(c) || llvm::isa<llvm::ConstantInt>(c)) {
                    std::vector<typename BlueprintFieldType::value_type> marshalled_field_val = marshal_field_val<BlueprintFieldType>(c);
                    if (marshalled_field_val.size() == 1) {
                        frame.scalars[c] = put_into_assignment(marshalled_field_val[0]);
                    }
                    else {
                        frame.vectors[c] = {};
                        for (std::size_t i = 0; i < marshalled_field_val.size(); i++) {
                            frame.vectors[c].push_back(put_into_assignment(marshalled_field_val[i]));
                        }
                    }
                } else if (llvm::isa<llvm::UndefValue>(c)) {
                    llvm::Type *undef_type = c->getType();
                    if (undef_type->isIntegerTy() || undef_type->isFieldTy() || llvm::isa<llvm::PoisonValue>(c)) {
                        frame.scalars[c] = undef_var;
                    } else if (auto vector_type = llvm::dyn_cast<llvm::FixedVectorType>(undef_type)) {
                        std::size_t arg_num = field_arg_num<BlueprintFieldType>(vector_type->getElementType());
                        frame.vectors[c] = std::vector<var>(vector_type->getNumElements() * arg_num, undef_var);
                    } else {
                        ASSERT(undef_type->isAggregateType());
                        auto layout = layout_resolver->get_type_layout<BlueprintFieldType>(undef_type);
                        ptr_type ptr = stack_memory.add_cells(layout);
                        for (size_t i = 0; i < layout_resolver->get_cells_num<BlueprintFieldType>(undef_type); ++i) {
                            stack_memory.store(ptr+i, undef_var);
                        }
                        frame.scalars[c] = put_into_assignment(ptr);
                    }
                } else if (llvm::isa<llvm::ConstantPointerNull>(c)) {
                    frame.scalars[c] = zero_var;
                } else if (auto *cv = llvm::dyn_cast<llvm::ConstantVector>(c)) {
                    size_t size = cv->getType()->getNumElements();
                    std::size_t arg_num = field_arg_num<BlueprintFieldType>(cv->getType()->getElementType());
                    std::vector<var> result_vector(size * arg_num);

                    ASSERT(cv->getType()->getElementType()->isFieldTy());

                    for (int i = 0; i < size; ++i) {
                        llvm::Constant *elem = cv->getAggregateElement(i);
                        if (llvm::isa<llvm::UndefValue>(elem))
                            continue;
                        std::vector<typename BlueprintFieldType::value_type> marshalled_field_val = marshal_field_val<BlueprintFieldType>(elem);
                        for (std::size_t j = 0; j < marshalled_field_val.size(); j++) {
                            result_vector[i * arg_num + j] = put_into_assignment(marshalled_field_val[j]);
                        }

                    }
                    frame.vectors[c] = result_vector;
                } else if (auto expr = llvm::dyn_cast<llvm::ConstantExpr>(c)) {
                    for (int i = 0; i < expr->getNumOperands(); ++i) {
                        put_constant(expr->getOperand(i), frame);
                    }
                    switch (expr->getOpcode()) {
                    case llvm::Instruction::PtrToInt:
                        handle_ptrtoint(expr, expr->getOperand(0), frame);
                        break;
                    case llvm::Instruction::GetElementPtr: {
                        if (std::uint8_t(gen_mode & generation_mode::ASSIGNMENTS)) {
                                std::vector<int> gep_indices;
                                for (unsigned i = 2; i < expr->getNumOperands(); ++i) {
                                    int gep_index = resolve_number<int>(frame, expr->getOperand(i));
                                    gep_indices.push_back(gep_index);
                                }

                                // getSourceElementType for ConstantExpr
                                llvm::gep_type_iterator type_it = gep_type_begin(expr);
                                llvm::Type *source_element_type = type_it.getIndexedType();
                                if (source_element_type == nullptr) {
                                    std::cerr
                                        << "Can't extract source element type for GetElementPtr constant expression!"
                                        << std::endl;
                                    ASSERT(false);
                                }

                                auto gep_res = handle_gep(expr->getOperand(0), expr->getOperand(1), source_element_type,
                                                          gep_indices, frame);
                                ASSERT(gep_res != 0);
                                frame.scalars[c] = put_into_assignment(gep_res);
                        } else {
                                frame.scalars[c] = put_into_assignment(0);
                        }
                        break;
                    }
                    default:
                        UNREACHABLE(std::string("Unhandled constant expression: ") + expr->getOpcodeName());
                    }
                } else if (auto addr = llvm::dyn_cast<llvm::BlockAddress>(c)) {
                    frame.scalars[c] = labels[addr->getBasicBlock()];
                } else if (auto func = llvm::dyn_cast<llvm::Function>(c)) {
                    cpp_values.push_back(func);
                    frame.scalars[c] = put_into_assignment(cpp_values.size() - 1, false);
                } else if (auto *gv = llvm::dyn_cast<llvm::GlobalVariable>(c)) {
                    put_global(gv);
                    frame.scalars[c] = globals[c];
                } else {
                    // The only other known constant is an address of a function in CallInst,
                    // but there is no way to distinguish it
                    ASSERT(c->getType()->isPointerTy());
                }
            }

            void restore_state(const ParserState& parser_state) {
                predecessor = parser_state.predecessor;
                currProverIdx = parser_state.currProverIdx;
                cpp_values = parser_state.cpp_values;
                gen_mode = parser_state.gen_mode;
                finished = parser_state.finished;
            }

            const llvm::Instruction *handle_branch(const llvm::Instruction* inst) {
                auto next_inst = inst;
                const auto stack_size = curr_branch.back().second;
                while (true) {
                    next_inst = handle_instruction(next_inst);
                    if (finished || next_inst == nullptr) {
                        return nullptr;
                    }
                    if (stack_size > call_stack.size()) {
                        return next_inst;
                    }
                }
                return nullptr;
            }

            const llvm::Instruction *handle_instruction(const llvm::Instruction *inst) {
                log.log_instruction(inst);
                stack_frame<var> &frame = call_stack.top();
                auto &variables = frame.scalars;
                std::uint32_t start_row = assignments[currProverIdx].allocated_rows();

                // extract zk related metadata
                std::uint32_t userProverIdx = extract_prover_idx_metadata(inst);

                if ((userProverIdx != currProverIdx && userProverIdx != currProverIdx + 1) ||
                    userProverIdx >= maxNumProvers) {
                    std::cout << "WARNING: ignored user defined prover index " << userProverIdx
                              << ", must be " << currProverIdx + 1 << std::endl;
                    userProverIdx = currProverIdx;
                }

                currProverIdx = userProverIdx;

                if (currProverIdx >= assignments.size()) {
                    assignments.emplace_back(assignment_ptr, currProverIdx);
                    circuits.emplace_back(bp_ptr, currProverIdx);
                }

                // Put constant operands to public input
                for (int i = 0; i < inst->getNumOperands(); ++i) {
                    llvm::Value *op = inst->getOperand(i);
                    if (variables.find(op) != variables.end()) {
                        continue;
                    }
                    if (auto *gv = llvm::dyn_cast<llvm::GlobalVariable>(op)) {
                        put_global(gv);
                        frame.scalars[op] = globals[op];
                    } else if (llvm::isa<llvm::Constant>(op)) {
                        // We are replacing constant handling with passing them directly to a component
                        // For now this functionality is supported only for intrinsics
                        // In other cases the logic remains unchanged
                        if (inst->getOpcode() != llvm::Instruction::Call ||
                            !llvm::cast<llvm::CallInst>(inst)->getCalledFunction()->isIntrinsic()) {
                            put_constant(llvm::cast<llvm::Constant>(op), frame);
                        }
                    }
                }

                const common_component_parameters param = {start_row, targetProverIdx, gen_mode};

                switch (inst->getOpcode()) {
                    case llvm::Instruction::Add: {

                        if (inst->getOperand(0)->getType()->isIntegerTy()) {
                            handle_integer_addition_component<BlueprintFieldType, ArithmetizationParams>(
                                        inst, frame, circuits[currProverIdx], assignments[currProverIdx], param);
                            return inst->getNextNonDebugInstruction();
                        }

                        if (inst->getOperand(0)->getType()->isFieldTy() && inst->getOperand(1)->getType()->isFieldTy()) {
                            handle_field_addition_component<BlueprintFieldType, ArithmetizationParams>(
                                        inst, frame, circuits[currProverIdx], assignments[currProverIdx], param);
                            return inst->getNextNonDebugInstruction();
                        } else if (inst->getOperand(0)->getType()->isCurveTy() && inst->getOperand(1)->getType()->isCurveTy()) {
                            handle_curve_addition_component<BlueprintFieldType, ArithmetizationParams>(
                                        inst, frame, circuits[currProverIdx], assignments[currProverIdx], param);
                            return inst->getNextNonDebugInstruction();
                        } else {
                            UNREACHABLE("curve + scalar is undefined");
                        }

                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Sub: {
                        if (inst->getOperand(0)->getType()->isIntegerTy()) {
                            handle_integer_subtraction_component<BlueprintFieldType, ArithmetizationParams>(
                                inst, frame, circuits[currProverIdx], assignments[currProverIdx], param);
                            return inst->getNextNonDebugInstruction();
                        }

                        if (inst->getOperand(0)->getType()->isFieldTy() && inst->getOperand(1)->getType()->isFieldTy()) {
                            handle_field_subtraction_component<BlueprintFieldType, ArithmetizationParams>(
                                inst, frame, circuits[currProverIdx], assignments[currProverIdx], param);
                            return inst->getNextNonDebugInstruction();
                        } else if (inst->getOperand(0)->getType()->isCurveTy() && inst->getOperand(1)->getType()->isCurveTy()) {
                            handle_curve_subtraction_component<BlueprintFieldType, ArithmetizationParams>(
                                inst, frame, circuits[currProverIdx], assignments[currProverIdx], param);
                            return inst->getNextNonDebugInstruction();
                        } else {
                            UNREACHABLE("curve - scalar is undefined");
                        }

                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Mul: {

                        if (inst->getOperand(0)->getType()->isIntegerTy()) {
                            handle_integer_multiplication_component<BlueprintFieldType, ArithmetizationParams>(
                                inst, frame, circuits[currProverIdx], assignments[currProverIdx], param);
                            return inst->getNextNonDebugInstruction();
                        }

                        if (inst->getOperand(0)->getType()->isFieldTy() && inst->getOperand(1)->getType()->isFieldTy()) {
                            handle_field_multiplication_component<BlueprintFieldType, ArithmetizationParams>(
                                inst, frame, circuits[currProverIdx], assignments[currProverIdx], param);
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
                                inst, frame, circuits[currProverIdx], assignments[currProverIdx], param);
                            return inst->getNextNonDebugInstruction();
                        } else {
                            UNREACHABLE("cmul opcode is defined only for curveTy * fieldTy");
                        }
                    }
                    case llvm::Instruction::UDiv: {
                        if (inst->getOperand(0)->getType()->isIntegerTy() && inst->getOperand(1)->getType()->isIntegerTy()) {
                            handle_integer_division_remainder_component<BlueprintFieldType, ArithmetizationParams>(
                                inst, frame, circuits[currProverIdx], assignments[currProverIdx], param, true);
                            return inst->getNextNonDebugInstruction();
                        }
                        else if (inst->getOperand(0)->getType()->isFieldTy() && inst->getOperand(1)->getType()->isFieldTy()) {
                            handle_field_division_component<BlueprintFieldType, ArithmetizationParams>(
                                inst, frame, circuits[currProverIdx], assignments[currProverIdx], param);
                            return inst->getNextNonDebugInstruction();
                        }
                        else {
                            UNREACHABLE("UDiv opcode is defined only for integerTy and fieldTy");
                        }
                    }
                    case llvm::Instruction::URem: {
                        if (inst->getOperand(0)->getType()->isIntegerTy() && inst->getOperand(1)->getType()->isIntegerTy()) {
                            handle_integer_division_remainder_component<BlueprintFieldType, ArithmetizationParams>(
                                inst, frame, circuits[currProverIdx], assignments[currProverIdx], param, false);
                            return inst->getNextNonDebugInstruction();
                        } else {
                            UNREACHABLE("URem opcode is defined only for integerTy");
                        }
                    }
                    case llvm::Instruction::Shl: {
                        if (inst->getOperand(0)->getType()->isIntegerTy() && inst->getOperand(1)->getType()->isIntegerTy()) {
                            handle_integer_bit_shift_constant_component<BlueprintFieldType, ArithmetizationParams>(
                                inst, frame, circuits[currProverIdx], assignments[currProverIdx], param,
                                        nil::blueprint::components::bit_shift_mode::LEFT);
                            return inst->getNextNonDebugInstruction();
                        } else {
                            UNREACHABLE("shl opcode is defined only for integerTy");
                        }
                    }
                    case llvm::Instruction::LShr: {
                        if (inst->getOperand(0)->getType()->isIntegerTy() && inst->getOperand(1)->getType()->isIntegerTy()) {
                            handle_integer_bit_shift_constant_component<BlueprintFieldType, ArithmetizationParams>(
                                inst, frame, circuits[currProverIdx], assignments[currProverIdx], param,
                                        nil::blueprint::components::bit_shift_mode::RIGHT);
                            return inst->getNextNonDebugInstruction();
                        } else {
                            UNREACHABLE("LShr opcode is defined only for integerTy");
                        }
                    }
                    case llvm::Instruction::SDiv: {

                        if (inst->getOperand(0)->getType()->isIntegerTy()) {
                            handle_integer_division_component<BlueprintFieldType, ArithmetizationParams>(
                                inst, frame, circuits[currProverIdx], assignments[currProverIdx], param);
                            return inst->getNextNonDebugInstruction();
                        }

                        if (inst->getOperand(0)->getType()->isFieldTy() && inst->getOperand(1)->getType()->isFieldTy()) {
                            handle_field_division_component<BlueprintFieldType, ArithmetizationParams>(
                                inst, frame, circuits[currProverIdx], assignments[currProverIdx], param);
                            return inst->getNextNonDebugInstruction();
                        }

                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::IToGF: {
                        if (field_arg_num<BlueprintFieldType>(inst->getType()) == 1) {
                            frame.scalars[inst] = frame.scalars[inst->getOperand(0)];
                        } else {
                            UNREACHABLE("Non-native field conversion for integers is not supported");
                        }
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Call: {
                        auto *call_inst = llvm::cast<llvm::CallInst>(inst);
                        const auto *fun = call_inst->getCalledFunction();
                        if (fun == nullptr) {
                            size_t fun_idx = resolve_number<size_t>(frame, call_inst->getCalledOperand());
                            ASSERT(fun_idx < cpp_values.size());
                            fun = static_cast<const llvm::Function *>(cpp_values[fun_idx]);
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
                                (arg->getType()->isFieldTy() && field_arg_num<BlueprintFieldType>(arg_type) > 1)) {
                                new_frame.vectors[arg] = frame.vectors[call_inst->getOperand(i)];
                            }
                            else {
                                ASSERT(variables.find(call_inst->getOperand(i)) != variables.end());
                                new_variables[arg] = variables[call_inst->getOperand(i)];
                            }

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
                            handle_scalar_cmp(cmp_inst, frame);
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
                        if (std::uint8_t(gen_mode & generation_mode::ASSIGNMENTS)) {
                            var condition = variables[inst->getOperand(0)];
                            llvm::Value *true_val = inst->getOperand(1);
                            llvm::Value *false_val = inst->getOperand(2);
                            if (var_value(assignments[currProverIdx], condition) != 0) {
                                variables[inst] = put_into_assignment(var_value(assignments[currProverIdx], variables[true_val]));
                            } else {
                                variables[inst] = put_into_assignment(var_value(assignments[currProverIdx], variables[false_val]));
                            }
                        } else {
                            log.debug(boost::format("Skip Select"));
                            variables[inst] = put_into_assignment(0);
                        }
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::And: {
                        if (std::uint8_t(gen_mode & generation_mode::ASSIGNMENTS)) {
                            const var &lhs = variables[inst->getOperand(0)];
                            const var &rhs = variables[inst->getOperand(1)];

                            // TODO: replace mock with component

                            typename BlueprintFieldType::integral_type x_integer(
                                var_value(assignments[currProverIdx], lhs).data);
                            typename BlueprintFieldType::integral_type y_integer(
                                var_value(assignments[currProverIdx], rhs).data);
                            typename BlueprintFieldType::value_type res = (x_integer & y_integer);
                            variables[inst] = put_into_assignment(res);
                        } else {
                            variables[inst] = put_into_assignment(0);
                            log.debug(boost::format("Skip And"));
                        }

                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Or: {
                        if (std::uint8_t(gen_mode & generation_mode::ASSIGNMENTS)) {
                            const var &lhs = variables[inst->getOperand(0)];
                            const var &rhs = variables[inst->getOperand(1)];

                            // TODO: replace mock with component

                            typename BlueprintFieldType::integral_type x_integer(
                                var_value(assignments[currProverIdx], lhs).data);
                            typename BlueprintFieldType::integral_type y_integer(
                                var_value(assignments[currProverIdx], rhs).data);
                            typename BlueprintFieldType::value_type res = (x_integer | y_integer);
                            variables[inst] = put_into_assignment(res);
                        } else {
                            variables[inst] = put_into_assignment(0);
                            log.debug(boost::format("Skip And"));
                        }

                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Xor: {
                        if (std::uint8_t(gen_mode & generation_mode::ASSIGNMENTS)) {
                            const var &lhs = variables[inst->getOperand(0)];
                            const var &rhs = variables[inst->getOperand(1)];

                            // TODO: replace mock with component

                            typename BlueprintFieldType::integral_type x_integer(
                                var_value(assignments[currProverIdx], lhs).data);
                            typename BlueprintFieldType::integral_type y_integer(
                                var_value(assignments[currProverIdx], rhs).data);
                            typename BlueprintFieldType::value_type res = (x_integer ^ y_integer);
                            variables[inst] = put_into_assignment(res);
                        } else {
                            variables[inst] = put_into_assignment(0);
                            log.debug(boost::format("Skip Xor"));
                        }

                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Br: {
                        // Save current basic block to resolve PHI inst further
                        predecessor = inst->getParent();

                        if (inst->getNumOperands() != 1) {
                            ASSERT(inst->getNumOperands() == 3);
                            std::string false_name = inst->getOperand(1)->hasName() ? inst->getOperand(1)->getName().str() : "unknown";
                            std::string true_name = inst->getOperand(2)->hasName() ? inst->getOperand(2)->getName().str() : "unknown";
                            auto false_bb = llvm::cast<llvm::BasicBlock>(inst->getOperand(1));
                            auto true_bb = llvm::cast<llvm::BasicBlock>(inst->getOperand(2));
                            var cond = variables[inst->getOperand(0)];

                            // check if loop
                            const llvm::MDNode* metaDataNode = inst->getMetadata("llvm.loop");
                            if (metaDataNode) {
                                UNREACHABLE("Can't to process loop");
                            }
                            const auto stack_size = call_stack.size();
                            if (std::uint8_t(gen_mode & generation_mode::ASSIGNMENTS)) {
                                bool cond_val = (var_value(assignments[currProverIdx], cond) != 0);

                                const ParserState parser_state(*this);
                                curr_branch.push_back(branch_desc(false, stack_size));
                                curr_branch.push_back(branch_desc(true, stack_size));
                                if (!cond_val) {
                                    gen_mode = std::uint8_t(gen_mode & (generation_mode::ASSIGNMENTS | generation_mode::FALSE_ASSIGNMENTS)) ?
                                        (gen_mode & generation_mode::CIRCUIT) | generation_mode::FALSE_ASSIGNMENTS :
                                        gen_mode & generation_mode::CIRCUIT;
                                }

                                log.debug(boost::format("start handle true branch: %1% %2%") % curr_branch.size() % (std::uint8_t(gen_mode & generation_mode::ASSIGNMENTS) == 0));
                                const llvm::Instruction* true_next_inst = nullptr;
                                if (!cond_val && true_name == "panic") {
                                    log.debug(boost::format("skip handle true branch as false positive panic: %1%") % curr_branch.size());
                                } else {
                                    true_next_inst = handle_branch(&(true_bb->front()));
                                    log.debug(boost::format("stop handle true branch: %1% %2%") % curr_branch.size() %
                                              true_next_inst);
                                }

                                restore_state(parser_state);
                                curr_branch.pop_back();

                                if (cond_val) {
                                    gen_mode = std::uint8_t(gen_mode & (generation_mode::ASSIGNMENTS | generation_mode::FALSE_ASSIGNMENTS)) ?
                                                  (gen_mode & generation_mode::CIRCUIT) | generation_mode::FALSE_ASSIGNMENTS :
                                                  gen_mode & generation_mode::CIRCUIT;
                                }

                                log.debug(boost::format("start handle false branch: %1% %2%") % curr_branch.size() % (std::uint8_t(gen_mode & generation_mode::ASSIGNMENTS) == 0));
                                auto false_next_inst = true_next_inst;
                                if (cond_val && false_name == "panic") {
                                    log.debug(boost::format("skip handle false branch as false positive panic: %1%") % curr_branch.size());
                                } else {
                                    false_next_inst = handle_branch(&(false_bb->front()));
                                    log.debug(boost::format("stop handle false branch: %1% %2%") % curr_branch.size() %
                                              false_next_inst);
                                }

                                if (false_next_inst) {
                                    restore_state(parser_state);
                                }
                                curr_branch.pop_back();

                                assert((stack_size - 1) == call_stack.size());

                                return false_next_inst;
                            }

                            const ParserState parser_state(*this);
                            curr_branch.push_back(branch_desc(false, stack_size));
                            curr_branch.push_back(branch_desc(true, stack_size));

                            log.debug(boost::format("start handle true branch: %1% %2%") % curr_branch.size() % (std::uint8_t(gen_mode & generation_mode::ASSIGNMENTS) == 0));
                            const llvm::Instruction* true_next_inst = nullptr;
                            if (true_name == "panic") {
                                log.debug(boost::format("skip handle true branch as false positive panic: %1%") % curr_branch.size());
                            } else {
                                true_next_inst = handle_branch(&(true_bb->front()));
                                log.debug(boost::format("stop handle true branch: %1% %2%") % curr_branch.size() %
                                          true_next_inst);
                            }

                            restore_state(parser_state);
                            curr_branch.pop_back();

                            log.debug(boost::format("start handle false branch: %1% %2%") % curr_branch.size() % (std::uint8_t(gen_mode & generation_mode::ASSIGNMENTS) == 0));
                            auto false_next_inst = true_next_inst;
                            if (false_name == "panic") {
                                log.debug(boost::format("skip handle false branch as false positive panic: %1%") % curr_branch.size());
                            } else {
                                false_next_inst = handle_branch(&(false_bb->front()));
                                log.debug(boost::format("stop handle false branch: %1% %2%") % curr_branch.size() %
                                          false_next_inst);
                            }

                            if (false_next_inst) {
                                restore_state(parser_state);
                            }
                            curr_branch.pop_back();

                            assert((stack_size - 1) == call_stack.size());

                            return false_next_inst;
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
                        if (std::uint8_t(gen_mode & generation_mode::ASSIGNMENTS)) {
                            unsigned bit_width = llvm::cast<llvm::IntegerType>(cond->getType())->getBitWidth();
                            ASSERT(bit_width <= 64);
                            auto cond_var = var_value(assignments[currProverIdx], frame.scalars[cond]);
                            auto cond_val = llvm::APInt(
                                bit_width,
                                (int64_t) static_cast<typename BlueprintFieldType::integral_type>(cond_var.data));
                            for (auto Case : switch_inst->cases()) {
                                if (Case.getCaseValue()->getValue().eq(cond_val)) {
                                    gen_mode =
                                        std::uint8_t(gen_mode &
                                                     (generation_mode::ASSIGNMENTS | generation_mode::FALSE_ASSIGNMENTS)) ?
                                            (gen_mode & generation_mode::CIRCUIT) | generation_mode::FALSE_ASSIGNMENTS :
                                            gen_mode & generation_mode::CIRCUIT;
                                }
                                const ParserState parser_state(*this);
                                curr_branch.push_back(branch_desc(false, call_stack.size()));
                                const auto next_inst = handle_branch(&Case.getCaseSuccessor()->front());
                                curr_branch.pop_back();
                            }
                        } else {
                            for (auto Case : switch_inst->cases()) {
                                const ParserState parser_state(*this);
                                curr_branch.push_back(branch_desc(false, call_stack.size()));
                                const auto next_inst = handle_branch(&Case.getCaseSuccessor()->front());
                                curr_branch.pop_back();
                            }
                        }
                        return nullptr;
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
                        std::vector<var> result_vector = frame.vectors[vec];
                        result_vector[index] = variables[inst->getOperand(1)];
                        frame.vectors[inst] = result_vector;
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::ExtractElement: {
                        auto extract_inst = llvm::cast<llvm::ExtractElementInst>(inst);
                        llvm::Value *vec = extract_inst->getOperand(0);
                        llvm::Value *index_value = extract_inst->getOperand(1);
                        if (!llvm::isa<llvm::ConstantInt>(index_value)) {
                            if (std::uint8_t(gen_mode & generation_mode::ASSIGNMENTS)) {
                                int index = resolve_number<int>(frame, index_value);
                                variables[inst] = frame.vectors[vec][index];
                            } else {
                                UNREACHABLE("Not constant index is not supported without generating assignment table");
                            }
                            return inst->getNextNonDebugInstruction();
                        }
                        int index = llvm::cast<llvm::ConstantInt>(index_value)->getZExtValue();
                        variables[inst] = frame.vectors[vec][index];
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Alloca: {
                        auto *alloca = llvm::cast<llvm::AllocaInst>(inst);
                        auto vec = layout_resolver->get_type_layout<BlueprintFieldType>(alloca->getAllocatedType());

                        ptr_type res_ptr = stack_memory.add_cells(vec);
                        log.debug(boost::format("Alloca: %1%") % res_ptr);
                        frame.scalars[inst] = put_into_assignment(res_ptr);
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::GetElementPtr: {
                        auto *gep = llvm::cast<llvm::GetElementPtrInst>(inst);
                        if (std::uint8_t(gen_mode & generation_mode::ASSIGNMENTS)) {
                            std::vector<int> gep_indices;
                            for (unsigned i = 1; i < gep->getNumIndices(); ++i) {
                                int gep_index = resolve_number<int>(frame, gep->getOperand(i + 1));
                                gep_indices.push_back(gep_index);
                            }
                            auto gep_res = handle_gep(gep->getPointerOperand(), gep->getOperand(1),
                                                      gep->getSourceElementType(), gep_indices, frame);
                            if (gep_res == 0) {
                                std::cerr << "Incorrect GEP result!" << std::endl;
                                return nullptr;
                            }
                            std::ostringstream oss;
                            oss << gep_res.data;
                            log.debug(boost::format("GEP: %1%") % oss.str());
                            frame.scalars[gep] = put_into_assignment(gep_res);
                        } else {
                            log.debug(boost::format("Skip GEP"));
                            frame.scalars[gep] = put_into_assignment(0);
                        }
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Load: {
                        auto *load_inst = llvm::cast<llvm::LoadInst>(inst);
                        ptr_type ptr = 0;
                        if (std::uint8_t(gen_mode & generation_mode::ASSIGNMENTS)) {
                            ptr = resolve_number<ptr_type>(frame, load_inst->getPointerOperand());
                        }
                        log.debug(boost::format("Load: %1%") % ptr);
                        handle_load(ptr, load_inst, frame);
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Store: {
                        if (std::uint8_t(gen_mode & generation_mode::ASSIGNMENTS)) {
                            auto *store_inst = llvm::cast<llvm::StoreInst>(inst);
                            ptr_type ptr = resolve_number<ptr_type>(frame, store_inst->getPointerOperand());
                            log.debug(boost::format("Store: %1%") % ptr);
                            const llvm::Value *val = store_inst->getValueOperand();
                            handle_store(ptr, val, frame);
                        } else {
                            log.debug(boost::format("Skip Store"));
                        }
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::InsertValue: {
                        auto *insert_inst = llvm::cast<llvm::InsertValueInst>(inst);
                        if (std::uint8_t(gen_mode & generation_mode::ASSIGNMENTS)) {
                            ptr_type ptr = resolve_number<ptr_type>(frame, insert_inst->getAggregateOperand());
                            // TODO(maksenov): handle offset properly
                            ptr += layout_resolver
                                       ->resolve_offset_with_index_hint<BlueprintFieldType>(
                                           insert_inst->getAggregateOperand()->getType(), insert_inst->getIndices())
                                       .second;
                            stack_memory.store(ptr, frame.scalars[insert_inst->getInsertedValueOperand()]);
                        }
                        frame.scalars[inst] = frame.scalars[insert_inst->getAggregateOperand()];
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::ExtractValue: {
                        auto *extract_inst = llvm::cast<llvm::ExtractValueInst>(inst);
                        if (std::uint8_t(gen_mode & generation_mode::ASSIGNMENTS)) {
                            ptr_type ptr = resolve_number<ptr_type>(frame, extract_inst->getAggregateOperand());
                            // TODO(maksenov): handle offset properly
                            ptr += layout_resolver
                                       ->resolve_offset_with_index_hint<BlueprintFieldType>(
                                           extract_inst->getAggregateOperand()->getType(), extract_inst->getIndices())
                                       .second;
                            const auto origin_var = stack_memory.load(ptr);
                            const auto wrapper = detail::put_constant<typename BlueprintFieldType::value_type,
                                                                      BlueprintFieldType, ArithmetizationParams, var>
                                (var_value(assignments[currProverIdx], origin_var), assignments[currProverIdx]);
                            frame.scalars[inst] = wrapper;
                        } else {
                            const auto undef_var = detail::put_constant<typename BlueprintFieldType::value_type,
                                                                        BlueprintFieldType, ArithmetizationParams, var>
                                (typename BlueprintFieldType::value_type(), assignments[currProverIdx]);
                            frame.scalars[inst] = undef_var;
                        }
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::IndirectBr: {
                        if (std::uint8_t(gen_mode & generation_mode::ASSIGNMENTS) == 0) {
                            UNREACHABLE("IndirectBr is not supported without generating assignment table");
                            return inst->getNextNonDebugInstruction();
                        }
                        ptr_type ptr = resolve_number<ptr_type>(frame, inst->getOperand(0));
                        var bb_var = stack_memory.load(ptr);
                        llvm::BasicBlock *bb = (llvm::BasicBlock *)(resolve_number<uintptr_t>(bb_var));
                        ASSERT(labels.find(bb) != labels.end());
                        return &bb->front();
                    }
                    case llvm::Instruction::PtrToInt: {
                        handle_ptrtoint(inst, inst->getOperand(0), frame);
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::IntToPtr: {
                        if (std::uint8_t(gen_mode & generation_mode::ASSIGNMENTS)) {
                            std::ostringstream oss;
                            size_t offset = resolve_number<size_t>(frame, inst->getOperand(0));
                            oss << var_value(assignments[currProverIdx], frame.scalars[inst->getOperand(0)]).data;
                            ptr_type ptr = stack_memory.inttoptr(offset);
                            log.debug(boost::format("IntToPtr %1% %2%") % oss.str() % ptr);
                            ASSERT(ptr != 0);
                            frame.scalars[inst] = put_into_assignment(ptr);
                        } else {
                            log.debug(boost::format("Skip IntToPtr"));
                            frame.scalars[inst] = put_into_assignment(0);
                        }
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Trunc: {
                        // FIXME: Handle trunc properly. For now just leave value as it is.
                        var x = frame.scalars[inst->getOperand(0)];
                        frame.scalars[inst] = x;
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Freeze: {
                        // Currently freeze is a no-op
                        frame.scalars[inst] = frame.scalars[inst->getOperand(0)];
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
                        if (frame.caller == nullptr) {
                            // Final return
                            finished = true;

                            if (std::uint8_t(gen_mode & generation_mode::SIZE_ESTIMATION)) {

                                std::cout << "\n=====================================================================================\n";
                                std::cout << "statistics:\n";

                                std::size_t circuit_rows_amount = 0;

                                for (const auto& pair : nil::blueprint::component_rows) {
                                    circuit_rows_amount += (pair.second * component_counter[pair.first]);
                                }

                                std::cout << "total rows amount estimation: " << circuit_rows_amount << "\n";
                                std::cout << "total rows amount real:       " << assignments[currProverIdx].allocated_rows() << "\n";
                                std::cout << "_______________________________________________________________________________________\n";

                                for (const auto& pair : nil::blueprint::component_counter) {
                                    std::cout << "component name: " << pair.first << "\n";
                                    std::cout << "Component was used " << pair.second << " times\n";
                                    if (!nil::blueprint::component_finished[pair.first]) {
                                        std::cout << "WARNING: component contains experimental features. Parameters are subject to change, do not fully trust to numbers below.\n";
                                    }
                                    std::cout << "gates amount: " << nil::blueprint::component_gates[pair.first] << "\n";
                                    std::cout << "witness size: " << nil::blueprint::component_witness[pair.first] << "\n";
                                    std::cout << "rows amount:  " << nil::blueprint::component_rows[pair.first];
                                    std::size_t total_rows = nil::blueprint::component_rows[pair.first] * pair.second;
                                    std::cout << " (" << total_rows << " in total)\n";
                                    std::cout << "_______________________________________________________________________________________\n";
                                }
                                std::cout << std::endl;
                            }

                            if(print_output_format != no_print) {
                                if(print_output_format == hex) {
                                    std::cout << std::hex;
                                }
                                if (inst->getNumOperands() != 0 && std::uint8_t(gen_mode & generation_mode::ASSIGNMENTS)) {
                                    llvm::Value *ret_val = inst->getOperand(0);
                                    if (ret_val->getType()->isPointerTy()) {
                                        // TODO(maksenov): support printing complex results
                                    } else if (ret_val->getType()->isVectorTy()) {
                                        std::vector<var> res = frame.vectors[ret_val];
                                        for (var x : res) {
                                            std::cout << var_value(assignments[currProverIdx], x).data << std::endl;
                                        }
                                    } else if (ret_val->getType()->isFieldTy() && field_arg_num<BlueprintFieldType>(ret_val->getType()) > 1) {
                                        std::vector<var> res = frame.vectors[ret_val];
                                        std::vector<typename BlueprintFieldType::value_type> chopped_field;
                                        for (std::size_t i = 0; i < res.size(); i++) {
                                            chopped_field.push_back(var_value(assignments[currProverIdx], res[i]));
                                        }
                                        llvm::GaloisFieldKind ret_field_type;

                                        ASSERT_MSG(llvm::isa<llvm::GaloisFieldType>(ret_val->getType()), "only field types are handled here");
                                        ret_field_type = llvm::cast<llvm::GaloisFieldType>(ret_val->getType())->getFieldKind();

                                        std::cout << unmarshal_field_val<BlueprintFieldType>(ret_field_type, chopped_field) << std::endl;

                                    } else if (ret_val->getType()->isCurveTy()) {
                                        std::size_t curve_len = curve_arg_num<BlueprintFieldType>(ret_val->getType());
                                        ASSERT_MSG(curve_len > 1, "curve element size must be >=2");
                                        if (curve_len == 2) {
                                            std::cout << var_value(assignments[currProverIdx], frame.vectors[ret_val][0]).data << "\n";
                                            std::cout << var_value(assignments[currProverIdx], frame.vectors[ret_val][1]).data << "\n";
                                        }
                                        else {
                                            llvm::GaloisFieldKind ret_field_type;
                                            ASSERT_MSG(llvm::isa<llvm::EllipticCurveType>(ret_val->getType()), "only curves can be handled here");
                                            ret_field_type  = llvm::cast<llvm::EllipticCurveType>(ret_val->getType())->GetBaseFieldKind();

                                            std::vector<var> res = frame.vectors[ret_val];

                                            std::vector<typename BlueprintFieldType::value_type> chopped_field_x;
                                            std::vector<typename BlueprintFieldType::value_type> chopped_field_y;
                                            for (std::size_t i = 0; i < curve_len / 2; i++) {
                                                chopped_field_x.push_back(var_value(assignments[currProverIdx], res[i]));
                                                chopped_field_y.push_back(var_value(assignments[currProverIdx], res[i + (curve_len/2)]));
                                            }
                                            std::cout << unmarshal_field_val<BlueprintFieldType>(ret_field_type, chopped_field_x) << std::endl;
                                            std::cout << unmarshal_field_val<BlueprintFieldType>(ret_field_type, chopped_field_y) << std::endl;

                                        }
                                    } else {
                                        std::cout << var_value(assignments[currProverIdx], frame.scalars[ret_val]).data << std::endl;
                                    }
                                }
                            }
                            if (curr_branch.size() <= 1) {
                                call_stack.pop();
                                stack_memory.pop_frame();
                            }
                            return nullptr;
                        }
                        if (curr_branch.size() == 0 || !curr_branch.back().first ||
                            // call inside branch
                            curr_branch.back().second < call_stack.size()) {
                            auto extracted_frame = std::move(call_stack.top());
                            call_stack.pop();
                            stack_memory.pop_frame();
                            if (inst->getNumOperands() != 0) {
                                llvm::Value *ret_val = inst->getOperand(0);
                                llvm::Type *ret_type = ret_val->getType();
                                auto &upper_frame_variables = call_stack.top().scalars;
                                if (ret_type->isVectorTy() || ret_type->isCurveTy() ||
                                    (ret_type->isFieldTy() && field_arg_num<BlueprintFieldType>(ret_type) > 1)) {
                                    auto &upper_frame_vectors = call_stack.top().vectors;
                                    auto res = extracted_frame.vectors[ret_val];
                                    upper_frame_vectors[extracted_frame.caller] = res;
                                } else if (ret_type->isAggregateType()) {
                                    if (std::uint8_t(gen_mode & generation_mode::ASSIGNMENTS)) {
                                        ptr_type ret_ptr = resolve_number<ptr_type>(extracted_frame, ret_val);
                                        ptr_type allocated_copy = stack_memory.add_cells(
                                            layout_resolver->get_type_layout<BlueprintFieldType>(ret_type));
                                        auto size = layout_resolver->get_type_size(ret_type);
                                        // TODO(maksenov): check if overwriting is possible here
                                        //                 (looks like it is not)
                                        memcpy(allocated_copy, ret_ptr, size);
                                        upper_frame_variables[extracted_frame.caller] =
                                            put_into_assignment(allocated_copy);
                                    } else {
                                        upper_frame_variables[extracted_frame.caller] = put_into_assignment(0);
                                    }
                                } else {
                                    upper_frame_variables[extracted_frame.caller] = extracted_frame.scalars[ret_val];
                                }
                            }
                            return extracted_frame.caller->getNextNonDebugInstruction();
                        }
                        return nullptr;
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

            bool evaluate(
                const llvm::Module &module,
                const boost::json::array &public_input,
                const boost::json::array &private_input
            ) {
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

                auto input_reader = InputReader<BlueprintFieldType, var, assignment_proxy<ArithmetizationType>>(
                    base_frame, stack_memory, assignments[currProverIdx], *layout_resolver, (std::uint8_t(gen_mode & generation_mode::ASSIGNMENTS) != 0));
                if (!input_reader.fill_public_input(function, public_input, private_input, log)) {
                    std::cerr << "Public input does not match the circuit signature";
                    const std::string &error = input_reader.get_error();
                    if (!error.empty()) {
                        std::cout << ": " << error;
                    }
                    std::cout << std::endl;
                    return false;
                }
                call_stack.emplace(std::move(base_frame));

                // Collect all the possible labels that could be an argument in IndirectBrInst
                for (const llvm::Function &function : module) {
                    for (const llvm::BasicBlock &bb : function) {
                        for (const llvm::Instruction &inst : bb) {
                            if (inst.getOpcode() != llvm::Instruction::IndirectBr) {
                                continue;
                            }
                            auto ib = llvm::cast<llvm::IndirectBrInst>(&inst);
                            for (const llvm::BasicBlock *succ : ib->successors()) {
                                if (labels.find(succ) != labels.end()) {
                                    continue;
                                }
                                auto label_type = llvm::Type::getInt8PtrTy(module.getContext());
                                unsigned label_type_size = layout_resolver->get_type_size(label_type);
                                ptr_type ptr = stack_memory.add_cells({{label_type_size, 0}});

                                // Store the pointer to BasicBlock to memory
                                // TODO(maksenov): avoid C++ pointers in assignment table
                                stack_memory.store(ptr, put_into_assignment((const uintptr_t)succ, true));

                                labels[succ] = put_into_assignment(ptr, true);
                            }
                        }
                    }
                }

                // Initialize undef and zero vars once
                undef_var = put_into_assignment(typename BlueprintFieldType::value_type(), true);
                zero_var = put_into_assignment(typename BlueprintFieldType::value_type(0), true);

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

            template<typename InputType>
            var put_into_assignment(InputType input, bool is_shared = false) { // TODO: column index is hardcoded but shouldn't be in the future
                if (is_shared && maxNumProvers > 1) {
                    return detail::put_shared<InputType, BlueprintFieldType, ArithmetizationParams, var>(input, assignments[currProverIdx]);
                } else {
                    return detail::put_constant<InputType, BlueprintFieldType, ArithmetizationParams, var>(input, assignments[currProverIdx]);
                }
            }

        private:
            llvm::LLVMContext context;
            const llvm::BasicBlock *predecessor = nullptr;
            std::stack<stack_frame<var>> call_stack;
            program_memory<var> stack_memory;
            std::unordered_map<const llvm::Value *, var> globals;
            std::unordered_map<const llvm::BasicBlock *, var> labels;
            bool finished = false;
            std::unique_ptr<LayoutResolver> layout_resolver;
            var undef_var;
            var zero_var;
            logger log;
            std::uint32_t maxNumProvers;
            std::uint32_t targetProverIdx;
            std::uint32_t currProverIdx;
            std::shared_ptr<circuit<ArithmetizationType>> bp_ptr;
            std::shared_ptr<assignment<ArithmetizationType>> assignment_ptr;
            std::vector<const void *> cpp_values;
            print_format print_output_format = no_print;
            bool estimate_size;
            bool validity_check;
            generation_mode gen_mode;
            std::vector<branch_desc> curr_branch;
        };

    }     // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENT_INSTRUCTION_PARSER_HPP
