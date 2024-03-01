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

#ifndef ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_ASSIGNER_HPP_
#define ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_ASSIGNER_HPP_

#include <list>
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
#include <nil/blueprint/input_reader.hpp>
#include <nil/blueprint/macros.hpp>
#include <nil/blueprint/memory.hpp>
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

using namespace nil::blueprint::mem;

namespace nil {
    namespace blueprint {

        enum print_format {
            no_print,
            dec,
            hex
        };

        template<typename BlueprintFieldType>
        struct assigner {

            assigner(
                crypto3::zk::snark::plonk_table_description<BlueprintFieldType> desc,
                boost::log::trivial::severity_level log_level,
                std::uint32_t max_num_provers,
                std::uint32_t target_prover_idx,
                generation_mode gen_mode,
                const std::string &kind = "",
                print_format output_print_format = no_print,
                bool check_validity = false
            ) :
                maxNumProvers(max_num_provers),
                targetProverIdx(target_prover_idx),
                currProverIdx(0),
                log(log_level),
                print_output_format(output_print_format),
                validity_check(check_validity),
                gen_mode(gen_mode)
            {

                detail::PolicyManager::set_policy(kind);

                assignment_ptr = std::make_shared<assignment<ArithmetizationType>>(desc);
                bp_ptr = std::make_shared<circuit<ArithmetizationType>>();
                assignments.emplace_back(assignment_ptr, currProverIdx);
                circuits.emplace_back(bp_ptr, currProverIdx);
            }

            using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
            using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
            using branch_desc = std::pair<bool/*is true branch*/, std::uint32_t/*size of call_stack on start branch*/>;
            using type_layout = TypeLayoutResolver::type_layout;

            std::vector<circuit_proxy<ArithmetizationType>> circuits;
            std::vector<assignment_proxy<ArithmetizationType>> assignments;

        private:

            struct AssignerState {
                AssignerState(const assigner& p) {
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

            void restore_state(const AssignerState& assigner_state) {
                predecessor = assigner_state.predecessor;
                currProverIdx = assigner_state.currProverIdx;
                cpp_values = assigner_state.cpp_values;
                gen_mode = assigner_state.gen_mode;
                finished = assigner_state.finished;
            }

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
                llvm::CmpInst::Predicate p = inst->getPredicate();
                const common_component_parameters param = {targetProverIdx, gen_mode};
                handle_comparison_component<BlueprintFieldType> (
                    inst, frame, p, circuits[currProverIdx], assignments[currProverIdx], internal_storage, statistics, param);
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

                const common_component_parameters param = {targetProverIdx, gen_mode};
                for (size_t i = 0; i < lhs.size(); ++i) {
                    using eq_component_type = components::equality_flag<
                        crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType>;
                    auto v = handle_comparison_component_eq_neq<BlueprintFieldType, eq_component_type>(
                        inst->getPredicate(), lhs[i], rhs[i], bitness,
                        circuits[currProverIdx], assignments[currProverIdx], internal_storage, statistics, param);

                    res.emplace_back(v.output);
                }
                handle_result<BlueprintFieldType>
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
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType>;

                const common_component_parameters param = {targetProverIdx, gen_mode};
                for (size_t i = 0; i < lhs.size(); ++i) {
                    auto v = handle_comparison_component_eq_neq<BlueprintFieldType, eq_component_type>(
                        inst->getPredicate(), lhs[i], rhs[i], 0,
                        circuits[currProverIdx], assignments[currProverIdx], internal_storage, statistics, param);
                    res.emplace_back(v.output);
                }

                var are_curves_equal = res[0];

                using component_type = components::logic_and<ArithmetizationType>;

                for (size_t i = 1; i < lhs.size(); ++i) {
                    are_curves_equal = handle_logic_and<BlueprintFieldType>(
                        are_curves_equal, res[i], circuits[currProverIdx], assignments[currProverIdx], internal_storage,
                        statistics, param);
                }
                handle_result<BlueprintFieldType>
                    (assignments[currProverIdx], inst, frame, {are_curves_equal}, gen_mode);
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
                frame.scalars[inst] = put_value_into_internal_storage(res);
            }

            template <typename NumberType>
            NumberType resolve_number(stack_frame<var> &frame, const llvm::Value *value) {
                var scalar = frame.scalars[value];
                return resolve_number<NumberType>(scalar);
            }

            template <typename NumberType>
            NumberType resolve_number(var scalar) {
                auto scalar_value = get_var_value(scalar);
                static constexpr auto limit_value = typename BlueprintFieldType::integral_type(std::numeric_limits<NumberType>::max());
                auto integral_value = static_cast<typename BlueprintFieldType::integral_type>(scalar_value.data);
                ASSERT_MSG(integral_value < limit_value, "");
                NumberType number = static_cast<NumberType>(integral_value);
                return number;
            }

            /**
             * @brief Store constant into memory, returning pointer to it.
             *
             * If constant is a constant expression, try to evaluate it and store the result.
             */
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
                ptr_type ptr = memory.stack_alloca(layout_resolver->get_type_size(constant_init->getType()));
                ptr_type res = ptr;
                while (!component_stack.empty()) {
                    const llvm::Constant *constant = component_stack.top();
                    component_stack.pop();
                    llvm::Type *type = constant->getType();
                    size_type type_size = layout_resolver->get_type_size(type);;
                    switch (type->getTypeID()) {
                        case llvm::Type::PointerTyID: {
                            var value;
                            if (constant->isZeroValue()) {
                                value = zero_var;
                            } else if (globals.find(constant) != globals.end()) {
                                value = globals[constant];
                            } else {
                                LLVM_PRINT(constant, str);
                                UNREACHABLE("Unsupported pointer initialization: " + str);
                            }
                            memory.store(ptr, type_size, value);
                            ptr += type_size;
                            break;
                        }
                        case llvm::Type::IntegerTyID:
                        case llvm::Type::GaloisFieldTyID:{
                            column_type<BlueprintFieldType> marshalled_field_val = marshal_field_val<BlueprintFieldType>(constant);
                            size_type chunk_size = type_size / marshalled_field_val.size();
                            for (typename BlueprintFieldType::value_type chunk : marshalled_field_val) {
                                var variable = put_constant_into_assignment(chunk);
                                memory.store(ptr, chunk_size, variable);
                                ptr += chunk_size;
                            }
                            break;
                        }
                        case llvm::Type::StructTyID:
                        case llvm::Type::ArrayTyID:
                        case llvm::Type::FixedVectorTyID: {
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
                            break;
                        }
                        default: {
                            LLVM_PRINT(type, str);
                            UNREACHABLE("Unsupported constant initialization of type: " + str);
                        }
                    }
                }
                return res;
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

                const common_component_parameters param = {targetProverIdx, gen_mode};

                switch (id) {
                    case llvm::Intrinsic::assigner_malloc: {
                        size_type bytes = resolve_number<size_type>(frame, inst->getOperand(0));
                        frame.scalars[inst] = put_value_into_internal_storage(memory.get_allocator().malloc(bytes));
                        return true;
                    }
                    case llvm::Intrinsic::assigner_free: {
                        if (gen_mode.has_assignments()) {
                            ptr_type ptr = resolve_number<ptr_type>(frame, inst->getOperand(0));
                            memory.get_allocator().free(ptr);
                        }
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

                            handle_component<BlueprintFieldType, component_type>
                                    (circuits[currProverIdx], assignments[currProverIdx], internal_storage, statistics, param, instance_input, inst, frame);
                            return true;
                        }
                        else {
                            UNREACHABLE("poseidon is implemented only for pallas native field");
                        }
                    }
                    case llvm::Intrinsic::assigner_sha2_256: {
                        handle_sha2_256_component<BlueprintFieldType>(inst, frame,
                                                                                             circuits[currProverIdx],
                                                                                             assignments[currProverIdx],
                                                                                             internal_storage,
                                                                                             statistics,
                                                                                             param);
                        return true;
                    }
                    case llvm::Intrinsic::assigner_sha2_512: {
                        if constexpr (std::is_same<BlueprintFieldType, typename nil::crypto3::algebra::curves::pallas::base_field_type>::value) {
                            handle_sha2_512_component<BlueprintFieldType>(inst, frame, circuits[currProverIdx], assignments[currProverIdx], internal_storage, statistics, param);
                            return true;
                        }
                        else {
                            UNREACHABLE("sha512 is implemented only for pallas native field");
                        }
                    }
                    case llvm::Intrinsic::assigner_optimal_ate_pairing: {
                        if constexpr (std::is_same<BlueprintFieldType, typename nil::crypto3::algebra::fields::bls12_base_field<381>>::value) {

                            handle_bls12381_pairing<BlueprintFieldType>(inst, frame, circuits[currProverIdx], assignments[currProverIdx], internal_storage, statistics, param);
                            return true;
                        }
                        else {
                            UNREACHABLE("bls12_optimal_ate_pairing is implemented only for bls12381_base native field");
                        }
                    }
                    case llvm::Intrinsic::assigner_hash_to_curve: {
                        if constexpr (std::is_same<BlueprintFieldType, typename nil::crypto3::algebra::fields::bls12_base_field<381>>::value) {

                            handle_h2c<BlueprintFieldType>(inst, frame, circuits[currProverIdx], assignments[currProverIdx], internal_storage, statistics, param);
                            return true;
                        }
                        else {
                            UNREACHABLE("assigner_hash_to_curve is implemented only for bls12381_base native field");
                        }
                    }
                    case llvm::Intrinsic::assigner_is_in_g1_check: {
                        if constexpr (std::is_same<BlueprintFieldType, typename nil::crypto3::algebra::fields::bls12_base_field<381>>::value) {
                            handle_is_in_g1<BlueprintFieldType>(inst, frame, circuits[currProverIdx], assignments[currProverIdx], internal_storage, statistics, param);
                            return true;
                        }
                        else {
                            UNREACHABLE("__builtin_assigner_is_in_g1_check is implemented only for bls12381_base native field");
                        }
                    }
                    case llvm::Intrinsic::assigner_is_in_g2_check: {
                        if constexpr (std::is_same<BlueprintFieldType, typename nil::crypto3::algebra::fields::bls12_base_field<381>>::value) {
                            handle_is_in_g2<BlueprintFieldType>(inst, frame, circuits[currProverIdx], assignments[currProverIdx], internal_storage, statistics, param);
                            return true;
                        }
                        else {
                            UNREACHABLE("__builtin_assigner_is_in_g2_check is implemented only for bls12381_base native field");
                        }
                    }
                    case llvm::Intrinsic::assigner_gt_multiplication: {
                        if constexpr (std::is_same<BlueprintFieldType, typename nil::crypto3::algebra::fields::bls12_base_field<381>>::value) {
                            handle_fp12_mul<BlueprintFieldType>(inst, frame, circuits[currProverIdx], assignments[currProverIdx], internal_storage, statistics, param);
                            return true;
                        }
                        else {
                            UNREACHABLE("__builtin_assigner_gt_multiplication is implemented only for bls12381_base native field");
                        }
                    }
                    case llvm::Intrinsic::assigner_bit_decomposition_field:
                    case llvm::Intrinsic::assigner_bit_decomposition: {
                        ASSERT(check_operands_constantness(inst, {1, 3}, frame));
                        handle_integer_bit_decomposition_component<BlueprintFieldType>(inst, frame, memory, circuits[currProverIdx], assignments[currProverIdx], internal_storage, statistics, param);
                        return true;
                    }
                    case llvm::Intrinsic::assigner_bit_composition: {
                        ASSERT(check_operands_constantness(inst, {1, 2}, frame));
                        handle_integer_bit_composition_component<BlueprintFieldType>(inst, frame, memory, circuits[currProverIdx], assignments[currProverIdx], internal_storage, statistics, param);
                        return true;
                    }
                    case llvm::Intrinsic::assigner_print_native_pallas_field: {
                        llvm::Value *input = inst->getOperand(0);
                        ASSERT(field_arg_num<BlueprintFieldType>(input->getType()) == 1);
                        std::cout << get_var_value(frame.scalars[input]).data << std::endl;
                        return true;
                    }
                    case llvm::Intrinsic::memcpy: {
                        if (gen_mode.has_assignments()) {
                            llvm::Value *src_val = inst->getOperand(1);
                            ptr_type dst = resolve_number<ptr_type>(frame, inst->getOperand(0));
                            ptr_type src = resolve_number<ptr_type>(frame, src_val);
                            size_type width = resolve_number<size_type>(frame, inst->getOperand(2));
                            memory.memcpy(dst, src, width);
                        }
                        return true;
                    }
                    case llvm::Intrinsic::memset: {
                        if (gen_mode.has_assignments()) {
                            ptr_type dst = resolve_number<ptr_type>(frame, inst->getOperand(0));
                            size_type width = resolve_number<size_type>(frame, inst->getOperand(2));
                            ASSERT(frame.scalars.find(inst->getOperand(1)) != frame.scalars.end());
                            const auto value_var = frame.scalars[inst->getOperand(1)];
                            memory.memset(dst, value_var, width);
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
                        crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType>;

                        var comparison_result = handle_comparison_component_eq_neq<BlueprintFieldType, eq_component_type>(
                            llvm::CmpInst::ICMP_EQ, logical_statement, zero_var, bitness,
                            circuits[currProverIdx], assignments[currProverIdx], internal_storage, statistics, param).output;

                        if (validity_check && gen_mode.has_assignments()) {
                            bool assigner_exit_check_input = get_var_value(comparison_result) == 0;
                            ASSERT_MSG(assigner_exit_check_input,
                                      "assigner_exit_check input is false, verification will fail!\n");
                        }

                        typename eq_component_type::input_type instance_input = {comparison_result, zero_var};
                        handle_component_input<BlueprintFieldType, eq_component_type>(assignments[currProverIdx], internal_storage, instance_input, param);
                        const auto input_vars = instance_input.all_vars();
                        ASSERT(input_vars.size() == 2);
                        circuits[currProverIdx].add_copy_constraint({input_vars[0].get(), input_vars[1].get()});

                        return true;
                    }
                    case llvm::Intrinsic::assigner_exit_check_eq: {

                        const var &x = frame.scalars[inst->getOperand(0)];
                        const var &y = frame.scalars[inst->getOperand(1)];


                        if (validity_check && gen_mode.has_assignments()) {
                            bool exit_check_res = get_var_value(x) == get_var_value(y);
                            ASSERT_MSG(exit_check_res,
                                      "assigner_exit_check_eq_pallas input is false, verification will fail!\n");
                        }

                        using eq_component_type = components::equality_flag<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType>;

                        typename eq_component_type::input_type instance_input = {x, y};
                        handle_component_input<BlueprintFieldType, eq_component_type>(assignments[currProverIdx], internal_storage, instance_input, param);
                        const auto input_vars = instance_input.all_vars();
                        ASSERT(input_vars.size() == 2);
                        circuits[currProverIdx].add_copy_constraint({input_vars[0].get(), input_vars[1].get()});

                        return true;
                    }
                    case llvm::Intrinsic::assigner_fri_lin_inter: {
                        handle_fri_lin_inter_component<BlueprintFieldType>(inst, frame, memory, circuits[currProverIdx], assignments[currProverIdx], internal_storage, statistics, param);
                        return true;
                    }
                    case llvm::Intrinsic::assigner_fri_cosets: {
                        ASSERT_MSG(check_operands_constantness(inst, {1, 2}, frame), "result length, omega and total_bits must be constants");
                        handle_fri_cosets_component<BlueprintFieldType>(inst, frame, memory, circuits[currProverIdx], assignments[currProverIdx], internal_storage, statistics, param);
                        return true;
                    }
                    case llvm::Intrinsic::assigner_gate_arg_verifier: {
                        ASSERT_MSG(check_operands_constantness(inst, {1, 2, 4}, frame), "gates_sizes, gates and selectors amount must be constants");
                        handle_gate_arg_verifier_component<BlueprintFieldType>(inst, frame, memory, circuits[currProverIdx], assignments[currProverIdx], internal_storage, statistics, param);
                        return true;
                    }
                    case llvm::Intrinsic::assigner_permutation_arg_verifier: {
                        ASSERT_MSG(check_operands_constantness(inst, {3}, frame), "f, se, sigma size must be constant");
                        handle_permutation_arg_verifier_component<BlueprintFieldType>(inst, frame, memory, circuits[currProverIdx], assignments[currProverIdx], internal_storage, statistics, param);
                        return true;
                    }
                    case llvm::Intrinsic::assigner_lookup_arg_verifier: {
                        std::vector<std::size_t> constants_positions = {};
                        for (std::size_t i = 0; i < 8; i++) { constants_positions.push_back(i);}
                        for (std::size_t i = 4; i < 13; i++) { constants_positions.push_back(2*i + 1);}
                        ASSERT_MSG(check_operands_constantness(inst, constants_positions, frame), "vectors sizes must be constants");
                        handle_lookup_arg_verifier_component<BlueprintFieldType>(inst, frame, memory, circuits[currProverIdx], assignments[currProverIdx], internal_storage, statistics, param);
                        return true;
                    }
                    case llvm::Intrinsic::assigner_fri_array_swap: {
                        ASSERT_MSG(check_operands_constantness(inst, {1}, frame), "array size must be constant");
                        handle_fri_array_swap_component<BlueprintFieldType>(inst, frame, memory, circuits[currProverIdx], assignments[currProverIdx], internal_storage, statistics, param);
                        return true;
                    }

                    default:
                        llvm::Function *intrinsic_func = llvm::cast<llvm::CallInst>(inst)->getCalledFunction();
                        std::string intrinsic_name = intrinsic_func->getName().str();
                        UNREACHABLE("Unexpected intrinsic: " + intrinsic_name);
                }
                return false;
            }

            /// @brief Store value at given pointer in memory.
            void handle_store(ptr_type ptr, const llvm::Value *val, stack_frame<var> &frame) {
                llvm::Type *type = val->getType();

                // Store values from vector register
                auto store_from_vector = [this, type](ptr_type ptr, const llvm::Value *val,
                                                      typename stack_frame<var>::vector_regs &vectors) {
                    type_layout layout = layout_resolver->get_type_layout<BlueprintFieldType>(type);
                    std::vector<var> value = vectors[val];
                    // Vector of vars gives us scalar components of the whole value and layout
                    // describes their sizes.
                    ASSERT(layout.size() == value.size());
                    for (auto i = 0; i < layout.size(); ++i) {
                        memory.store(ptr, layout[i], value[i]);
                        ptr += layout[i];
                    }
                };

                switch (type->getTypeID()) {
                    case llvm::Type::PointerTyID:
                    case llvm::Type::IntegerTyID: {
                        memory.store(ptr, layout_resolver->get_type_size(type), frame.scalars[val]);
                        break;
                    }
                    case llvm::Type::GaloisFieldTyID: {
                        if (field_arg_num<BlueprintFieldType>(type) == 1) {
                            // Native field case
                            memory.store(ptr, layout_resolver->get_type_size(type), frame.scalars[val]);
                        } else {
                            store_from_vector(ptr, val, frame.vectors);
                        }
                        break;
                    }
                    case llvm::Type::EllipticCurveTyID:
                    case llvm::Type::ArrayTyID:
                    case llvm::Type::StructTyID:
                    case llvm::Type::FixedVectorTyID: {
                        store_from_vector(ptr, val, frame.vectors);
                        break;
                    }
                    default: {
                        LLVM_PRINT(type, str);
                        UNREACHABLE("Unsupported store of type: " + str);
                    }
                }
            }

            /**
             * @brief Load value from memory and store it into `frame`.
             *
             * Value size is infered from `dest` type.
             */
            void handle_load(ptr_type ptr, const llvm::Value *dest, stack_frame<var> &frame) {
                llvm::Type *type = dest->getType();

                // Load values into scalar register
                auto load_into_scalar = [this, type](ptr_type ptr, const llvm::Value *dest,
                                                     typename stack_frame<var>::scalar_regs &scalars) {
                    var value;
                    size_type type_size = layout_resolver->get_type_size(type);
                    value = put_value_into_internal_storage(get_var_value(memory.load(ptr, type_size)));
                    scalars[dest] = value;
                };

                // Load values into vector register
                auto load_into_vector = [this, type](ptr_type ptr, const llvm::Value *dest,
                                                     typename stack_frame<var>::vector_regs &vectors) {
                    type_layout layout = layout_resolver->get_type_layout<BlueprintFieldType>(type);
                    std::vector<var> values;
                    for (auto i = 0; i < layout.size(); ++i) {
                        var value;
                        value =
                            put_value_into_internal_storage(get_var_value(memory.load(ptr, layout[i])));
                        values.push_back(value);
                        ptr += layout[i];
                    }
                    vectors[dest] = values;
                };

                switch (type->getTypeID()) {
                    case llvm::Type::PointerTyID:
                    case llvm::Type::IntegerTyID: {
                        load_into_scalar(ptr, dest, frame.scalars);
                        break;
                    }
                    case llvm::Type::GaloisFieldTyID: {
                        if (field_arg_num<BlueprintFieldType>(type) == 1) {
                            // Native field case
                            load_into_scalar(ptr, dest, frame.scalars);
                        } else {
                            load_into_vector(ptr, dest, frame.vectors);
                        }
                        break;
                    }
                    case llvm::Type::EllipticCurveTyID:
                    case llvm::Type::StructTyID:
                    case llvm::Type::ArrayTyID:
                    case llvm::Type::FixedVectorTyID: {
                        load_into_vector(ptr, dest, frame.vectors);
                        break;
                    }
                    default: {
                        LLVM_PRINT(type, str);
                        UNREACHABLE("Unsupported load of type: " + str);
                    }
                }
            }

            /// @brief Handle `getelementptr` instruction or constant expression.
            ptr_type handle_gep(const llvm::Value *pointer_operand,
                                const llvm::Value *initial_idx_operand,
                                llvm::Type *gep_ty,
                                std::list<int> &gep_indices,
                                stack_frame<var> &frame) {
                ASSERT_MSG(pointer_operand->getType()->isPointerTy(),
                           "vector of pointers is not supported for getelementptr instruction");
                ptr_type ptr = resolve_number<ptr_type>(frame, pointer_operand);

                // Handle indexing first pointer
                // FIXME: This is naive implementation, which does not handle negative index
                // and doesn't take into account type of the index. Must be fixed.
                int idx = resolve_number<int>(frame, initial_idx_operand);
                if (idx < 0) {
                    TODO("getelementptr with negative first index");
                }
                ptr += idx * layout_resolver->get_type_size(gep_ty);

                // Handle all operands left
                if (!gep_indices.empty()) {
                    // TODO: if this is ensured by LLVM, do we need this assertion?
                    ASSERT_MSG(gep_ty->isAggregateType(),
                               "GEP instruction with > 1 indices must operate on aggregate type");
                    ptr += layout_resolver->get_offset_of_element(gep_ty, gep_indices);
                }
                return ptr;
            }

            void handle_ptrtoint(const llvm::Value *result, const llvm::Value *pointer, stack_frame<var> &frame) {
                if (gen_mode.has_assignments()) {
                    ASSERT_MSG(pointer->getType()->isPointerTy(),
                               "ptrtoint with vector arguments is not supported now");
                    ptr_type ptr = resolve_number<ptr_type>(frame, pointer);
                    unsigned dest_bit_width = result->getType()->getIntegerBitWidth();
                    if (dest_bit_width < mem::ptr_bit_width) {
                        // get `dest_bit_width` least significant bits from `ptr`
                        ptr = ptr & ((1 << dest_bit_width) - 1);
                    }
                    frame.scalars[result] = put_constant_into_assignment(ptr);
                } else {
                    log.debug(boost::format("Skip PtrToInt"));
                    frame.scalars[result] = put_constant_into_assignment(0);
                }
            }

            void put_global(const llvm::GlobalVariable *global) {
                if (globals.find(global) != globals.end()) {
                    return;
                }
                const llvm::Constant *initializer = global->getInitializer();
                if (initializer->getType()->isAggregateType()) {
                    ptr_type ptr = store_constant(initializer);
                    globals[global] = put_constant_into_assignment(ptr);
                } else if (initializer->getType()->isIntegerTy() ||
                           (initializer->getType()->isFieldTy() &&
                            field_arg_num<BlueprintFieldType>(initializer->getType()) == 1)) {
                    size_type constant_width = layout_resolver->get_type_size(initializer->getType());
                    ptr_type ptr = memory.stack_alloca(constant_width);
                    column_type<BlueprintFieldType> marshalled_field_val = marshal_field_val<BlueprintFieldType>(initializer);
                    memory.store(ptr, constant_width, put_constant_into_assignment(marshalled_field_val[0]));
                    globals[global] = put_constant_into_assignment(ptr);
                } else if (llvm::isa<llvm::ConstantPointerNull>(initializer)) {
                    size_type ptr_width = layout_resolver->get_type_size(initializer->getType());
                    ptr_type ptr = memory.stack_alloca(ptr_width);
                    memory.store(ptr, ptr_width, zero_var);
                    globals[global] = put_constant_into_assignment(ptr);
                } else {
                    LLVM_PRINT(global, str);
                    UNREACHABLE("Unhandled global variable: " + str);
                }
            }

            void put_constant(llvm::Constant *c, stack_frame<var> &frame) {
                if (llvm::isa<llvm::ConstantField>(c) || llvm::isa<llvm::ConstantInt>(c)) {
                    column_type<BlueprintFieldType> marshalled_field_val = marshal_field_val<BlueprintFieldType>(c);
                    if (marshalled_field_val.size() == 1) {
                        frame.scalars[c] = put_constant_into_assignment(marshalled_field_val[0]);
                    }
                    else {
                        frame.vectors[c] = {};
                        for (std::size_t i = 0; i < marshalled_field_val.size(); i++) {
                            frame.vectors[c].push_back(put_constant_into_assignment(marshalled_field_val[i]));
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
                        size_type size = layout_resolver->get_type_size(undef_type);
                        ptr_type ptr = memory.stack_alloca(size);
                        memory.store(ptr, size, undef_var);
                        frame.scalars[c] = put_constant_into_assignment(ptr);
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
                        column_type<BlueprintFieldType> marshalled_field_val = marshal_field_val<BlueprintFieldType>(elem);
                        for (std::size_t j = 0; j < marshalled_field_val.size(); j++) {
                            result_vector[i * arg_num + j] = put_constant_into_assignment(marshalled_field_val[j]);
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
                        if (gen_mode.has_assignments()) {
                                std::list<int> gep_indices;
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

                                ptr_type gep_res = handle_gep(expr->getOperand(0), expr->getOperand(1),
                                                              source_element_type, gep_indices, frame);
                                frame.scalars[c] = put_constant_into_assignment(gep_res);
                        } else {
                            frame.scalars[c] = put_constant_into_assignment(0);
                        }
                        break;
                    }
                    default: {
                        LLVM_PRINT(expr, str);
                        UNREACHABLE("Unhandled constant expression: " + str);
                    }
                    }
                } else if (auto addr = llvm::dyn_cast<llvm::BlockAddress>(c)) {
                    frame.scalars[c] = labels[addr->getBasicBlock()];
                } else if (auto func = llvm::dyn_cast<llvm::Function>(c)) {
                    cpp_values.push_back(func);
                    frame.scalars[c] = put_constant_into_assignment(cpp_values.size() - 1);
                } else if (auto *gv = llvm::dyn_cast<llvm::GlobalVariable>(c)) {
                    put_global(gv);
                    frame.scalars[c] = globals[c];
                } else {
                    // The only other known constant is an address of a function in CallInst,
                    // but there is no way to distinguish it
                    ASSERT(c->getType()->isPointerTy());
                }
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

                const common_component_parameters param = {targetProverIdx, gen_mode};

                switch (inst->getOpcode()) {
                    case llvm::Instruction::Add: {

                        if (inst->getOperand(0)->getType()->isIntegerTy()) {
                            handle_integer_addition_component<BlueprintFieldType>(
                                        inst, frame, circuits[currProverIdx], assignments[currProverIdx], internal_storage, statistics, param);
                            return inst->getNextNonDebugInstruction();
                        }

                        if (inst->getOperand(0)->getType()->isFieldTy() && inst->getOperand(1)->getType()->isFieldTy()) {
                            handle_field_addition_component<BlueprintFieldType>(
                                        inst, frame, circuits[currProverIdx], assignments[currProverIdx], internal_storage, statistics, param);
                            return inst->getNextNonDebugInstruction();
                        } else if (inst->getOperand(0)->getType()->isCurveTy() && inst->getOperand(1)->getType()->isCurveTy()) {
                            handle_curve_addition_component<BlueprintFieldType>(
                                        inst, frame, circuits[currProverIdx], assignments[currProverIdx], internal_storage, statistics, param);
                            return inst->getNextNonDebugInstruction();
                        } else {
                            UNREACHABLE("curve + scalar is undefined");
                        }

                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Sub: {
                        if (inst->getOperand(0)->getType()->isIntegerTy()) {
                            handle_integer_subtraction_component<BlueprintFieldType>(
                                inst, frame, circuits[currProverIdx], assignments[currProverIdx], internal_storage, statistics, param);
                            return inst->getNextNonDebugInstruction();
                        }

                        if (inst->getOperand(0)->getType()->isFieldTy() && inst->getOperand(1)->getType()->isFieldTy()) {
                            handle_field_subtraction_component<BlueprintFieldType>(
                                inst, frame, circuits[currProverIdx], assignments[currProverIdx], internal_storage, statistics, param);
                            return inst->getNextNonDebugInstruction();
                        } else if (inst->getOperand(0)->getType()->isCurveTy() && inst->getOperand(1)->getType()->isCurveTy()) {
                            handle_curve_subtraction_component<BlueprintFieldType>(
                                inst, frame, circuits[currProverIdx], assignments[currProverIdx], internal_storage, statistics, param);
                            return inst->getNextNonDebugInstruction();
                        } else {
                            UNREACHABLE("curve - scalar is undefined");
                        }

                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Mul: {

                        if (inst->getOperand(0)->getType()->isIntegerTy()) {
                            handle_integer_multiplication_component<BlueprintFieldType>(
                                inst, frame, circuits[currProverIdx], assignments[currProverIdx], internal_storage, statistics, param);
                            return inst->getNextNonDebugInstruction();
                        }

                        if (inst->getOperand(0)->getType()->isFieldTy() && inst->getOperand(1)->getType()->isFieldTy()) {
                            handle_field_multiplication_component<BlueprintFieldType>(
                                inst, frame, circuits[currProverIdx], assignments[currProverIdx], internal_storage, statistics, param);
                            return inst->getNextNonDebugInstruction();
                        }

                        UNREACHABLE("Mul opcode is defined only for fieldTy and integerTy");

                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::CMul: {
                        if (
                            (inst->getOperand(0)->getType()->isCurveTy() && inst->getOperand(1)->getType()->isFieldTy()) ||
                            (inst->getOperand(1)->getType()->isCurveTy() && inst->getOperand(0)->getType()->isFieldTy())) {
                            handle_curve_multiplication_component<BlueprintFieldType>(
                                inst, frame, circuits[currProverIdx], assignments[currProverIdx], internal_storage, statistics, param);
                            return inst->getNextNonDebugInstruction();
                        } else {
                            UNREACHABLE("cmul opcode is defined only for curveTy * fieldTy");
                        }
                    }
                    case llvm::Instruction::UDiv: {
                        if (inst->getOperand(0)->getType()->isIntegerTy() && inst->getOperand(1)->getType()->isIntegerTy()) {
                            handle_integer_division_remainder_component<BlueprintFieldType>(
                                inst, frame, circuits[currProverIdx], assignments[currProverIdx], internal_storage, statistics, param, true);
                            return inst->getNextNonDebugInstruction();
                        }
                        else if (inst->getOperand(0)->getType()->isFieldTy() && inst->getOperand(1)->getType()->isFieldTy()) {
                            handle_field_division_component<BlueprintFieldType>(
                                inst, frame, circuits[currProverIdx], assignments[currProverIdx], internal_storage, statistics, param);
                            return inst->getNextNonDebugInstruction();
                        }
                        else {
                            UNREACHABLE("UDiv opcode is defined only for integerTy and fieldTy");
                        }
                    }
                    case llvm::Instruction::URem: {
                        if (inst->getOperand(0)->getType()->isIntegerTy() && inst->getOperand(1)->getType()->isIntegerTy()) {
                            handle_integer_division_remainder_component<BlueprintFieldType>(
                                inst, frame, circuits[currProverIdx], assignments[currProverIdx], internal_storage, statistics, param, false);
                            return inst->getNextNonDebugInstruction();
                        } else {
                            UNREACHABLE("URem opcode is defined only for integerTy");
                        }
                    }
                    case llvm::Instruction::Shl: {
                        if (inst->getOperand(0)->getType()->isIntegerTy() && inst->getOperand(1)->getType()->isIntegerTy()) {
                            handle_integer_bit_shift_constant_component<BlueprintFieldType>(
                                inst, frame, circuits[currProverIdx], assignments[currProverIdx], internal_storage, statistics, param,
                                        nil::blueprint::components::bit_shift_mode::LEFT);
                            return inst->getNextNonDebugInstruction();
                        } else {
                            UNREACHABLE("shl opcode is defined only for integerTy");
                        }
                    }
                    case llvm::Instruction::LShr: {
                        if (inst->getOperand(0)->getType()->isIntegerTy() && inst->getOperand(1)->getType()->isIntegerTy()) {
                            handle_integer_bit_shift_constant_component<BlueprintFieldType>(
                                inst, frame, circuits[currProverIdx], assignments[currProverIdx], internal_storage, statistics, param,
                                        nil::blueprint::components::bit_shift_mode::RIGHT);
                            return inst->getNextNonDebugInstruction();
                        } else {
                            UNREACHABLE("LShr opcode is defined only for integerTy");
                        }
                    }
                    case llvm::Instruction::SDiv: {

                        if (inst->getOperand(0)->getType()->isIntegerTy()) {
                            handle_integer_division_component<BlueprintFieldType>(
                                inst, frame, circuits[currProverIdx], assignments[currProverIdx], internal_storage, statistics, param);
                            return inst->getNextNonDebugInstruction();
                        }

                        if (inst->getOperand(0)->getType()->isFieldTy() && inst->getOperand(1)->getType()->isFieldTy()) {
                            handle_field_division_component<BlueprintFieldType>(
                                inst, frame, circuits[currProverIdx], assignments[currProverIdx], internal_storage, statistics, param);
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
                            } else {
                                ASSERT(variables.find(call_inst->getOperand(i)) != variables.end());
                                new_variables[arg] = variables[call_inst->getOperand(i)];
                            }
                        }
                        new_frame.caller = call_inst;
                        call_stack.emplace(std::move(new_frame));
                        memory.push_frame();
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
                            LLVM_PRINT(cmp_type, str);
                            UNREACHABLE("Unsupported icmp operand type: " + str);
                        }
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Select: {
                        var condition = variables[inst->getOperand(0)];
                        llvm::Value *true_val = inst->getOperand(1);
                        llvm::Value *false_val = inst->getOperand(2);
                        if (get_var_value(condition) != 0) {
                            variables[inst] = put_value_into_internal_storage(get_var_value(variables[true_val]));
                        } else {
                            variables[inst] = put_value_into_internal_storage(get_var_value(variables[false_val]));
                        }
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::And: {
                        const var &lhs = variables[inst->getOperand(0)];
                        const var &rhs = variables[inst->getOperand(1)];

                        // TODO: replace mock with component

                        typename BlueprintFieldType::integral_type x_integer(
                            get_var_value(lhs).data);
                        typename BlueprintFieldType::integral_type y_integer(
                            get_var_value(rhs).data);
                        typename BlueprintFieldType::value_type res = (x_integer & y_integer);
                        variables[inst] = put_value_into_internal_storage(res);

                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Or: {
                        const var &lhs = variables[inst->getOperand(0)];
                        const var &rhs = variables[inst->getOperand(1)];

                        // TODO: replace mock with component

                        typename BlueprintFieldType::integral_type x_integer(
                            get_var_value(lhs).data);
                        typename BlueprintFieldType::integral_type y_integer(
                            get_var_value(rhs).data);
                        typename BlueprintFieldType::value_type res = (x_integer | y_integer);
                        variables[inst] = put_value_into_internal_storage(res);
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Xor: {
                        const var &lhs = variables[inst->getOperand(0)];
                        const var &rhs = variables[inst->getOperand(1)];

                        // TODO: replace mock with component

                        typename BlueprintFieldType::integral_type x_integer(
                            get_var_value(lhs).data);
                        typename BlueprintFieldType::integral_type y_integer(
                            get_var_value(rhs).data);
                        typename BlueprintFieldType::value_type res = (x_integer ^ y_integer);
                        variables[inst] = put_value_into_internal_storage(res);
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
                            if (gen_mode.has_assignments()) {
                                bool cond_val = (get_var_value(cond) != 0);

                                const AssignerState assigner_state(*this);

                                curr_branch.push_back(branch_desc(false, stack_size));
                                curr_branch.push_back(branch_desc(true, stack_size));
                                if (!cond_val) {
                                    gen_mode = (gen_mode.has_assignments() || gen_mode.has_false_assignments()) ?
                                        (gen_mode & generation_mode::circuit()) | generation_mode::false_assignments() :
                                        gen_mode & generation_mode::circuit();
                                }

                                log.debug(boost::format("start handle true branch: %1% %2%") % curr_branch.size() % !gen_mode.has_assignments());
                                const llvm::Instruction* true_next_inst = nullptr;
                                if (!cond_val && true_name == "panic") {
                                    log.debug(boost::format("skip handle true branch as false positive panic: %1%") % curr_branch.size());
                                } else {
                                    true_next_inst = handle_branch(&(true_bb->front()));
                                    log.debug(boost::format("stop handle true branch: %1% %2%") % curr_branch.size() %
                                              true_next_inst);
                                }

                                AssignerState true_assigner_state(*this);
                                restore_state(assigner_state);

                                curr_branch.pop_back();

                                if (cond_val) {
                                    gen_mode = (gen_mode.has_assignments() || gen_mode.has_false_assignments()) ?
                                                  (gen_mode & generation_mode::circuit()) | generation_mode::false_assignments() :
                                                  gen_mode & generation_mode::circuit();
                                }

                                log.debug(boost::format("start handle false branch: %1% %2%") % curr_branch.size() % !gen_mode.has_assignments());
                                auto false_next_inst = true_next_inst;
                                if (cond_val && false_name == "panic") {
                                    log.debug(boost::format("skip handle false branch as false positive panic: %1%") % curr_branch.size());
                                } else {
                                    false_next_inst = handle_branch(&(false_bb->front()));
                                    log.debug(boost::format("stop handle false branch: %1% %2%") % curr_branch.size() %
                                              false_next_inst);
                                }

                                if (false_next_inst != nullptr && cond_val) {
                                    restore_state(true_assigner_state);
                                }

                                curr_branch.pop_back();

                                ASSERT((stack_size - 1) == call_stack.size() || finished);

                                return false_next_inst;
                            }

                            const AssignerState assigner_state(*this);
                            curr_branch.push_back(branch_desc(false, stack_size));
                            curr_branch.push_back(branch_desc(true, stack_size));

                            log.debug(boost::format("start handle true branch: %1% %2%") % curr_branch.size() % !gen_mode.has_assignments());
                            const llvm::Instruction* true_next_inst = nullptr;
                            if (true_name == "panic") {
                                log.debug(boost::format("skip handle true branch as false positive panic: %1%") % curr_branch.size());
                            } else {
                                true_next_inst = handle_branch(&(true_bb->front()));
                                log.debug(boost::format("stop handle true branch: %1% %2%") % curr_branch.size() %
                                          true_next_inst);
                            }

                            restore_state(assigner_state);
                            curr_branch.pop_back();

                            log.debug(boost::format("start handle false branch: %1% %2%") % curr_branch.size() % (gen_mode.has_assignments() == 0));
                            auto false_next_inst = true_next_inst;
                            if (false_name == "panic") {
                                log.debug(boost::format("skip handle false branch as false positive panic: %1%") % curr_branch.size());
                            } else {
                                false_next_inst = handle_branch(&(false_bb->front()));
                                log.debug(boost::format("stop handle false branch: %1% %2%") % curr_branch.size() %
                                          false_next_inst);
                            }

                            if (false_next_inst) {
                                restore_state(assigner_state);
                            }
                            curr_branch.pop_back();

                            ASSERT((stack_size - 1) == call_stack.size() || finished);

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
                                    (value_type->isFieldTy() &&
                                     field_arg_num<BlueprintFieldType>(value_type) == 1)) {
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
                        if (gen_mode.has_assignments()) {
                            unsigned bit_width = llvm::cast<llvm::IntegerType>(cond->getType())->getBitWidth();
                            ASSERT(bit_width <= 64);
                            auto cond_var = get_var_value(frame.scalars[cond]);
                            auto cond_val = llvm::APInt(
                                bit_width,
                                (int64_t) static_cast<typename BlueprintFieldType::integral_type>(cond_var.data));
                            for (auto Case : switch_inst->cases()) {
                                if (Case.getCaseValue()->getValue().eq(cond_val)) {
                                    gen_mode = (gen_mode.has_assignments() && gen_mode.has_false_assignments()) ?
                                            (gen_mode & generation_mode::circuit()) | generation_mode::false_assignments() :
                                            gen_mode & generation_mode::circuit();
                                }
                                const AssignerState assigner_state(*this);
                                curr_branch.push_back(branch_desc(false, call_stack.size()));
                                const auto next_inst = handle_branch(&Case.getCaseSuccessor()->front());
                                curr_branch.pop_back();
                            }
                        } else {
                            for (auto Case : switch_inst->cases()) {
                                const AssignerState assigner_state(*this);
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
                            int index = resolve_number<int>(frame, index_value);
                            variables[inst] = frame.vectors[vec][index];
                            return inst->getNextNonDebugInstruction();
                        }
                        int index = llvm::cast<llvm::ConstantInt>(index_value)->getZExtValue();
                        variables[inst] = frame.vectors[vec][index];
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Alloca: {
                        auto *alloca = llvm::cast<llvm::AllocaInst>(inst);
                        unsigned size = layout_resolver->get_type_size(alloca->getAllocatedType());
                        ptr_type res_ptr = memory.stack_alloca(size);
                        frame.scalars[inst] = put_value_into_internal_storage(res_ptr);
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::GetElementPtr: {
                        auto *gep = llvm::cast<llvm::GetElementPtrInst>(inst);
                        if (gen_mode.has_assignments()) {
                            std::list<int> gep_indices;
                            for (unsigned i = 1; i < gep->getNumIndices(); ++i) {
                                int gep_index = resolve_number<int>(frame, gep->getOperand(i + 1));
                                gep_indices.push_back(gep_index);
                            }
                            ptr_type gep_res = handle_gep(gep->getPointerOperand(), gep->getOperand(1),
                                                          gep->getSourceElementType(), gep_indices, frame);
                            log.debug(boost::format("GEP: %1%") % gep_res);
                            frame.scalars[gep] = put_value_into_internal_storage(gep_res);
                        } else {
                            log.debug(boost::format("Skip GEP"));
                            frame.scalars[gep] = put_value_into_internal_storage(0);
                        }
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Load: {
                        auto *load_inst = llvm::cast<llvm::LoadInst>(inst);
                        ptr_type ptr = resolve_number<ptr_type>(frame, load_inst->getPointerOperand());
                        log.debug(boost::format("Load: %1%") % ptr);
                        handle_load(ptr, load_inst, frame);
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::Store: {
                        auto *store_inst = llvm::cast<llvm::StoreInst>(inst);
                        ptr_type ptr = resolve_number<ptr_type>(frame, store_inst->getPointerOperand());
                        if (gen_mode.has_assignments()) {
                            log.debug(boost::format("Store: %1%") % ptr);
                            const llvm::Value *val = store_inst->getValueOperand();
                            handle_store(ptr, val, frame);
                        } else {
                            log.debug(boost::format("Skip store: %1%") % ptr);
                        }
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::InsertValue: {
                        TODO("InsertValue");
                    }
                    case llvm::Instruction::ExtractValue: {
                        TODO("ExtractValue");
                    }
                    case llvm::Instruction::IndirectBr: {
                        if (!gen_mode.has_assignments()) {
                            UNREACHABLE("IndirectBr is not supported without generating assignment table");
                        }
                        // TODO: we don't need to recalculate label type every time, it's constant
                        auto label_type = llvm::Type::getInt8PtrTy(context);
                        unsigned label_type_size = layout_resolver->get_type_size(label_type);
                        ptr_type ptr = resolve_number<ptr_type>(frame, inst->getOperand(0));
                        var bb_var = memory.load(ptr, label_type_size);
                        llvm::BasicBlock *bb = (llvm::BasicBlock *)(resolve_number<uintptr_t>(bb_var));
                        ASSERT(labels.find(bb) != labels.end());
                        return &bb->front();
                    }
                    case llvm::Instruction::PtrToInt: {
                        handle_ptrtoint(inst, inst->getOperand(0), frame);
                        return inst->getNextNonDebugInstruction();
                    }
                    case llvm::Instruction::IntToPtr: {
                        if (gen_mode.has_assignments()) {
                            auto *inttoptr = llvm::cast<llvm::IntToPtrInst>(inst);
                            ASSERT_MSG(inttoptr->getSrcTy()->isIntegerTy(),
                                    "inttoptr with vector arguments is not supported now");
                            ptr_type ptr = resolve_number<ptr_type>(frame, inttoptr->getOperand(0));
                            unsigned src_bit_width = inttoptr->getSrcTy()->getIntegerBitWidth();
                            if (src_bit_width > mem::ptr_bit_width) {
                                TODO("integer must be truncated to pointer size");
                            }
                            frame.scalars[inst] = put_value_into_internal_storage(ptr);
                        } else {
                            log.debug(boost::format("Skip IntToPtr"));
                            frame.scalars[inst] = put_value_into_internal_storage(0);
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

                            // Fill return value
                            if (inst->getNumOperands() != 0 && gen_mode.has_assignments()) {
                                auto ret_val = inst->getOperand(0);
                                auto ret_type = ret_val->getType();
                                switch (ret_type->getTypeID()) {
                                    case llvm::Type::IntegerTyID: {
                                        return_value = {typename BlueprintFieldType::integral_type(
                                            var_value(assignments[currProverIdx], frame.scalars[ret_val]).data)};
                                        break;
                                    }
                                    case llvm::Type::GaloisFieldTyID: {
                                        auto field_type = llvm::cast<llvm::GaloisFieldType>(ret_type);
                                        if (field_arg_num<BlueprintFieldType>(field_type) == 1) {
                                            // Native field case
                                            return_value = {typename BlueprintFieldType::integral_type(
                                                var_value(assignments[currProverIdx], frame.scalars[ret_val]).data)};
                                        } else {
                                            std::vector<var> res = frame.vectors[ret_val];
                                            std::vector<typename BlueprintFieldType::value_type> chopped_field;
                                            for (std::size_t i = 0; i < res.size(); i++) {
                                                chopped_field.push_back(var_value(assignments[currProverIdx], res[i]));
                                            }
                                            return_value = {unmarshal_field_val<BlueprintFieldType>(field_type->getFieldKind(), chopped_field)};
                                        }
                                        break;
                                    }
                                    default: {
                                        // Do nothing, just leave return value empty.
                                        // Right now I don't think we should create an error here.
                                    }
                                }
                            }

                            if(print_output_format != no_print && gen_mode.has_assignments()) {
                                if(print_output_format == hex) {
                                    std::cout << std::hex;
                                }
                                if (inst->getNumOperands() != 0) {
                                    llvm::Value *ret_val = inst->getOperand(0);
                                    if (ret_val->getType()->isPointerTy()) {
                                        // TODO(maksenov): support printing complex results
                                    } else if (ret_val->getType()->isVectorTy()) {
                                        std::vector<var> res = frame.vectors[ret_val];
                                        for (var x : res) {
                                            std::cout << get_var_value(x).data << std::endl;
                                        }
                                    } else if (ret_val->getType()->isFieldTy() && field_arg_num<BlueprintFieldType>(ret_val->getType()) > 1) {
                                        std::vector<var> res = frame.vectors[ret_val];
                                        column_type<BlueprintFieldType> chopped_field;
                                        for (std::size_t i = 0; i < res.size(); i++) {
                                            chopped_field.push_back(get_var_value(res[i]));
                                        }
                                        llvm::GaloisFieldKind ret_field_type;

                                        ASSERT_MSG(llvm::isa<llvm::GaloisFieldType>(ret_val->getType()), "only field types are handled here");
                                        ret_field_type = llvm::cast<llvm::GaloisFieldType>(ret_val->getType())->getFieldKind();

                                        std::cout << unmarshal_field_val<BlueprintFieldType>(ret_field_type, chopped_field) << std::endl;

                                    } else if (ret_val->getType()->isCurveTy()) {
                                        std::size_t curve_len = curve_arg_num<BlueprintFieldType>(ret_val->getType());
                                        ASSERT_MSG(curve_len > 1, "curve element size must be >=2");
                                        if (curve_len == 2) {
                                            std::cout << get_var_value(frame.vectors[ret_val][0]).data << "\n";
                                            std::cout << get_var_value(frame.vectors[ret_val][1]).data << "\n";
                                        }
                                        else {
                                            llvm::GaloisFieldKind ret_field_type;
                                            ASSERT_MSG(llvm::isa<llvm::EllipticCurveType>(ret_val->getType()), "only curves can be handled here");
                                            ret_field_type  = llvm::cast<llvm::EllipticCurveType>(ret_val->getType())->GetBaseFieldKind();

                                            std::vector<var> res = frame.vectors[ret_val];

                                            column_type<BlueprintFieldType> chopped_field_x;
                                            column_type<BlueprintFieldType> chopped_field_y;
                                            for (std::size_t i = 0; i < curve_len / 2; i++) {
                                                chopped_field_x.push_back(get_var_value(res[i]));
                                                chopped_field_y.push_back(get_var_value(res[i + (curve_len/2)]));
                                            }
                                            std::cout << unmarshal_field_val<BlueprintFieldType>(ret_field_type, chopped_field_x) << std::endl;
                                            std::cout << unmarshal_field_val<BlueprintFieldType>(ret_field_type, chopped_field_y) << std::endl;

                                        }
                                    } else {
                                        std::cout << get_var_value(frame.scalars[ret_val]).data << std::endl;
                                    }
                                }
                            }
                            if (curr_branch.size() <= 1) {
                                call_stack.pop();
                                memory.pop_frame();
                            }
                            return nullptr;
                        }
                        if (curr_branch.size() == 0 || !curr_branch.back().first ||
                            // call inside branch
                            curr_branch.back().second < call_stack.size()) {
                            auto extracted_frame = std::move(call_stack.top());
                            call_stack.pop();
                            memory.pop_frame();
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
                                    if (gen_mode.has_assignments()) {
                                        ptr_type ret_ptr = resolve_number<ptr_type>(extracted_frame, ret_val);
                                        size_type size = layout_resolver->get_type_size(ret_type);
                                        ptr_type allocated_copy = memory.stack_alloca(size);
                                        // TODO(maksenov): check if overwriting is possible here
                                        //                 (looks like it is not)
                                        memory.memcpy(allocated_copy, ret_ptr, size);
                                        upper_frame_variables[extracted_frame.caller] =
                                            put_value_into_internal_storage(allocated_copy);
                                    } else {
                                        upper_frame_variables[extracted_frame.caller] = put_value_into_internal_storage(0);
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

            template<typename InputType>
            var put_constant_into_assignment(InputType input) {
                return detail::put_constant<InputType, BlueprintFieldType, var>(input, assignments[currProverIdx]);
            }

            template<typename InputType>
            var put_value_into_internal_storage(InputType input) {
                return detail::put_internal_value<InputType, BlueprintFieldType, var>(input, internal_storage);
            }

            typename BlueprintFieldType::value_type get_var_value(const var &input_var) {
                return detail::var_value<BlueprintFieldType, var>(input_var, assignments[currProverIdx], internal_storage, gen_mode.has_assignments());
            }

        public:
            bool parse_ir_file(const char *ir_file) {
                llvm::SMDiagnostic diagnostic;
                module = llvm::parseIRFile(ir_file, diagnostic, context);
                if (module == nullptr) {
                    diagnostic.print("assigner", llvm::errs());
                    return false;
                }
                layout_resolver = std::make_unique<TypeLayoutResolver>(module->getDataLayout());
                auto entry_point_it = module->end();
                for (auto function_it = module->begin(); function_it != module->end(); ++function_it) {
                    if (function_it->hasFnAttribute(llvm::Attribute::Circuit)) {
                        if (entry_point_it != module->end()) {
                            std::cerr << "More then one functions with [[circuit]] attribute in the module"
                                      << std::endl;
                            return false;
                        }
                        entry_point_it = function_it;
                    }
                }
                if (entry_point_it == module->end()) {
                    std::cerr << "Entry point is not found" << std::endl;
                    return false;
                }
                circuit_function = &*entry_point_it;
                return true;
            }

            bool dump_public_input(const boost::json::array &public_input, const std::string &output_file) {
                stack_frame<var> frame;
                std::nullptr_t empty_assignmnt;
                auto input_reader = InputReader<BlueprintFieldType, var, std::nullptr_t>(
                    frame, memory, empty_assignmnt, *layout_resolver, internal_storage);
                auto empty_private_input = boost::json::array();
                if (!input_reader.fill_public_input(*circuit_function, public_input, empty_private_input, log)) {
                    std::cerr << "Public input does not match the circuit signature";
                    const std::string &error = input_reader.get_error();
                    if (!error.empty()) {
                        std::cout << ": " << error;
                    }
                    std::cout << std::endl;
                    return false;
                }
                input_reader.dump_public_input(output_file);
                return true;
            }

            bool evaluate(
                const boost::json::array &public_input,
                const boost::json::array &private_input
            ) {

                stack_frame<var> base_frame;
                auto &variables = base_frame.scalars;
                base_frame.caller = nullptr;

                auto input_reader = InputReader<BlueprintFieldType, var, assignment_proxy<ArithmetizationType>>(
                    base_frame, memory, assignments[currProverIdx], *layout_resolver, internal_storage, gen_mode.has_assignments());
                if (!input_reader.fill_public_input(*circuit_function, public_input, private_input, log)) {
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
                for (const llvm::Function &function : *module) {
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
                                auto label_type = llvm::Type::getInt8PtrTy(module->getContext());
                                unsigned label_type_size = layout_resolver->get_type_size(label_type);
                                ptr_type ptr = memory.stack_alloca(label_type_size);

                                // Store the pointer to BasicBlock to memory
                                // TODO(maksenov): avoid C++ pointers in assignment table
                                memory.store(ptr, label_type_size, put_value_into_internal_storage((const uintptr_t)succ));

                                labels[succ] = put_value_into_internal_storage(ptr);
                            }
                        }
                    }
                }

                // Initialize undef and zero vars once
                undef_var = put_constant_into_assignment(typename BlueprintFieldType::value_type());
                zero_var = put_constant_into_assignment(typename BlueprintFieldType::value_type(0));

                const llvm::Instruction *next_inst = &circuit_function->begin()->front();
                while (true) {
                    next_inst = handle_instruction(next_inst);
                    if (finished) {
                        if (gen_mode.has_size_estimation()) {
                            std::cout << "\nallocated_rows: " <<  assignments[currProverIdx].allocated_rows() << "\n";
                            statistics.print();
                        }
                        return true;
                    }
                    if (next_inst == nullptr) {
                        return false;
                    }
                }
            }

            /**
             * @brief Get return value of circuit function. May be empty, if evaluation ended with error
             * or wasn't performed at all. Also empty, if circuit function returns `void`.
             *
             * We return here `BlueprintFieldType::integral_type`-s, so non-native field values
             * can be unmarshalled before return.
             */
            std::vector<typename BlueprintFieldType::integral_type> get_return_value() {
                return return_value;
            }

        private:
            llvm::LLVMContext context;
            const llvm::BasicBlock *predecessor = nullptr;
            std::unique_ptr<llvm::Module> module;
            llvm::Function *circuit_function;
            std::stack<stack_frame<var>> call_stack;
            program_memory<var> memory;
            std::unordered_map<const llvm::Value *, var> globals;
            std::unordered_map<const llvm::BasicBlock *, var> labels;
            bool finished = false;
            std::unique_ptr<TypeLayoutResolver> layout_resolver;
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
            bool validity_check;
            generation_mode gen_mode;
            std::vector<branch_desc> curr_branch;
            component_calls statistics;
            /***
             * extention of assignment table for keep internal values which not presented in components
             * identified as constant column with special internal_storage_index = std::numeric_limits<std::size_t>::max()
            ***/
            column_type<BlueprintFieldType> internal_storage;
            std::vector<typename BlueprintFieldType::integral_type> return_value;
        };

    }     // namespace blueprint
}    // namespace nil

#endif    // ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_ASSIGNER_HPP_
