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

#ifndef CRYPTO3_ASSIGNER_HANDLE_COMPONENT_HPP
#define CRYPTO3_ASSIGNER_HANDLE_COMPONENT_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/component.hpp>
#include <nil/blueprint/basic_non_native_policy.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/addition.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/addition.hpp>
#include <nil/blueprint/components/algebra/curves/pasta/plonk/unified_addition.hpp>
#include <nil/blueprint/components/algebra/curves/edwards/plonk/non_native/complete_addition.hpp>
#include <nil/blueprint/components/algebra/curves/pasta/plonk/variable_base_scalar_mul.hpp>
#include <nil/blueprint/components/algebra/curves/edwards/plonk/non_native/variable_base_multiplication.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/division.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/multiplication.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/multiplication.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/subtraction.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/subtraction.hpp>
#include <nil/blueprint/components/hashes/sha2/plonk/sha256.hpp>
#include <nil/blueprint/components/hashes/sha2/plonk/sha512.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/reduction.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/bit_decomposition.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/bit_composition.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/bit_shift_constant.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/division_remainder.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/equality_flag.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/logic_ops.hpp>
#include <nil/blueprint/components/systems/snark/plonk/placeholder/fri_array_swap.hpp>
#include <nil/blueprint/components/systems/snark/plonk/placeholder/fri_cosets.hpp>
#include <nil/blueprint/components/systems/snark/plonk/placeholder/fri_lin_inter.hpp>
#include <nil/blueprint/components/systems/snark/plonk/placeholder/gate_argument_verifier.hpp>
#include <nil/blueprint/components/systems/snark/plonk/placeholder/lookup_argument_verifier.hpp>
#include <nil/blueprint/components/systems/snark/plonk/placeholder/permutation_argument_verifier.hpp>
#include <nil/blueprint/components/systems/snark/plonk/placeholder/fri_cosets.hpp>

#include <nil/blueprint/asserts.hpp>
#include <nil/blueprint/stack.hpp>
#include <nil/blueprint/policy/policy_manager.hpp>


namespace nil {
    namespace blueprint {

        // fri_cosets
        template<typename BlueprintFieldType, typename ArithmetizationParams>
        typename components::fri_cosets<
            crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, BlueprintFieldType>::result_type get_component_result(
                circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                std::uint32_t start_row,
                const typename components::fri_cosets<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, BlueprintFieldType>::input_type& instance_input,
                std::size_t res_length,
                typename BlueprintFieldType::value_type omega) {

            using component_type = components::fri_cosets<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, BlueprintFieldType>;

            const auto p = detail::PolicyManager::get_parameters(detail::ManifestReader<component_type, ArithmetizationParams>::get_witness(0, res_length));

            component_type component_instance(p.witness, detail::ManifestReader<component_type, ArithmetizationParams>::get_constants(),
                                              detail::ManifestReader<component_type, ArithmetizationParams>::get_public_inputs(), res_length, omega);

            if constexpr( use_lookups<component_type>() ){
                auto lookup_tables = component_instance.component_lookup_tables();
                for(auto &[k,v]:lookup_tables){
                    bp.reserve_table(k);
                }
            };

            components::generate_circuit(component_instance, bp, assignment, instance_input, start_row);

            return components::generate_assignments(component_instance, assignment, instance_input, start_row);
        }

        // variable_base_multiplication
        template<typename BlueprintFieldType, typename ArithmetizationParams,
                 typename ArithmetizationType, typename CurveType, typename Ed25519Type>
        typename components::variable_base_multiplication<
                ArithmetizationType, CurveType, Ed25519Type, basic_non_native_policy<BlueprintFieldType>>::result_type get_component_result(
                circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                std::uint32_t start_row,
                const typename components::variable_base_multiplication<
                    ArithmetizationType, CurveType, Ed25519Type, basic_non_native_policy<BlueprintFieldType>>::input_type& instance_input) {

            using component_type = components::variable_base_multiplication<
                ArithmetizationType, CurveType, Ed25519Type, basic_non_native_policy<BlueprintFieldType>>;

            const auto p = detail::PolicyManager::get_parameters(detail::ManifestReader<component_type, ArithmetizationParams>::get_witness(0, 253));

            component_type component_instance(p.witness, detail::ManifestReader<component_type, ArithmetizationParams>::get_constants(),
                                              detail::ManifestReader<component_type, ArithmetizationParams>::get_public_inputs(), 253, nil::blueprint::components::bit_shift_mode::RIGHT);

            if constexpr( use_lookups<component_type>() ){
                auto lookup_tables = component_instance.component_lookup_tables();
                for(auto &[k,v]:lookup_tables){
                    bp.reserve_table(k);
                }
            };

            components::generate_circuit(component_instance, bp, assignment, instance_input, start_row);

            return components::generate_assignments(component_instance, assignment, instance_input, start_row);
        }

        // logic_and
        template<typename BlueprintFieldType, typename ArithmetizationParams>
        typename components::logic_and<
            crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>::result_type get_component_result(
            circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
            assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                &assignment,
            std::uint32_t start_row,
            const typename components::logic_and<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>::input_type& instance_input) {

            using component_type = components::logic_and<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>;

            const auto p = detail::PolicyManager::get_parameters(detail::ManifestReader<component_type, ArithmetizationParams>::get_witness(0));

            component_type component_instance(p.witness);

            if constexpr( use_lookups<component_type>() ){
                auto lookup_tables = component_instance.component_lookup_tables();
                for(auto &[k,v]:lookup_tables){
                    bp.reserve_table(k);
                }
            };

            components::generate_circuit(component_instance, bp, assignment, instance_input, start_row);

            return components::generate_assignments(component_instance, assignment, instance_input, start_row);
        }

        // bit_compositon
        template<typename BlueprintFieldType, typename ArithmetizationParams>
        typename nil::blueprint::components::bit_composition<
            crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>::result_type get_component_result(
            circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
            assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                &assignment,
            std::uint32_t start_row,
            const typename nil::blueprint::components::bit_composition<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>::input_type& instance_input,
            std::size_t BitsAmount,
            bool check_input,
            nil::blueprint::components::bit_composition_mode mode) {

            using component_type = nil::blueprint::components::bit_composition<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>;
            const auto p = detail::PolicyManager::get_parameters(detail::ManifestReader<component_type, ArithmetizationParams>::get_witness(0, BitsAmount, true));

            component_type component_instance(p.witness, detail::ManifestReader<component_type, ArithmetizationParams>::get_constants(),
                                             detail::ManifestReader<component_type, ArithmetizationParams>::get_public_inputs(), BitsAmount, true, mode);

            if constexpr( use_lookups<component_type>() ){
                auto lookup_tables = component_instance.component_lookup_tables();
                for(auto &[k,v]:lookup_tables){
                    bp.reserve_table(k);
                }
            };

            components::generate_circuit(component_instance, bp, assignment, instance_input, start_row);

            return components::generate_assignments(component_instance, assignment, instance_input, start_row);
        }

        // bit_decompositon
        template<typename BlueprintFieldType, typename ArithmetizationParams>
        typename nil::blueprint::components::bit_decomposition<
            crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>::result_type get_component_result(
                circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                std::uint32_t start_row,
                const typename nil::blueprint::components::bit_decomposition<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>::input_type& instance_input,
                std::size_t BitsAmount,
                nil::blueprint::components::bit_composition_mode mode) {

            using component_type = nil::blueprint::components::bit_decomposition<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>;
            const auto p = detail::PolicyManager::get_parameters(detail::ManifestReader<component_type, ArithmetizationParams>::get_witness(0, BitsAmount));

            component_type component_instance(p.witness, detail::ManifestReader<component_type, ArithmetizationParams>::get_constants(),
                                              detail::ManifestReader<component_type, ArithmetizationParams>::get_public_inputs(), BitsAmount, mode);

            if constexpr( use_lookups<component_type>() ){
                auto lookup_tables = component_instance.component_lookup_tables();
                for(auto &[k,v]:lookup_tables){
                    bp.reserve_table(k);
                }
            };

            components::generate_circuit(component_instance, bp, assignment, instance_input, start_row);

            return components::generate_assignments(component_instance, assignment, instance_input, start_row);
        }

        template<typename BlueprintFieldType, typename ArithmetizationParams, typename ComponentType, typename... Args>
        typename ComponentType::result_type get_component_result(
                circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                &assignment,
                std::uint32_t start_row,
                const typename ComponentType::input_type& instance_input,
                Args... args) {

            const auto p = detail::PolicyManager::get_parameters(detail::ManifestReader<ComponentType, ArithmetizationParams>::get_witness(0, args...));

            ComponentType component_instance(p.witness, detail::ManifestReader<ComponentType, ArithmetizationParams>::get_constants(),
                                              detail::ManifestReader<ComponentType, ArithmetizationParams>::get_public_inputs(), args...);

            if constexpr( use_lookups<ComponentType>() ){
                auto lookup_tables = component_instance.component_lookup_tables();
                for(auto &[k,v]:lookup_tables){
                    bp.reserve_table(k);
                }
            };

            components::generate_circuit(component_instance, bp, assignment, instance_input, start_row);

            return components::generate_assignments(component_instance, assignment, instance_input, start_row);
        }

        template<typename BlueprintFieldType, typename ArithmetizationParams, typename ComponentType>
        void handle_component_result(
                assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                &assignment,
                const llvm::Instruction *inst,
                stack_frame<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &frame,
                bool next_prover,
                const typename ComponentType::result_type& component_result) {

            using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

            std::vector<var> output = component_result.all_vars();

            if (output.size() == 1) {
                frame.scalars[inst] = next_prover ? save_shared_var(assignment, output[0]) : output[0];
            } else {
                frame.vectors[inst] = next_prover ? save_shared_var(assignment, output) : output;
            }
        }

        template<typename BlueprintFieldType, typename ArithmetizationParams>
        void handle_result(
                assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                &assignment,
                const llvm::Instruction *inst,
                stack_frame<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &frame,
                bool next_prover,
                const std::vector<typename crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>>& result) {

            if (result.size() == 1) {
                frame.scalars[inst] = next_prover ? save_shared_var(assignment, result[0]) : result[0];
            } else {
                frame.vectors[inst] = next_prover ? save_shared_var(assignment, result) : result;
            }
        }

        template<typename BlueprintFieldType, typename ArithmetizationParams, typename ComponentType, typename... Args>
        void handle_component(
                circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                &assignment,
                std::uint32_t start_row,
                const typename ComponentType::input_type& instance_input,
                const llvm::Instruction *inst,
                stack_frame<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &frame,
                bool next_prover,
                Args... args) {

            const auto component_result = get_component_result<BlueprintFieldType, ArithmetizationParams, ComponentType>
                    (bp, assignment, start_row, instance_input, args...);

            handle_component_result<BlueprintFieldType, ArithmetizationParams, ComponentType>(assignment, inst, frame, next_prover, component_result);
        }

    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_ASSIGNER_HANDLE_COMPONENT_HPP
