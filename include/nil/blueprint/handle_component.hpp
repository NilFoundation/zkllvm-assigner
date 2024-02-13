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

#include <nil/blueprint/component_mockups/is_in_g1.hpp>
#include <nil/blueprint/component_mockups/is_in_g2.hpp>
#include <nil/blueprint/component_mockups/h2c.hpp>
#include <nil/blueprint/component_mockups/fp12_multiplication.hpp>
#include <nil/blueprint/component_mockups/bls12_381_pairing.hpp>
#include <nil/blueprint/component_mockups/comparison.hpp>

#include <nil/blueprint/asserts.hpp>
#include <nil/blueprint/stack.hpp>
#include <nil/blueprint/statistics.hpp>
#include <nil/blueprint/policy/policy_manager.hpp>
#include <typeinfo>


namespace nil {
    namespace blueprint {

        enum class generation_mode : uint8_t {
            NONE = 0,
            CIRCUIT = 1 << 0,
            ASSIGNMENTS = 1 << 1,
            FALSE_ASSIGNMENTS = 1 << 2,
            SIZE_ESTIMATION = 1 << 3
        };

        constexpr enum generation_mode operator |( const enum generation_mode self, const enum generation_mode val )
        {
            return (enum generation_mode)(uint8_t(self) | uint8_t(val));
        }

        constexpr enum generation_mode operator &( const enum generation_mode self, const enum generation_mode val )
        {
            return (enum generation_mode)(uint8_t(self) & uint8_t(val));
        }

        struct common_component_parameters {
            std::uint32_t start_row;
            std::uint32_t target_prover_idx;
            generation_mode gen_mode;
        };


        template<typename BlueprintFieldType, typename ArithmetizationParams, typename ComponentType>
        void handle_component_input(
            assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                &assignment,
            typename ComponentType::input_type& instance_input, generation_mode gen_mode) {

            using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

            std::vector<std::reference_wrapper<var>> input = instance_input.all_vars();
            const auto& used_rows = assignment.get_used_rows();

            for (auto& v : input) {
                bool found = (used_rows.find(v.get().rotation) != used_rows.end());
                if (!found && (v.get().type == var::column_type::witness || v.get().type == var::column_type::constant)) {
                    var new_v;
                    if (std::uint8_t(gen_mode & generation_mode::ASSIGNMENTS)) {
                        new_v = save_shared_var(assignment, v);
                    } else {
                        const auto& shared_idx = assignment.shared_column_size(0);
                        assignment.shared(0, shared_idx) = BlueprintFieldType::value_type::zero();;
                        new_v = var(1, shared_idx, false, var::column_type::public_input);
                    }
                    v.get().index = new_v.index;
                    v.get().rotation = new_v.rotation;
                    v.get().relative = new_v.relative;
                    v.get().type = new_v.type;
                }
            }
        }

        template<typename BlueprintFieldType, typename ArithmetizationParams, typename ComponentType>
        void generate_circuit(
            ComponentType& component_instance,
            circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
            assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                &assignment,
            const typename ComponentType::input_type& instance_input,
            std::uint32_t start_row) {

            if constexpr( use_lookups<ComponentType>() ){
                auto lookup_tables = component_instance.component_lookup_tables();
                for(auto &[k,v]:lookup_tables){
                    bp.reserve_table(k);
                }
            };

            components::generate_circuit(component_instance, bp, assignment, instance_input, start_row);
        }

        template<typename T> struct has_get_empty_rows_amount{
        private:
            static int detect(...);
            template<typename U> static decltype(std::declval<U>().get_empty_rows_amount()) detect(const U&);
        public:
            static constexpr bool value = std::is_same<std::size_t, decltype(detect(std::declval<T>()))>::value;
        };

        template<bool>
        struct generate_empty_assignments_if_exist {
            template<typename BlueprintFieldType, typename ArithmetizationParams, typename ComponentType>
            static typename ComponentType::result_type implementation(const ComponentType& component_instance,
                      assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                          &assignment,
                      const typename ComponentType::input_type& instance_input, std::uint32_t start_row) {
                return components::generate_assignments(component_instance, assignment, instance_input, start_row);
            }
        };

        template<>
        struct generate_empty_assignments_if_exist<true> {
            template<typename BlueprintFieldType, typename ArithmetizationParams, typename ComponentType>
            static typename ComponentType::result_type implementation(const ComponentType& component_instance,
                                                                      assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                                                                          &assignment,
                                                                      const typename ComponentType::input_type& instance_input, std::uint32_t start_row) {
                return components::generate_empty_assignments(component_instance, assignment, instance_input, start_row);
            }
        };

        template<typename BlueprintFieldType, typename ArithmetizationParams, typename ComponentType>
        typename ComponentType::result_type generate_assignments(
            const ComponentType& component_instance,
            assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                &assignment,
            const typename ComponentType::input_type& instance_input,
            std::uint32_t start_row, std::uint32_t target_prover_idx) {

            if (target_prover_idx == assignment.get_id() || target_prover_idx == std::numeric_limits<std::uint32_t>::max()) {
                return components::generate_assignments(component_instance, assignment, instance_input,
                                                        start_row);
            } else {
                return generate_empty_assignments_if_exist<has_get_empty_rows_amount<ComponentType>::value>::
                    implementation(component_instance, assignment, instance_input, start_row);
            }
        }

        template<typename BlueprintFieldType, typename ArithmetizationParams, typename ComponentType, typename... Args>
        typename ComponentType::result_type get_component_result(
                circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                &assignment,
                const common_component_parameters& param,
                typename ComponentType::input_type& instance_input,
                Args... args) {

            const auto p = detail::PolicyManager::get_parameters(detail::ManifestReader<ComponentType, ArithmetizationParams>::get_witness(0, args...));

            ComponentType component_instance(p.witness, detail::ManifestReader<ComponentType, ArithmetizationParams>::get_constants(),
                                              detail::ManifestReader<ComponentType, ArithmetizationParams>::get_public_inputs(), args...);


            BOOST_LOG_TRIVIAL(debug) << "Using component \"" << component_instance.component_name << "\"";

            if (std::uint8_t(param.gen_mode & generation_mode::SIZE_ESTIMATION)) {
                statistics.add_record(
                    component_instance.component_name,
                    component_instance.rows_amount,
                    component_instance.gates_amount,
                    component_instance.witness_amount()
                );
                return typename ComponentType::result_type(component_instance, param.start_row);
            }

            handle_component_input<BlueprintFieldType, ArithmetizationParams, ComponentType>(assignment, instance_input, param.gen_mode);

            // copy constraints before execute component
            const auto num_copy_constraints = bp.copy_constraints().size();

            // generate circuit in any case for fill selectors
            generate_circuit(component_instance, bp, assignment, instance_input, param.start_row);

            if (std::uint8_t(param.gen_mode & generation_mode::ASSIGNMENTS)) {
                return generate_assignments(component_instance, assignment, instance_input, param.start_row,
                                            param.target_prover_idx);
            } else {
                if (std::uint8_t(param.gen_mode & generation_mode::FALSE_ASSIGNMENTS)) {
                    const auto rows_amount = ComponentType::get_rows_amount(p.witness.size(), 0, args...);
                    // disable selector
                    for (std::uint32_t i = 0; i < rows_amount; i++) {
                        for (std::uint32_t j = 0; j < assignment.selectors_amount(); j++) {
                            assignment.selector(j, param.start_row + i) = BlueprintFieldType::value_type::zero();
                        }
                    }

                    // fake allocate rows
                    for (std::uint32_t i = 0; i < rows_amount; i++) {
                        assignment.witness(0, param.start_row + i) = BlueprintFieldType::value_type::zero();
                    }

                    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

                    // fill copy constraints
                    const auto &copy_constraints = bp.copy_constraints();
                    for (std::uint32_t i = num_copy_constraints; i < copy_constraints.size(); i++) {
                        if (copy_constraints[i].first.type == var::column_type::witness &&
                            copy_constraints[i].first.rotation >= param.start_row) {
                            if (copy_constraints[i].second.rotation >=
                                assignment.witness(copy_constraints[i].second.index).size()) {
                                assignment.witness(copy_constraints[i].second.index,
                                                   copy_constraints[i].second.rotation) =
                                    BlueprintFieldType::value_type::zero();
                            }
                            assignment.witness(copy_constraints[i].first.index, copy_constraints[i].first.rotation) =
                                var_value(assignment, copy_constraints[i].second);
                        } else if (copy_constraints[i].second.type == var::column_type::witness &&
                                   copy_constraints[i].second.rotation >= param.start_row) {
                            if (copy_constraints[i].first.rotation >=
                                assignment.witness(copy_constraints[i].first.index).size()) {
                                assignment.witness(copy_constraints[i].first.index,
                                                   copy_constraints[i].first.rotation) =
                                    BlueprintFieldType::value_type::zero();
                            }
                            assignment.witness(copy_constraints[i].second.index, copy_constraints[i].second.rotation) =
                                var_value(assignment, copy_constraints[i].first);
                        } else {
                            std::cout << "wrong copy constraint\n";
                        }
                    }
                }
            }
            return typename ComponentType::result_type(component_instance, param.start_row);
        }

        template<typename BlueprintFieldType, typename ArithmetizationParams, typename ComponentType>
        void handle_component_result(
                assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                &assignment,
                const llvm::Instruction *inst,
                stack_frame<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &frame,
                const typename ComponentType::result_type& component_result, generation_mode gen_mode) {

            using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

            std::vector<var> output = component_result.all_vars();

            //touch result variables
            if (std::uint8_t(gen_mode & generation_mode::ASSIGNMENTS) == 0) {
                const auto result_vars = component_result.all_vars();
                for (const auto &v : result_vars) {
                    if (v.type == var::column_type::witness) {
                        assignment.witness(v.index, v.rotation) = BlueprintFieldType::value_type::zero();
                    } else if (v.type == var::column_type::constant) {
                        assignment.constant(v.index, v.rotation) = BlueprintFieldType::value_type::zero();
                    }
                }
            }
            if (output.size() == 1) {
                frame.scalars[inst] = output[0];
            } else {
                frame.vectors[inst] = output;
            }
        }

        template<typename BlueprintFieldType, typename ArithmetizationParams>
        void handle_result(
                assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                &assignment,
                const llvm::Instruction *inst,
                stack_frame<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &frame,
                const std::vector<typename crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>>& result,
                generation_mode gen_mode) {

            using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

            //touch result variables
            if (std::uint8_t(gen_mode & generation_mode::ASSIGNMENTS) == 0) {
                for (const auto &v : result) {
                    if (v.type == var::column_type::witness) {
                        assignment.witness(v.index, v.rotation) = BlueprintFieldType::value_type::zero();
                    } else if (v.type == var::column_type::constant) {
                        assignment.constant(v.index, v.rotation) = BlueprintFieldType::value_type::zero();
                    }
                }
            }
            if (result.size() == 1) {
                frame.scalars[inst] = result[0];
            } else {
                frame.vectors[inst] = result;
            }
        }

        template<typename BlueprintFieldType, typename ArithmetizationParams, typename ComponentType, typename... Args>
        void handle_component(
                circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                &assignment,
                const common_component_parameters& param,
                typename ComponentType::input_type& instance_input,
                const llvm::Instruction *inst,
                stack_frame<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &frame,
                Args... args) {

            const auto component_result = get_component_result<BlueprintFieldType, ArithmetizationParams, ComponentType>
                    (bp, assignment, param, instance_input, args...);

            handle_component_result<BlueprintFieldType, ArithmetizationParams, ComponentType>(assignment, inst, frame, component_result, param.gen_mode);
        }

    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_ASSIGNER_HANDLE_COMPONENT_HPP
