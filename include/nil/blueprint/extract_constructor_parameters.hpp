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

#ifndef ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_EXTRACT_CONSTRUCTOR_PARAMETERS_HPP_
#define ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_EXTRACT_CONSTRUCTOR_PARAMETERS_HPP_

#include <nil/blueprint/memory/load.hpp>

namespace nil {
    namespace blueprint {
        namespace detail {

            template <typename BlueprintFieldType>
            typename BlueprintFieldType::value_type extract_constant_field_value(llvm::Value *input_value){
                column_type<BlueprintFieldType> marshalled_value = marshal_field_val<BlueprintFieldType>(input_value);
                ASSERT(marshalled_value.size() == 1);
                return marshalled_value[0];
            }

            template <typename BlueprintFieldType>
            std::size_t extract_constant_size_t_value(llvm::Value *input_value){
                return std::size_t(
                    typename BlueprintFieldType::integral_type(
                            extract_constant_field_value<BlueprintFieldType>(input_value).data
                        )
                    );
            }

            template <typename BlueprintFieldType>
            bool extract_constant_bool_value(llvm::Value *input_value){
                return bool(
                    typename BlueprintFieldType::integral_type(
                            extract_constant_field_value<BlueprintFieldType>(input_value).data
                        )
                    );
            }

            template<typename BlueprintFieldType>
            std::vector<std::size_t> extract_constant_vector(llvm::Value *parameters_vector_value) {
                std::vector<std::size_t> res = {};
                ASSERT(parameters_vector_value->getType()->isPointerTy());
                ASSERT(llvm::isa<llvm::GlobalValue>(parameters_vector_value));
                auto gv = llvm::cast<llvm::GlobalVariable>(parameters_vector_value);
                auto struct_constant = gv->getInitializer();
                ASSERT(struct_constant->getType()->getStructNumElements() == 1);
                auto array_constant = struct_constant->getAggregateElement(0u);
                ASSERT(array_constant->getType()->isArrayTy());
                for (unsigned i = 0; i < array_constant->getType()->getArrayNumElements(); ++i) {
                    auto elem_constant = array_constant->getAggregateElement(i);
                    res.push_back(extract_constant_size_t_value<BlueprintFieldType>(elem_constant));
                }
                return res;
            }

            template<typename BlueprintFieldType, typename var>
            std::vector<var> extract_intrinsic_input_vector(llvm::Value *input_value, std::size_t input_length,
            typename std::map<const llvm::Value *, var> &variables,
                program_memory<var> &memory,
                circuit_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment_proxy<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                column_type<BlueprintFieldType> &internal_storage, component_calls &statistics,
                const common_component_parameters& param) {
                std::vector<var> res = {};
                ptr_type input_ptr = static_cast<ptr_type>(
                    typename BlueprintFieldType::integral_type(detail::var_value<BlueprintFieldType, var>(variables[input_value], assignment, internal_storage, param.gen_mode.has_assignments()).data));
                for (std::size_t i = 0; i < input_length; i++) {
                    ASSERT(memory[input_ptr].size == (BlueprintFieldType::number_bits + 7) / 8);
                    auto v = memory.load(input_ptr++);
                    v = create_load_component<BlueprintFieldType, var>(
                                v, bp, assignment, internal_storage, statistics, param);
                    res.push_back(v);
                }
                return res;
            }


        }    // namespace detail
    }    // namespace blueprint
}    // namespace nil

#endif  // ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_EXTRACT_CONSTRUCTOR_PARAMETERS_HPP_
