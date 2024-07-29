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

#ifndef ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_COMPONENT_HANDLER_INPUT_WRAPPER_HPP_
#define ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_COMPONENT_HANDLER_INPUT_WRAPPER_HPP_


namespace nil {
    namespace blueprint {

        template<typename BlueprintFieldType>
        struct component_handler_input_wrapper {
            using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
            component_calls statistics;
            std::map<var, std::size_t> comp_counter_form_var;
            std::vector<table_piece<var>> table_pieces;
            std::vector<std::pair<std::uint32_t, var>> to_be_shared;
        };


    }    // namespace blueprint
}    // namespace nil

#endif    // ZKLLVM_ASSIGNER_INCLUDE_NIL_BLUEPRINT_COMPONENT_HANDLER_INPUT_WRAPPER_HPP_
