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

#ifndef CRYPTO3_ASSIGNER_STATISTICS_HPP
#define CRYPTO3_ASSIGNER_STATISTICS_HPP

namespace nil {
    namespace blueprint {

        struct component_calls {

            std::map<std::string, int> component_counter;
            std::map<std::string, int> component_rows;
            std::map<std::string, int> component_gates;
            std::map<std::string, int> component_witness;
            std::map<std::string, bool> component_finished;

            std::set<std::string> unfinished_components = {
                "non_native fp12 multiplication",
                "is_in_g1",
                "is_in_g2",
                "native_bls12_381_pairing",
                "hash to curve",
                "comparison",
            };

            void add_record(std::string name, std::size_t rows, std::size_t gates, std::size_t witness) {
                component_counter[name] += 1;
                component_rows[name] = rows;
                component_gates[name] = gates;
                component_witness[name] = witness;
                if (unfinished_components.find(name) != unfinished_components.end()) {
                    component_finished[name] = false;
                } else {
                    component_finished[name] = true;
                }
            }

            void print() {
                std::cout << "\n=====================================================================================\n";
                std::cout << "statistics:\n";

                std::size_t circuit_rows_amount = 0;

                for (const auto& pair : component_rows) {
                    circuit_rows_amount += (pair.second * component_counter[pair.first]);
                }

                std::cout << "total rows amount estimation: " << circuit_rows_amount << "\n";
                std::cout << "_______________________________________________________________________________________\n";

                for (const auto& pair : component_counter) {
                    std::cout << "component name: " << pair.first << "\n";
                    std::cout << "Component was used " << pair.second << " times\n";
                    if (!component_finished[pair.first]) {
                        std::cout << "WARNING: component contains experimental features. Parameters are subject to change, do not fully trust to numbers below.\n";
                    }
                    std::cout << "gates amount: " << component_gates[pair.first] << "\n";
                    std::cout << "witness size: " << component_witness[pair.first] << "\n";
                    std::cout << "rows amount:  " << component_rows[pair.first];
                    std::size_t total_rows = component_rows[pair.first] * pair.second;
                    std::cout << " (" << total_rows << " in total)\n";
                    std::cout << "_______________________________________________________________________________________\n";
                }
                std::cout << std::endl;

            }
        };

        nil::blueprint::component_calls statistics;

    }     // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_ASSIGNER_STATISTICS_HPP
