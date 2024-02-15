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

        struct component_statistics {
            std::size_t component_counter;
            std::size_t component_rows;
            std::size_t component_gates;
            std::size_t component_witness;
            std::size_t component_finished;

            component_statistics (std::size_t component_r, std::size_t component_g, std::size_t component_w, std::size_t component_f) {
                component_counter = 1;
                component_rows = component_r;
                component_gates = component_g;
                component_witness = component_w;
                component_finished = component_f;
            }

            component_statistics () {
            }

            void component_call() {
                component_counter++;
            }
        };

        struct component_calls {

            std::map<std::string, component_statistics> components;

            std::set<std::string> unfinished_components = {
                "non_native fp12 multiplication",
                "is_in_g1",
                "is_in_g2",
                "native_bls12_381_pairing",
                "hash to curve",
                "comparison",
            };

            void add_record(std::string name, std::size_t rows, std::size_t gates, std::size_t witness) {

                bool component_finished;

                if (unfinished_components.find(name) != unfinished_components.end()) {
                    component_finished = false;
                } else {
                    component_finished = true;
                }

                if (components.find(name) == components.end()) {
                    components[name] = component_statistics(rows, gates, witness, component_finished);
                } else {
                    components[name].component_call();
                }
            }

            void print() {
                std::cout << "================\n";
                std::cout << "statistics:\n";

                std::size_t circuit_rows_amount = 0;

                for (const auto& [name, component] : components) {
                    circuit_rows_amount += (component.component_rows * component.component_counter);
                }

                std::cout << "total rows amount estimation: " << circuit_rows_amount << "\n";
                std::cout << "________________\n";

                for (const auto& [name, component] : components) {
                    std::cout << "component name: " << name << "\n";
                    std::cout << "Component was used " << component.component_counter << " times\n";
                    if (!component.component_finished) {
                        std::cout << "WARNING: component contains experimental features. Parameters are subject to change, do not fully trust to numbers below.\n";
                    }
                    std::cout << "gates amount: " << component.component_gates << "\n";
                    std::cout << "witness size: " << component.component_witness << "\n";
                    std::cout << "rows amount:  " << component.component_rows;
                    std::size_t total_rows = component.component_rows * component.component_counter;
                    std::cout << " (" << total_rows << " in total)\n";
                    std::cout << "________________\n";
                }
                std::cout << std::endl;

            }
        };
    }     // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_ASSIGNER_STATISTICS_HPP
