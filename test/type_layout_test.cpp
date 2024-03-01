#define BOOST_TEST_MODULE memory_type_layout_test

#include <boost/test/unit_test.hpp>

#include <nil/blueprint/mem/type_layout.hpp>

#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/ZK/ZKEnums.h"

#include <vector>

using namespace nil::blueprint::mem;

BOOST_AUTO_TEST_SUITE(memory_type_layout_suite)

BOOST_AUTO_TEST_CASE(memory_type_layout_sizes) {
    llvm::LLVMContext ctx;
    std::string Error;
    // This data layout string is copied from assigner target description.
    // Probably we should retreive it dynamically from assigner target here.
    llvm::DataLayout dl("e-m:e-p:64:8-a:8-i16:8-i32:8-i64:8-v768:8-v1152:8-v1536:8");
    TypeLayoutResolver resolver(dl);

    // Primitive types
    BOOST_TEST(resolver.get_type_size(llvm::Type::getInt1Ty(ctx)) == 1);
    BOOST_TEST(resolver.get_type_size(llvm::Type::getInt8Ty(ctx)) == 1);
    BOOST_TEST(resolver.get_type_size(llvm::Type::getInt16Ty(ctx)) == 2);
    BOOST_TEST(resolver.get_type_size(llvm::Type::getInt32Ty(ctx)) == 4);
    BOOST_TEST(resolver.get_type_size(llvm::Type::getInt64Ty(ctx)) == 8);

    BOOST_TEST(resolver.get_type_size(llvm::PointerType::getUnqual(ctx)) == 8);

    BOOST_TEST(resolver.get_type_size(llvm::GaloisFieldType::get(ctx, llvm::GALOIS_FIELD_PALLAS_BASE)) == 32);
    BOOST_TEST(resolver.get_type_size(llvm::GaloisFieldType::get(ctx, llvm::GALOIS_FIELD_PALLAS_SCALAR)) == 32);
    BOOST_TEST(resolver.get_type_size(llvm::GaloisFieldType::get(ctx, llvm::GALOIS_FIELD_VESTA_BASE)) == 32);
    BOOST_TEST(resolver.get_type_size(llvm::GaloisFieldType::get(ctx, llvm::GALOIS_FIELD_VESTA_SCALAR)) == 32);
    BOOST_TEST(resolver.get_type_size(llvm::GaloisFieldType::get(ctx, llvm::GALOIS_FIELD_BLS12381_BASE)) == 48);
    BOOST_TEST(resolver.get_type_size(llvm::GaloisFieldType::get(ctx, llvm::GALOIS_FIELD_BLS12381_SCALAR)) == 32);
    BOOST_TEST(resolver.get_type_size(llvm::GaloisFieldType::get(ctx, llvm::GALOIS_FIELD_CURVE25519_BASE)) == 32);
    BOOST_TEST(resolver.get_type_size(llvm::GaloisFieldType::get(ctx, llvm::GALOIS_FIELD_CURVE25519_SCALAR)) == 32);

    // Aggregate types
    BOOST_TEST(resolver.get_type_size(llvm::ArrayType::get(llvm::Type::getInt32Ty(ctx), 4)) == 16);

    std::vector<llvm::Type*> elems = {};
    BOOST_TEST(resolver.get_type_size(llvm::StructType::get(ctx, elems, true)) == 0);
    BOOST_TEST(resolver.get_type_size(llvm::StructType::get(ctx, elems, false)) == 0);

    elems = {
        llvm::Type::getInt8Ty(ctx),
    };
    BOOST_TEST(resolver.get_type_size(llvm::StructType::get(ctx, elems, true)) == 1);
    BOOST_TEST(resolver.get_type_size(llvm::StructType::get(ctx, elems, false)) == 1);

    elems = {
        llvm::ArrayType::get(llvm::Type::getInt32Ty(ctx), 4),
    };
    BOOST_TEST(resolver.get_type_size(llvm::StructType::get(ctx, elems, true)) == 16);
    BOOST_TEST(resolver.get_type_size(llvm::StructType::get(ctx, elems, false)) == 16);

    elems = {
        llvm::Type::getInt8Ty(ctx),
        llvm::ArrayType::get(llvm::Type::getInt32Ty(ctx), 4),
    };
    BOOST_TEST(resolver.get_type_size(llvm::StructType::get(ctx, elems, true)) == 17);
    BOOST_TEST(resolver.get_type_size(llvm::StructType::get(ctx, elems, false)) == 17);

    elems = {
        llvm::Type::getInt8Ty(ctx),
        llvm::GaloisFieldType::get(ctx, llvm::GALOIS_FIELD_PALLAS_BASE),
        llvm::ArrayType::get(llvm::Type::getInt32Ty(ctx), 4),
    };
    BOOST_TEST(resolver.get_type_size(llvm::StructType::get(ctx, elems, true)) == 49);
    BOOST_TEST(resolver.get_type_size(llvm::StructType::get(ctx, elems, false)) == 49);
}

BOOST_AUTO_TEST_SUITE_END()
