target datalayout = "e-m:e-p:64:8-a:8-i16:8-i32:8-i64:8-v768:8-v1152:8-v1536:8"
target triple = "assigner"

define i64 @main() #1 {
entry:
    %ptr = inttoptr i64 0 to ptr
    %elemptr = getelementptr {__zkllvm_field_pallas_base, i8}, ptr %ptr, i64 0, i32 1
    %ret = ptrtoint ptr %elemptr to i64
    ret i64 %ret
}

attributes #1 = { circuit }
