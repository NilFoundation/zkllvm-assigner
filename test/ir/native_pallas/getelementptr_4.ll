target datalayout = "e-m:e-p:64:8-a:8-i16:8-i32:8-i64:8-v768:8-v1152:8-v1536:8"
target triple = "assigner"

%struct.RT = type { i8, [10 x [20 x i32]], i8 }  ; sizeof(%struct.RT) = 802
%struct.ST = type { i32, __zkllvm_field_pallas_scalar, %struct.RT }  ; sizeof(%struct.ST) = 838

define i64 @main() #1 {
entry:
    %ptr = inttoptr i64 0 to ptr
    ;                                                       838    874    875    1275   1327
    %elemptr = getelementptr inbounds %struct.ST, ptr %ptr, i64 1, i32 2, i32 1, i64 5, i64 13
    %ret = ptrtoint ptr %elemptr to i64
    ret i64 %ret
}

attributes #1 = { circuit }
