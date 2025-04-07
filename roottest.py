
import math
import numpy as np
from fv_scheme import fv_scheme 
# 기본 세팅
# q = 2^50 : 1125899906842624
# t = 17^3 : 4913

# q' = p^e 꼴로 바꿀 때
# 바뀐 ciphertext modulus -> 2^90 : 1152921504606846976
# 바뀐 plaintext modulus -> 17^6 : 24137569

# lifting 함수 설정 (p = 17 일 때)

n = pow(2, 7)
# 평문, 암호문 모듈러스
q = pow(4, 10)
t = pow(2, 15)
delta = math.floor(q / t)

print("q = ", q, "t = ", t, "delta = ", delta)


fv = fv_scheme.FV_SH(degree=n, pt_modulus=t, ct_modulus=q)
s = fv.secret_key
# 공개 키
pk = fv.generate_public_key()
rlk = fv.generate_relinearisation_version1_key(T=2)
# NTT 계산

def merge_polynomial_by_T(poly_list, T):
    """
    poly_list: split_polynomial_by_T 함수의 출력으로 얻은 리스트.
               예) poly_list = [
                      [d0_0, d0_1, ..., d0_{n-1}],   # 0번째 자리 (낮은 자리)
                      [d1_0, d1_1, ..., d1_{n-1}],   # 1번째 자리
                      ...
                      [d_L_0, d_L_1, ..., d_L_{n-1}]
                   ]
    T: 기저 (base)
    
    각 다항식의 자리수를 합산하여 원래의 다항식(계수 리스트)을 복원한다.
    반환:
         reconstructed: [c0, c1, ..., c_{n-1}], 여기서
         c_j = sum_{i=0}^{L} ( poly_list[i][j] * T^i ).
    """
    if not poly_list:
        return []
    
    n = len(poly_list[0])  # 다항식의 계수 개수
    L = len(poly_list)     # 분해된 자리수의 개수 (즉, L = floor(log_T(q)) + 1)
    
    reconstructed = []
    for j in range(n):
        coeff = 0
        for i in range(L):
            coeff += poly_list[i][j] * (T ** i)
        reconstructed.append(coeff)
    return reconstructed


if __name__ == "__main__":
    test = [10, 20, 30, 40, 50]
    t = fv.split_polynomial_by_T(test, 7)
    print("split_polynomial_by_T: ", t)
    res = merge_polynomial_by_T(t, 7)
    print("merge_polynomial_by_T: ", res)

   
    
   