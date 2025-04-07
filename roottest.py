
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
q = pow(2, 90)
t = pow(2, 15)
delta = math.floor(q / t)

print("q = ", q, "t = ", t, "delta = ", delta)


fv = fv_scheme.FV_SH(degree=n, pt_modulus=t, ct_modulus=q)
s = fv.secret_key
# 공개 키
pk = fv.generate_public_key()
rlk = fv.generate_relinearisation_version1_key(T=2)
# NTT 계산

def get_w(n, mod):
    """
    w^n = -1, w^(2n) = 1을 만족하는 w를 찾는 함수
    :param n: n 값
    :param mod: 모듈러 값
    :return: 조건을 만족하는 w
    """
    # 1부터 mod - 1 사이의 정수 중 조건을 만족하는 w를 찾음
    for w in range(1, mod):
        if pow(w, n, mod) == mod - 1:
            return w
    
    raise ValueError("조건을 만족하는 w를 찾을 수 없습니다.")
    
def get_roots(n, mod):
    
    roots = []
    # 다항식을 계산
    for w in range(mod):
        if pow(w, n, mod) == mod - 1:
            # 중복된 근이 있는지 검사 후 없으면 추가
            if w % mod not in roots:
                w = w % mod
                roots.append(w)
    
    # 계수에 mod 17 하여 출력
    return [roots[i] % mod for i in range(len(roots))]
    
if __name__ == "__main__":
    for i in range(2, 25):
        n = pow(2, i)
        p = [3, 2]
        for j in range(2):
            for k in range(1, 15 + 2 * j):
                mod = pow(p[j], k)
                try:
                    w = get_w(n, mod)
                    print("n = ", n, "mod = ", p[j], "w = ", w)
                except ValueError as e:
                    print(e)
                    continue

   
   
    
   