import pandas as pd
import numpy as np
from fv_scheme import fv_scheme 


# n = pow(2, 0)
#  # ring q 생성
# p = 2
# e = 20
# q = pow(p, e)

# T = 2

# fv_mod_q = fv_scheme.FV_SH(degree=n, pt_modulus=t, ct_modulus=q)

# def create_ring(q, t):

#     fv = fv_scheme.FV_SH(degree=n, pt_modulus=t, ct_modulus=q)
#     fv.public_key = fv_mod_q.public_key
#     fv.secret_key = fv_mod_q.secret_key
#     fv.relinearisation_key = fv.generate_relinearisation_version1_key(T=T)
#     return fv

# def digit_extraction(ciphertext1, e, p):
    
#     row = e + 1
#     col = e + 1
#     # 2차원 리스트 초기화
#     w = [[0] * col for _ in range(row)]
#     ciphertext1 = [ct.tolist() if isinstance(ct, np.ndarray) else ct for ct in ciphertext1]
#     w[0][0] = ciphertext1
#     rings = []
#     for j in range(e + 1):
#         ring = create_ring(q=q, t=pow(p, e - j))
#         rings.append(ring)
        
#     for k in range(e):
#         y = ciphertext1
#         for j in range(k + 1):
#             w[j][k + 1] = rings[j].multiply_use_rlk_ver1(ct1=w[j][k], ct2=w[j][k], T=T, rlk=rings[j].relinearisation_key)
#             # 트릭!! 테스트를 위해 복호화 후 다시 암호화
#             dec_res = rings[j].decrypt(w[j][k + 1])
#             w[j][k + 1] = rings[j].encrypt(pk=rings[j].public_key, m=dec_res)
#             # w 계수에 음수 처리
#             inverse_w1 = [coef * -1 for coef in w[j][k + 1][0]]
#             inverse_w2 = [coef * -1 for coef in w[j][k + 1][1]]
#             inverse_w = [inverse_w1, inverse_w2]
#             # y = (y - w[j][k + 1]) / p
#             y = rings[j].add(y, inverse_w)
#         w[k + 1][k + 1] = y
#     return w

# def digit_select(ciphertext1, p, e):
   
#     w = digit_extraction(ciphertext1, e, p)
#     rings = []
#     for j in range(e + 1):
#         ring = create_ring(q=q, t=pow(p, e - j))
#         rings.append(ring)
    
#     w_dec = []
#     for i in range(e + 1):
#         row = []
#         for j in range(e + 1):
#             if w[i][j] == 0:
#                 w[i][j] = [[0], [0]]
#             row.append(rings[i].decrypt(w[i][j]))
#             # row.append(w[i][j])
#         w_dec.append(row)
#     df  = pd.DataFrame(w_dec)
#     df.to_csv('digit_extraction.csv', index=False, header=False)
            
#     ring = create_ring(q=q, t=pow(p, e))
    
#     return w[r - 1][r]

def digit_extraction(z, mod):
    
    e = len(bin(mod)) - 3  # t의 이진수 길이에서 '0b'를 제외한 길이
    row = e + 1
    col = e + 1
    # 2차원 리스트 초기화
    w = [[0] * col for _ in range(row)]
    
    w[0][0] = z
  
    for k in range(e):
        y = z
        for j in range(k + 1):
            w[j][k + 1] = w[j][k] * w[j][k] % mod
            y = (y - w[j][k + 1]) // 2
        w[k + 1][k + 1] = y
    return w

def digit_select(z, mod):
   
    w = digit_extraction(z, mod)
    for i in range(len(w)):
        w[i][-1] = (w[i][-1])
    df  = pd.DataFrame(w)
    df.to_csv('digit_extraction.csv', index=False, header=False)
    
    # return w[r - 1][r]

# 예제 사용s
if __name__ == "__main__":
    z = -3
    mask = 179
    
    mod = 2**10
    
    z_mul_mask = z * mask % mod
    inv_mask = pow(mask, -1, mod)
    minus_inv_mask = -(inv_mask - mod // 2)
    print("z * mask % mod:", z_mul_mask)
    print("Inverse of mask % mod:", inv_mask)
    print("(-inv_mask) % mod:", minus_inv_mask)
    recover = - ((785 * (73 + mod // 2)) % mod)
    print("복구된 값:", recover)
    digit_select(minus_inv_mask, mod)
