import math
import numpy as np
from fv_scheme import fv_scheme 


n = pow(2, 0)
 # ring q 생성
p = 2
e = 20
q = pow(p, e)
r = 8
t = pow(p, r)
T = 2


def create_ring(q, t):

    fv = fv_scheme.FV_SH(degree=n, pt_modulus=t, ct_modulus=q)
    fv.relinearisation_key = fv.generate_relinearisation_version1_key(T=2)
    return fv

def digit_extraction(ciphertext1, e, p):
    
    row = e + 1
    col = e + 1
    # 2차원 리스트 초기화
    w = [[0] * col for _ in range(row)]
    ciphertext1 = [ct.tolist() if isinstance(ct, np.ndarray) else ct for ct in ciphertext1]
    w[0][0] = ciphertext1
    rings = []
    for j in range(e + 1):
        ring = create_ring(q=q, t=pow(p, e - j))
        rings.append(ring)
    for k in range(e):
        y = ciphertext1
        for j in range(k + 1):
            w[j][k + 1] = rings[j].multiply_use_rlk_ver1(ct1=w[j][k], ct2=w[j][k], T=2, rlk=rings[j].relinearisation_key)
            # w 계수에 음수 처리
            inverse_w1 = [coef * -1 for coef in w[j][k + 1][0]]
            inverse_w2 = [coef * -1 for coef in w[j][k + 1][1]]
            inverse_w = [inverse_w1, inverse_w2]
            # y = (y - w[j][k + 1]) / p
            y = rings[j].add(y, inverse_w)
        w[k + 1][k + 1] = y
    return w

def digit_remove(ciphertext1, p, e, v):
   
    w = digit_extraction(ciphertext1, e, p)
    print("w:")
    for row in w:
        print(row)
            
    ring = create_ring(q=q, t=pow(p, e))
    remove_digit_v = ciphertext1
    for i in range(v):
        # temp = w[i][e - 1] * pow(p, i)
        temp = [[-coef for coef in w[i][e][0]], [-coef for coef in w[i][e][1]]]
        # remove_digit_v -= w[i][e - 1] * pow(p, i)
        remove_digit_v = ring.add(remove_digit_v, temp)
    return remove_digit_v

# 예제 사용s
if __name__ == "__main__":
    z = 11
    p = 2

    # 11 을 암호화
    fv_mod_q = create_ring(q=q, t=t)
    pt = [z]
    ciphertext = fv_mod_q.encrypt(pk=fv_mod_q.public_key, m=pt)
    print("ciphertext : ", ciphertext)
    ciphertext = digit_remove(ciphertext, p, e, e-r)
    # print("digit remove 결과 : ", ciphertext)
    
    # 복호화
    dec_ciphertext = fv_mod_q.decrypt(ciphertext)
    print("복호화 결과 : ", dec_ciphertext)
    
   
   
    
   