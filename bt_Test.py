import pandas as pd
import numpy as np
from fv_scheme import fv_scheme 


n = pow(2, 0)
 # ring q 생성
p = 2
e = 70
q = pow(p, e)
r = 5
t = pow(p, r)
T = 2

fv_mod_q = fv_scheme.FV_SH(degree=n, pt_modulus=t, ct_modulus=q)

def create_ring(q, t):

    fv = fv_scheme.FV_SH(degree=n, pt_modulus=t, ct_modulus=q)
    fv.public_key = fv_mod_q.public_key
    fv.secret_key = fv_mod_q.secret_key
    fv.relinearisation_key = fv.generate_relinearisation_version1_key(T=T)
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
            w[j][k + 1] = rings[j].multiply_use_rlk_ver1(ct1=w[j][k], ct2=w[j][k], T=T, rlk=rings[j].relinearisation_key)
            # 트릭!! 테스트를 위해 복호화 후 다시 암호화
            dec_res = rings[j].decrypt(w[j][k + 1])
            w[j][k + 1] = rings[j].encrypt(pk=rings[j].public_key, m=dec_res)
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
    rings = []
    for j in range(e + 1):
        ring = create_ring(q=q, t=pow(p, e - j))
        rings.append(ring)
    
    w_dec = []
    for i in range(e + 1):
        row = []
        for j in range(e + 1):
            if w[i][j] == 0:
                w[i][j] = [[0], [0]]
            # row.append(rings[i].decrypt(w[i][j]))
            row.append(w[i][j])
        w_dec.append(row)
    df  = pd.DataFrame(w_dec)
    df.to_csv('digit_extraction.csv', index=False, header=False)
            
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
    z = 15
    p = 2

    # 11 을 암호화
   
    pt = [z]
    ciphertext = fv_mod_q.encrypt(pk=fv_mod_q.public_key, m=pt)
    print("ciphertext : ", ciphertext)
    ciphertext = digit_remove(ciphertext1=ciphertext, p=p, e=r, v=2)
    print("결과 : ", ciphertext)
    # print("digit remove 결과 : ", ciphertext)
    
    # 복호화
    dec_ciphertext = fv_mod_q.decrypt(ciphertext)
    print("복호화 결과 : ", dec_ciphertext)
   
   
    
    # arr = np.random.randint(0,10,(5,8))
    # df  = pd.DataFrame(arr, 
    #                 index=[f"row{i}" for i in range(arr.shape[0])],
    #                 columns=[f"col{j}" for j in range(arr.shape[1])])
    # print(df)  # Jupyter나 IPython 환경에선 바로 표 형태로 보여 줍니다.