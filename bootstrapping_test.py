import math
import numpy as np
from fv_scheme import fv_scheme 

# 기본 세팅



n = pow(2, 0)
 # ring q 생성
p = 2
e = 20
q = pow(p, e)
r = 5
t = pow(p, r)
T = 16

Q = pow(2, 100)

fv_mod_q = fv_scheme.FV_SH(degree=n, pt_modulus=t, ct_modulus=q)
fv_mod_q.relinearisation_key = fv_mod_q.generate_relinearisation_version1_key(T=T)

def create_ring(q, t):

    fv = fv_scheme.FV_SH(degree=n, pt_modulus=t, ct_modulus=q)
    fv.public_key = fv_mod_q.public_key
    fv.secret_key = fv_mod_q.secret_key
    fv.relinearisation_key = fv.generate_relinearisation_version1_key(T=T)
    return fv


def modulus_switching(ciphertext1, before_modulus, after_modulus):
    factor = after_modulus / before_modulus
    def process_component(component):
        if isinstance(component, list):
            return [round(factor * x) for x in component]
        else:
            return round(factor * component)
    return [process_component(comp) for comp in ciphertext1]

def dot_product_with_sk(ciphertext1, fv_mod_Q, Q, q_prime):
    '''
    # 파라미터 설정
    평문 모듈러스 : q' (기존 암호문의 모듈러스를 평문 모듈러스로 설정)
    암호문 모듈러스 : Q (Q >> q')
    
    1. ring Q  에서 sk 를 암호화 -> (d0, d1)
    2. 기존 암호문 (c0, c1) -> (floor(Q/q') * c0 + c1 * d0, c1 * d1) = (e0, e1) 형태로 변환
       <(c0, c1), Enc(s)> : inner product

    
    return : <e0, e1>
    '''
    def scalar_multiply_poly(poly, scalar):
        return [scalar * coeff for coeff in poly]
    d0, d1 = fv_mod_Q.encrypt(pk=fv_mod_Q.public_key, m=fv_mod_Q.secret_key)
    factor = math.floor(Q / q_prime)
    e0 = fv_mod_Q.ring_q._ring_add(scalar_multiply_poly(ciphertext1[0], factor), fv_mod_Q.ring_q._ring_multiply(ciphertext1[1], d0))
    e1 = fv_mod_Q.ring_q._ring_multiply(ciphertext1[1], d1)

    return [e0, e1]

def digit_extraction(ciphertext1, e, p):
    
    row = e + 1
    col = e + 1
    # 2차원 리스트 초기화
    w = [[0] * col for _ in range(row)]
    ciphertext1 = [ct.tolist() if isinstance(ct, np.ndarray) else ct for ct in ciphertext1]
    w[0][0] = ciphertext1
    rings = []
    for j in range(e + 1):
        ring = create_ring(q=Q, t=pow(p, e - j))
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
    ring = create_ring(q=Q, t=pow(p, e))
    remove_digit_v = ciphertext1
    for i in range(v):
        # temp = w[i][e - 1] * pow(p, i)
        temp = [[-coef for coef in w[i][e][0]], [-coef for coef in w[i][e][1]]]
        # remove_digit_v -= w[i][e - 1] * pow(p, i)
        remove_digit_v = ring.add(remove_digit_v, temp)
    return remove_digit_v

def before_bootstrapping(ciphertext1, ciphertext2):
    
    # 5회 곱셈, 6회 부터는 곱셈이 불가능
    enc_mul_result = ciphertext1
    for i in range(5):
        if i % 2 == 0:
            enc_mul_result = fv_mod_q.multiply_use_rlk_ver1(ct1=ciphertext2, ct2=enc_mul_result, T=T, rlk=fv_mod_q.relinearisation_key)
        else:
            enc_mul_result = fv_mod_q.multiply_use_rlk_ver1(ct1=ciphertext1, ct2=enc_mul_result, T=T, rlk=fv_mod_q.relinearisation_key)
        dec_mul_ciphertext = fv_mod_q.decrypt(enc_mul_result)
        print(f"{i + 1} 번 곱셈 후 곱셈 결과 다항식 복호화 결과 : \n", dec_mul_ciphertext)


def bootstrapping(ciphertext1):
    print("1. modulus switching")
    #1. modulus switching
    # 2^30 -> 2^30
    q_prime = pow(p, e)
    
    # ring q' 생성
    fv_mod_q_prime = create_ring(q_prime, t)
    # 같은 pk 사용
    fv_mod_q_prime.public_key = fv_mod_q.public_key
    # 같은 secret key 사용
    fv_mod_q_prime.secret_key = fv_mod_q.secret_key
    # 같은 재선형화 키 사용
    fv_mod_q_prime.relinearisation_key = fv_mod_q_prime.generate_relinearisation_version1_key(T=T)

    ciphertext_modulus_switched = modulus_switching(ciphertext1, q, q_prime)

    delta = math.floor(q / t)
    print("q = ", q, "t = ", t, "delta = ", delta)

    print("2. dot product with sk")
    t_prime = pow(p, e)
    # ring Q 생성
    fv_mod_Q = create_ring(Q, t_prime)
    # 같은 sk 사용
    fv_mod_Q.public_key = fv_mod_q.public_key
    fv_mod_Q.secret_key = fv_mod_q.secret_key
    fv_mod_Q.relinearisation_key = fv_mod_Q.generate_relinearisation_version1_key(T=T)

    delta = math.floor(q / t)
    print("q = ", q, "t = ", t, "delta = ", delta)


    # dot product with sk
    dot_product_result_ciphertext = dot_product_with_sk(ciphertext1, fv_mod_Q, Q, t_prime)
    

    print("3. digit extraction")
    digit_remove_result = digit_remove(ciphertext1=dot_product_result_ciphertext, p=p, e=e, v= e-r)
    # print("digit extraction 결과 : \n", digit_remove_result)
    modulus_switched_ciphertext = modulus_switching(ciphertext1=digit_remove_result, before_modulus=Q, after_modulus=q)
    # print("modulus switching 후 : \n", modulus_switched_ciphertext)
    # dec_digit_remove_ciphertext = fv_mod_q.decrypt(modulus_switched_ciphertext)
    # print("digit extraction 후 복호화 결과 : \n", dec_digit_remove_ciphertext)

    return modulus_switched_ciphertext

# 예제 사용
if __name__ == "__main__":

    print("================== bootstrapping 전 ==================") 
    print("파라미터 설정")
    print("q = ", q, "t = ", t, "delta = ", math.floor(q / t))
    # 다항식 계수에 packing
    packed_plaintext1 = [5]
    packed_plaintext2 = [pow(5, -1, t)] # 역수

    # 다항식 암호화
    ciphertext1 = fv_mod_q.encrypt(pk=fv_mod_q.public_key, m=packed_plaintext1)
    ciphertext2 = fv_mod_q.encrypt(pk=fv_mod_q.public_key, m=packed_plaintext2)
    # 부트스트래핑 전 덧셈, 곱셈
    before_bootstrapping(ciphertext1=ciphertext1, ciphertext2=ciphertext2)
   


    print("================== bootstrapping ==================") 
    

    enc_mul_result = ciphertext1
    for i in range(5):
        if i % 2 == 0:
            enc_mul_result = fv_mod_q.multiply_use_rlk_ver1(ct1=ciphertext2, ct2=enc_mul_result, T=T, rlk=fv_mod_q.relinearisation_key)
        else:
            enc_mul_result = fv_mod_q.multiply_use_rlk_ver1(ct1=ciphertext1, ct2=enc_mul_result, T=T, rlk=fv_mod_q.relinearisation_key)
            bootstrapping_result = bootstrapping(ciphertext1=enc_mul_result)
            enc_mul_result = bootstrapping_result

        dec_mul_ciphertext = fv_mod_q.decrypt(enc_mul_result)
        print(f"{i + 1} 번 곱셈 후 곱셈 결과 다항식 복호화 결과 : \n", dec_mul_ciphertext)

    

    
    
    
   
   
    
   