import math
import numpy as np
from fv_scheme import fv_scheme 

# 기본 세팅
# q = 2^60 : 1152921504606846976
# t = 2^20 : 1048576

# q -> q' 2^60 -> 2^40 = 1099511627776

# q' = p^e 꼴로 바꿀 때
# 바뀐 ciphertext modulus -> 2^100 : 1267650600228229401496703205376
# 바뀐 plaintext modulus -> 2^40 : 1099511627776


n = pow(2, 0)
 # ring q 생성
q = pow(2, 60)
t = pow(2, 20)
T = 2
fv_mod_q = fv_scheme.FV_SH(degree=n, pt_modulus=t, ct_modulus=q)
fv_mod_q.relinearisation_key = fv_mod_q.generate_relinearisation_version1_key(T=2)

def create_ring(q, t, T):

    delta = math.floor(q / t)
    print("q = ", q, "t = ", t, "delta = ", delta)

    fv = fv_scheme.FV_SH(degree=n, pt_modulus=t, ct_modulus=q)
    
    return fv


def modulus_switching(ciphertext, q, q_prime):
    factor = q_prime / q
    def process_component(component):
        if isinstance(component, list):
            return [round(factor * x) for x in component]
        else:
            return round(factor * component)
    return [process_component(comp) for comp in ciphertext]

def bootstrapping_with_encrypted_sk(ciphertext, fv_mod_Q, Q, q_prime):
    '''
    # 파라미터 설정
    평문 모듈러스 : q' (기존 암호문의 모듈러스를 평문 모듈러스로 설정)
    암호문 모듈러스 : Q (Q >> q')
    sk : ring Q 에서 새로 생성한 sk
    
    1. ring Q  에서 sk 를 암호화 -> (d0, d1)
    2. 기존 암호문 (c0, c1) -> (floor(Q/q') * c0 + c1 * d0, c1 * d1) = (e0, e1) 형태로 변환
       <(c0, c1), Enc(s)> : inner product

    
    return : <e0, e1>
    '''
    def scalar_multiply_poly(poly, scalar):
        return [scalar * coeff for coeff in poly]
    d0, d1 = fv_mod_Q.encrypt(pk=fv_mod_Q.public_key, m=fv_mod_Q.secret_key)
    factor = math.floor(Q / q_prime)
    e0 = fv_mod_Q.ring_q._ring_add(scalar_multiply_poly(ciphertext[0], factor), fv_mod_Q.ring_q._ring_multiply(ciphertext[1], d0))
    e1 = fv_mod_Q.ring_q._ring_multiply(ciphertext[1], d1)

    return [e0, e1]

def digit_extraction(z, e, p):
    row = e + 1
    col = e + 1
    # 2차원 리스트 초기화
    w = [[0] * col for _ in range(row)]
    w[0][0] = z
    Fe = [0, 0, 1]  # X^2

    for k in range(e):
        y = z
        for j in range(k + 1):
            w[j][k + 1] = np.polyval(Fe[::-1], w[j][k])
            y = (y - w[j][k + 1]) / p
        w[k + 1][k + 1] = y
        
    return w

def digit_remove(z, p, e, v):
    w = digit_extraction(z, e, p)
    # 맨 위 열 인덱스 출력 (칸 맞춤)

    # col = e + 1
    # header = ["      "] + [f"{j:>10}" for j in range(col)]
    # print("[" + " ".join(header) + "]")

    # # 각 행마다 좌측에 행 인덱스 출력
    # for i, row_vals in enumerate(w):
    #     print("[" + f"{i:>6}" + " " + " ".join(f"{val:>10}" for val in row_vals) + "]")
    
    remove_digit_v = z
    for i in range(v):
        remove_digit_v -= w[i][e - 1] * pow(p, i)

    return int(remove_digit_v % pow(p, e))

def before_bootstrapping(ciphertext):
    
     # 다항식 덧셈
    enc_add_result = ciphertext
    # 5회 덧셈
    for _ in range(5):
        enc_add_result = fv_mod_q.add(enc_add_result, ciphertext)
    dec_add_ciphertext = fv_mod_q.decrypt(enc_add_result)
    print("덧셈 후 덧셈 결과 다항식 복호화 결과: \n", dec_add_ciphertext)
    
    # 4회 곱셈, 5회 부터는 곱셈이 불가능
    enc_mul_result = ciphertext
    for _ in range(4):
        enc_mul_result = fv_mod_q.multiply_use_rlk_ver1(ct1=ciphertext, ct2=enc_mul_result, T=T, rlk=fv_mod_q.relinearisation_key)
    
    dec_mul_ciphertext = fv_mod_q.decrypt(enc_mul_result)
    print("곱셈 후 곱셈 결과 다항식 복호화 결과 : \n", dec_mul_ciphertext)


# 예제 사용
if __name__ == "__main__":

    print("================== bootstrapping 전 ==================") 
   
    # 다항식 계수에 packing
    packed_plaintext1 = [10]
    # 다항식 암호화
    ciphertext = fv_mod_q.encrypt(pk=fv_mod_q.public_key, m=packed_plaintext1)

    # 부트스트래핑 전 덧셈, 곱셈
    before_bootstrapping(ciphertext=ciphertext)

    print("================== bootstrapping ==================") 
    print("1. modulus switching")
    #1. modulus switching
    # 2^60 -> 2^40
    q_prime = pow(2, 40)
    t = pow(2, 20)
    
    # ring q' 생성
    fv_mod_q_prime = create_ring(q_prime, t, T)
    # 같은 pk 사용
    fv_mod_q_prime.public_key = fv_mod_q.public_key
    # 같은 secret key 사용
    fv_mod_q_prime.secret_key = fv_mod_q.secret_key
    # 같은 재선형화 키 사용
    fv_mod_q_prime.relinearisation_key = fv_mod_q.relinearisation_key

    ciphertext_modulus_switched = modulus_switching(ciphertext, q, q_prime)

    dec_modulus_switched_ciphertext = fv_mod_q_prime.decrypt(ciphertext_modulus_switched)
    print("modulus switching 후 복호화 결과 : \n", dec_modulus_switched_ciphertext)

    print("2. dot product with sk")
    Q = pow(2, 100)
    # ring Q 생성
    fv_mod_Q = create_ring(Q, t, T)
    # 같은 sk 사용
    fv_mod_Q.secret_key = fv_mod_q_prime.secret_key
    # dot product with sk
    dot_product_result_ciphertext = bootstrapping_with_encrypted_sk(ciphertext_modulus_switched, fv_mod_Q, Q, q_prime)
    dec_e0_e1 = fv_mod_Q.decrypt(dot_product_result_ciphertext)
    print("dot product with sk 후 복호화 결과 : \n", dec_e0_e1)

    print("3. digit extraction")
    test = 17
    e = 5
    p = 2
    res = digit_remove(test, p, e, 1)
    print("digit extraction 결과 : ", res)

    
    
   
   
    
   