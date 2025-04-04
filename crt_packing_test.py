
import math
import numpy as np
from fv_scheme import fv_scheme 
# 곱셈 시 오버플로 해결해야 함!!!

n = pow(2, 2)
# 평문, 암호문 모듈러스
q = pow(2, 30)
t = pow(17,2)
delta = math.floor(q / t)

print("q = ", q, "t = ", t, "delta = ", delta)


fv = fv_scheme.FV_SH(degree=n, pt_modulus=t, ct_modulus=q)
s = fv.secret_key
# 공개 키
pk = fv.generate_public_key()
rlk = fv.generate_relinearisation_version1_key(T=2)
# NTT 계산
def NTT(f, w, mod):
    # 입력값의 길이
    n = len(f)
    # 결과값
    F = [0] * n
    # z = w^2
    z = pow(w, 2, mod)
    # 입력값에 대해 계산
    for i in range(n):
        # 오버플로가 나지 않도록 w^2 을 분리해서 계산
        for j in range(n):
            # z^j * w^j 계산
            temp = pow(z, i * j, mod) * pow(w, j, mod)
            temp %= mod
            F[i] += f[j] * temp
    return [F[i] % mod for i in range(n)]

# INTT 계산
def INTT(F, w, mod):
    # 입력값의 길이
    n = len(F)
    # 결과값
    f = [0] * n
    # 입력값에 대해 계산
    for i in range(n):
        # 계산
        for j in range(n):
            f[i] += F[j] * pow(w, (-2 * i * j) - i, mod)
        f[i] *= pow(n, -1, mod)
    return [f[i] % mod for i in range(n)]

def get_w(n, mod):
    """
    w^n = -1, w^(2n) = 1을 만족하는 w를 찾는 함수
    :param n: n 값
    :param mod: 모듈러 값
    :return: 조건을 만족하는 w
    """

    # 1부터 mod - 1 사이의 정수 중 조건을 만족하는 w를 찾음
    for w in range(1, mod):
        if pow(w, n, mod) == mod - 1 and pow(w, 2 * n, mod) == 1:
            return w
    
    raise ValueError("조건을 만족하는 w를 찾을 수 없습니다.")
    

def crt_pack_with_INTT(m, mod, n):
   w = get_w(n, mod)
   return INTT(m, w, mod)

def inverse_crt_pack_with_NTT(m, mod, n):
    w = get_w(n, mod)
    return NTT(m, w, mod)

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
    
    


# 예제 사용
if __name__ == "__main__":
    
    # 입력값 벡터 m 을 설정

    mod = t
    # 다항식의 근을 계산
    roots = get_roots(n, mod)
    slot_length = len(roots)
    print("ψ : ", roots)
    print("슬롯 개수 : " , slot_length)

    plaintext1 = [1, 2, 3, 4]
    plaintext2 = [5, 6, 7, 8]

    print("입력 벡터1 : ", plaintext1)
    print("입력 벡터2 : ", plaintext2)

    # 다항식 계수에 packing
    packed_plaintext1 = crt_pack_with_INTT(plaintext1, mod, n)
    packed_plaintext2 = crt_pack_with_INTT(plaintext2, mod, n)
    print("첫번째 입력벡터를 벡터 -> 다항식 packing : \n", np.poly1d(packed_plaintext1[::-1]))
    print("두번째 입력벡터를 벡터 -> 다항식 packing : \n", np.poly1d(packed_plaintext2[::-1]))

    # 다항식 암호화
    enc_plaintext1 = fv.encrypt(pk=pk, m=packed_plaintext1)
    enc_plaintext2 = fv.encrypt(pk=pk, m=packed_plaintext2)
    
    # 다항식 곱셈
    enc_mul = fv.multiply_use_rlk_ver1(ct1=enc_plaintext1, ct2=enc_plaintext2, T=2, rlk=rlk)
    print("곱셈 결과 암호문 c'0 : \n", np.poly1d(enc_mul[0][::-1]))
    print("곱셈 결과 암호문 c'1 : \n", np.poly1d(enc_mul[1][::-1]))
    print("======= 암호화 상태로 다항식 곱셈 수행 (NTT 변환 후 NTT 곱셈 사용) =======")
    # 다항식 복호화
    dec_ciphertext = fv.decrypt(enc_mul)
    print("곱셈 후 곱셈 결과 다항식 복호화 결과 : \n", np.poly1d(dec_ciphertext[::-1]))

    # 벡터 복구
    mul_result_of_packed_plaintext = inverse_crt_pack_with_NTT(dec_ciphertext, mod, n)
    print("복구된 벡터 : ", mul_result_of_packed_plaintext)
    
    
    # # root 개의 슬롯만큼 m, m2 생성
    # m = [random.randint(1, mod - 1) for _ in range(slot_length)]
    # print("m : ", m)
    
    # m2 = [random.randint(1, mod - 1) for _ in range(slot_length)]
    # print("m2 : ", m2)
   
    # # CRT Packing 을 계산
    # # m_crt_pack = crt_pack (roots, m, mod) //라그랑주 보간법 버전
    # m_crt_pack = crt_pack_with_NTT(m, mod, n)
    # print("CRT Packing1 : ", np.poly1d(m_crt_pack))

    # # numpy 사용하여 다항식에 근 대입 //라그랑주 보간법 버전
    # res = []
    # for i in range(len(roots)):
    #     res.append(int(np.polyval(m_crt_pack[::-1], roots[i]) % mod))
    # print("m 의 값 복구 : " , res)

    # inv_m_crt_pack = inverse_crt_pack_with_NTT(m_crt_pack, mod, n)
    # print("Inverse CRT Packing1 : ", inv_m_crt_pack)

    # # m2_crt_pack = crt_pack(roots, m2, mod) //라그랑주 보간법 버전
    # m2_crt_pack = crt_pack_with_NTT(m2, mod, n)
    # print("CRT Packing2 : ", np.poly1d(m2_crt_pack))
    
    # # numpy 사용하여 다항식에 근 대입 //라그랑주 보간법 버전
    # res = []
    # for i in range(len(roots)):
    #     res.append(int(np.polyval(m2_crt_pack[::-1], roots[i]) % mod))
    # print("m2 의 값 복구 : " , res)

    # inv_m2_crt_pack = inverse_crt_pack_with_NTT(m2_crt_pack, mod, n)
    # print("Inverse CRT Packing2 : ", inv_m2_crt_pack)

    # print("\n\n=============== 2. m, m2 곱셈 테스트 ================")
    # # 1. 단순 다항식 곱셈
    # start_t = time.time()
    # # f = x^n + 1 생성
    # f = [1] + [0] * (n - 1) + [1]

    # # CRT Packing1 * CRT Packing2 계산
    # m_crt_mul_m2_crt = [0] * (2 * n - 1)
    
    # for i in range(len(m_crt_pack)):
    #     for j in range(len(m2_crt_pack)):
    #         m_crt_mul_m2_crt[i + j] += m_crt_pack[i] * m2_crt_pack[j]
    #         m_crt_mul_m2_crt[i + j] %= mod
    # # f = x^n + 1 로 mod 연산
    # _, remainder = np.polydiv(m_crt_mul_m2_crt[::-1], f[::-1])
    # # 오름차순으로 변경
    # m_crt_mul_m2_crt = remainder[::-1]

    # print("CRT Packing1 * CRT Packing2 : ", np.poly1d(m_crt_mul_m2_crt[::-1]))
    # print(f"단순 곱셈 Time :  {(time.time() - start_t):.6f}")

    # # numpy 사용하여 다항식에 근 대입
    # res = []
    # for i in range(len(roots)):
    #     res.append(int(np.polyval(m_crt_mul_m2_crt[::-1], roots[i]) % mod))
    # print("CRT Packing1 * CRT Packing2 의 값 복구 : " , res)

    # # 2. NTT 를 이용한 곱셈
    # # w 값을 계산
    # start_t = time.time()

    # w = get_w(n, mod)
    # # NTT 계산
    # F = NTT(m_crt_pack, w, mod)
    # G = NTT(m2_crt_pack, w, mod)
    # H = np.mod(np.multiply(F, G), mod)
    # # INTT 계산
    # h = INTT(H, w, mod)
    # print("CRT Packing1 * CRT Packing2 with NTT: ", np.poly1d(h[::-1]))
    # print(f"NTT 곱셈 Time :  {(time.time() - start_t):.6f}")
    # # numpy 사용하여 다항식에 근 대입
    # res = []
    # for i in range(len(roots)):
    #     res.append(int(np.polyval(h[::-1], roots[i]) % mod))
    # print("CRT Packing1 * CRT Packing2 with NTT 의 값 복구 : " , res)
   
    
   