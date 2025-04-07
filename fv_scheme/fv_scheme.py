import math
import time
import numpy as np
from parameters.polynomial_ring import PolynomialRing


class FV_SH(PolynomialRing):
    def __init__(self, degree , pt_modulus, ct_modulus):
        """
        n : cyclotomic poly 차수 (f(x) = x^n + 1)
        t : 평문 모듈러스
        q : 암호문 모듈러스
        ring_t : 평문 다항식 Ring
        ring_q : 암호문 다항식 Ring
        delta : q/t 의 버림 값
        param_generator : 파라미터 생성기(다항식 생성, 작은 에러 다항식 생성)
        secret_key : 비밀키
        """
        self.n = degree
        self.t = pt_modulus
        self.q = ct_modulus
        self.ring_t = PolynomialRing(degree=degree, modulus=pt_modulus)
        self.ring_q = PolynomialRing(degree=degree, modulus=ct_modulus)
        self.delta = math.floor(ct_modulus / pt_modulus)
        self.secret_key = self.ring_q._generate_small_error()
    
    def generate_public_key(self):
        """
        공개키 생성
        pk = [p0, p1] = [-a·s + e mod q , a] 을 반환
        """
        s = self.secret_key
        a = self.ring_q._generate_polynomial()
        e = self.ring_q._generate_polynomial_from_chi()
        
        """
        p0 = -a·s + e mod q, p1 = a
        """
        p0 = self.ring_q._ring_add(self.ring_q._ring_multiply(a, s), e)
        p0_negative = [-coef for coef in p0]
        p0_negative_mod_q = self.ring_q._centered_mod_list(p0_negative)

        p1 = a

        return [p0_negative_mod_q, p1]
    
    def generate_relinearisation_version1_key(self, T):
        """
        version 1 재선형화 키 생성
        rlk = [-a·s + e + T^i·s mod q , a]
        """
        # 재선형화 키 개수
        length = math.floor(math.log(self.q, T))
        s = self.secret_key

        rlk = []

        # length 개의 재선형화 키 생성
        for i in range(0, length + 1):
            a = self.ring_q._generate_polynomial()
            e = self.ring_q._generate_polynomial_from_chi()

            rlk0 = self.ring_q._ring_add(self.ring_q._ring_multiply(a, s), e)
            rlk0_negative = [-coef for coef in rlk0]
            
            # T^i·s^2 계산
            s_square = self.ring_q._ring_multiply(s, s)
            T_pow_i_mul_s_square = [coef * pow(T, i) for coef in s_square]
            # -a·s + e + T^i·s^2 계산
            rlk0_negative_add_T_pow_i_mul_s_square = self.ring_q._ring_add(rlk0_negative, T_pow_i_mul_s_square)
            # mod q 적용
            rlk0_negative_add_T_pow_i_mul_s_square_mod_q = self.ring_q._centered_mod_list(rlk0_negative_add_T_pow_i_mul_s_square)

            rlk1 = a
            rlk.append([rlk0_negative_add_T_pow_i_mul_s_square_mod_q, rlk1])

        return rlk

    def generate_relinearisation_version2_key(self, p):
        """
        version 2 재선형화 키 생성
        rlk = [-a·s + e + p·s^2 mod pq , a]
        """
        ring_pq = PolynomialRing(degree=self.n, modulus= p * self.q)

        s = self.secret_key
    
        # pq Ring 에서 다항식을 생성
        a = ring_pq._generate_polynomial()
        
        # 에러 추출 분포는 보안성을 위해 수정 필요
        e = ring_pq._generate_polynomial_from_chi()
        
        rlk0 = ring_pq._ring_add(ring_pq._ring_multiply(a, s), e)
    
        rlk0_negative = [-coef for coef in rlk0]
        
        # p·s^2 계산
        s_square = ring_pq._ring_multiply(s, s)

        p_mul_s_square = [coef * p for coef in s_square]
        # -a·s + e + p·s^2 계산 (ring pq 에서 계산!)
        rlk0_negative_add_p_mul_s_square = ring_pq._ring_add(rlk0_negative, p_mul_s_square)
        # mod pq 적용
        rlk0_negative_add_p_mul_s_square_mod_pq = ring_pq._centered_mod_list(rlk0_negative_add_p_mul_s_square)

        rlk1 = a

        rlk = [rlk0_negative_add_p_mul_s_square_mod_pq, rlk1]

        return rlk
    
    def encrypt(self, pk, m):
        """
        암호화
        ct = [c0, c1] = [p0·u + e1 + ∆·m mod q, p1·u + e2 mod q] 을 반환
        """
        p0 = pk[0]
        p1 = pk[1]

        u = self.ring_q._generate_small_error()

        e1 = self.ring_q._generate_polynomial_from_chi()
        e2 = self.ring_q._generate_polynomial_from_chi()

        """
        ∆·m 부분
        """
        delta_mul_m = [coef * self.delta for coef in m]
        """
        c0 = p0·u + e1 + ∆·m mod q, c1 = p1·u + e2 mod q
        """
        
        c0 = self.ring_q._ring_add(self.ring_q._ring_add(self.ring_q._ring_multiply(p0, u), e1) , delta_mul_m)
        c1 = self.ring_q._ring_add(self.ring_q._ring_multiply(p1, u), e2)

        """
        mod q 를 적용한 암호문 [c0, c1]
        """
        c0_mod_q = self.ring_q._centered_mod_list(c0)
        c1_mod_q = self.ring_q._centered_mod_list(c1)

        ct = [c0_mod_q, c1_mod_q]
        return ct
    
    def decrypt(self, ct):
        """
        복호화
        """
        c0 = ct[0]
        c1 = ct[1]
        s = self.secret_key

        """
        c0 + c1·s = ∆·m + v + q·r
        """
        c0_c1s = self.ring_q._ring_add(c0, self.ring_q._ring_multiply(c1, s))
        
        """
        c0 + c1·s mod q = ∆·m + v
        """
        c0_cls_mod_q = self.ring_q._centered_mod_list(c0_c1s)
        
        """
        t/q · [c0 + c1·s] mod q = m + some error + r·t
        """

        # 각 계수에 t/q 를 곱하고 버림 연산
        pt = [round(coef * self.t / self.q) for coef in c0_cls_mod_q]
       
        pt_mod_t = self.ring_t._centered_mod_list(pt)
        return pt_mod_t
    
    def add(self, ct1, ct2):
        """
        암호문 덧셈
        """

        """
        FV.SH.Add(ct1, ct2) = [ct1[0] + ct2[0] mod q, ct1[1] + ct2[1] mod q]
        """

        c0 = self.ring_q._ring_add(ct1[0], ct2[0])
        c0_mod_q = self.ring_q._centered_mod_list(c0)

        c1 = self.ring_q._ring_add(ct1[1], ct2[1])
        c1_mod_q = self.ring_q._centered_mod_list(c1)

        ct = [c0_mod_q, c1_mod_q]
        return ct
    
    def multiply_use_rlk_ver1(self, ct1, ct2, T, rlk):
        """
        재선형화 버전 1을 이용한 암호문 곱셈
        mod q 가 없는 상태에서 곱셈 후 마지막에 mod q 적용
        """

        """
        FV.SH.Multiply(ct1, ct2) : compute
        c0 = round(t/q · ct1[0] · ct2[0]) mod q
        c1 = round{t/q · (ct1[0] · ct2[1] + ct1[1] · ct2[0])} mod q
        c2 = round(t/q · ct1[1] · ct2[1]) mod q
        """
        
        c0 = self.ring_q._ring_multiply(ct1[0], ct2[0])
        c0 = [coef * (self.t / self.q) for coef in c0]
        c0 = [round(coef) for coef in c0]

        c1 = self.ring_q._ring_add(self.ring_q._ring_multiply(ct1[0], ct2[1]), self.ring_q._ring_multiply(ct1[1], ct2[0]))
        c1 = [coef * (self.t / self.q) for coef in c1]
        c1 = [round(coef) for coef in c1]

        c2 = self.ring_q._ring_multiply(ct1[1], ct2[1])
        c2 = [coef * (self.t / self.q) for coef in c2]
        c2 = [round(coef) for coef in c2]

        """
        재선형화 버전 1
        """
        c0_prime_mod_q, c1_prime_mod_q = self.relinearisation_ver1(multiplied_ct=[c0, c1, c2], T=T, rlk=rlk)
        return [c0_prime_mod_q, c1_prime_mod_q]
    
    def multiply_use_rlk_ver2(self, ct1, ct2, p, rlk):
        """
        재선형화 버전 2를 이용한 암호문 곱셈
        mod q 가 없는 상태에서 곱셈 후 마지막에 mod q 적용
        """

        """
        FV.SH.Multiply(ct1, ct2) : compute
        c0 = round(t/q · ct1[0] · ct2[0]) mod q
        c1 = round{t/q · (ct1[0] · ct2[1] + ct1[1] · ct2[0])} mod q
        c2 = round(t/q · ct1[1] · ct2[1]) mod q
        """

        c0 = self.ring_q._ring_multiply(ct1[0], ct2[0])
        c0 = [coef * (self.t / self.q) for coef in c0]
        c0 = [round(coef) for coef in c0]

        c1 = self.ring_q._ring_add(self.ring_q._ring_multiply(ct1[0], ct2[1]), self.ring_q._ring_multiply(ct1[1], ct2[0]))
        c1 = [coef * (self.t / self.q) for coef in c1]
        c1 = [round(coef) for coef in c1]

        c2 = self.ring_q._ring_multiply(ct1[1], ct2[1])
        c2 = [coef * (self.t / self.q) for coef in c2]
        c2 = [round(coef) for coef in c2]

        """
        재선형화 버전 2
        mod q 가 아닌 mod pq 에서 계산
        """
        c0_prime_mod_q, c1_prime_mod_q = self.relinearisation_ver2(multiplied_ct=[c0, c1, c2], p=p, rlk=rlk)

        return [c0_prime_mod_q, c1_prime_mod_q]
    
    def relinearisation_ver1(self, multiplied_ct, T, rlk):
        """
        relinearisation version 1
        """
        c0 = multiplied_ct[0]
        c1 = multiplied_ct[1]
        c2 = multiplied_ct[2]

        # 기저 T 를 이용하여 c2 를 분해
        c2_split = self.split_polynomial_by_T(c2 = c2, T = T)
        c0_prime = []
        c1_prime = []
        
        L = math.floor(math.log(self.q, T))
        # length 개의 재선형화 키에 대해 계산
        for i in range(L + 1):
            c0_prime = self.ring_q._ring_add(c0_prime, self.ring_q._ring_multiply(rlk[i][0], c2_split[i]))
            c1_prime = self.ring_q._ring_add(c1_prime, self.ring_q._ring_multiply(rlk[i][1], c2_split[i])) 
        
        c0_prime = self.ring_q._ring_add(c0_prime, c0)
        c0_prime_mod_q = self.ring_q._centered_mod_list(c0_prime)
        c1_prime = self.ring_q._ring_add(c1_prime, c1)
        c1_prime_mod_q = self.ring_q._centered_mod_list(c1_prime)
        
        return [c0_prime_mod_q, c1_prime_mod_q]
    
    def split_polynomial_by_T(self, c2, T):
        """
        다항식의 각 계수를 기저 T 로 분해하여 L 개의 다항식 리스트를 생성
        
        :param c2: 다항식의 계수 리스트 
        :param T: 기저(base)
        :param q: 암호문 모듈러스
        :return: L 개의 다항식 리스트 
        """
        # length 계산 (기저 T 로 표현했을 때 최대 자리 수)
        length = math.floor(math.log(self.q, T))

        # length 개의 다항식 초기화 (모든 항이 0인 다항식)
        poly_list = [np.zeros(len(c2), dtype=int) for _ in range(length + 1)]

        # 각 계수를 기저 T로 변환하여 자리별로 배치
        for i, coeff in enumerate(c2):  # 다항식의 각 계수에 대해 반복
            num = coeff
            for j in range(length + 1):  # L 개의 다항식 생성
                poly_list[j][i] = num % T  
                num //= T  # 다음 자리 계산

        return [poly.tolist() for poly in poly_list]  # 리스트 형태로 반환
    
    def relinearisation_ver2(self, multiplied_ct, p, rlk):
        """
        relinearisation version 2
        mod q 가 아닌 mod pq 에서 계산
        """
        ring_pq = PolynomialRing(degree=self.n, modulus= p * self.q)

        c0 = multiplied_ct[0]
        c1 = multiplied_ct[1]
        c2 = multiplied_ct[2]

        c2_mul_rlk0 = ring_pq._ring_multiply(c2, rlk[0])
        # c0' = c0 + c2·rlk[0] / p 후 계수 반올림
        c0_prime = [round(coef/p) for coef in c2_mul_rlk0]
        # 이 때 c0_prime 은 mod pq 가 아닌 mod q 에서 연산
        c0_prime_mod_q = self.ring_q._centered_mod_list(c0_prime)

        c2_mul_rlk1 = ring_pq._ring_multiply(c2, rlk[1])
        # c1' = c1 + c2·rlk[1] / p 후 계수 반올림
        c1_prime = [round(coef/p) for coef in c2_mul_rlk1]
        # 이 때 c1_prime 은 mod pq 가 아닌 mod q 에서 연산
        c1_prime_mod_q = self.ring_q._centered_mod_list(c1_prime)

        c0_prime_mod_q_add_c0 = self.ring_q._ring_add(c0_prime_mod_q, c0)
        # c0 를 더한 후 한번 더 mod q 적용
        c0_prime_mod_q_add_c0 = self.ring_q._centered_mod_list(c0_prime_mod_q_add_c0)

        c1_prime_mod_q_add_c1 = self.ring_q._ring_add(c1_prime_mod_q, c1)
        # c1 를 더한 후 한번 더 mod q 적용
        c1_prime_mod_q_add_c1 = self.ring_q._centered_mod_list(c1_prime_mod_q_add_c1)
        
        return [c0_prime_mod_q_add_c0, c1_prime_mod_q_add_c1]