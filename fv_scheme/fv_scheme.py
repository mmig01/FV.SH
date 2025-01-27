import math
import numpy as np
from parameters.parameter_generator import ParamGenerator
from parameters.polynomial_ring import PolynomialRing


class FV_SH(PolynomialRing, ParamGenerator):
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
        self.param_generator = ParamGenerator(degree=degree, pt_modulus=pt_modulus, ct_modulus=ct_modulus)
        self.secret_key = self.param_generator._generate_small_error()
    
    def generate_public_key(self):
        """
        공개키 생성
        pk = [p0, p1] = [-a·s + e mod q , a] 을 반환
        """
        s = self.secret_key
        a = self.param_generator._generate_polynomial()
        e = self.param_generator._generate_polynomial_from_chi()
        
        """
        p0 = -a·s + e mod q, p1 = a
        """
        p0 = self.ring_q._ring_add(self.ring_q._ring_multiply(a, s), e)
        p0_negative = [-coef for coef in p0]
        p0_negative_mod_q = self.ring_q._centered_mod_list(p0_negative)

        p1 = a

        return [p0_negative_mod_q, p1]
    
    def encrypt(self, pk, m):
        """
        암호화
        ct = [c0, c1] = [p0·u + e1 + ∆·m mod q, p1·u + e2 mod q] 을 반환
        """
        p0 = pk[0]
        p1 = pk[1]

        u = self.param_generator._generate_small_error()

        e1 = self.param_generator._generate_polynomial_from_chi()
        e2 = self.param_generator._generate_polynomial_from_chi()

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
    
    def multiply(self, ct1, ct2, rlk):
        """
        암호문 곱셈
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
        c0_mod_q = self.ring_q._centered_mod_list(c0)

        c1 = self.ring_q._ring_add(self.ring_q._ring_multiply(ct1[0], ct2[1]), self.ring_q._ring_multiply(ct1[1], ct2[0]))
        c1 = [coef * (self.t / self.q) for coef in c1]
        c1 = [round(coef) for coef in c1]
        c1_mod_q = self.ring_q._centered_mod_list(c1)

        c2 = self.ring_q._ring_multiply(ct1[1], ct2[1])
        c2 = [coef * (self.t / self.q) for coef in c2]
        c2 = [round(coef) for coef in c2]
        c2_mod_q = self.ring_q._centered_mod_list(c2)
        
        return [c0_mod_q, c1_mod_q, c2_mod_q]