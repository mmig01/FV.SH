import math
import numpy as np
from parameters.polynomial_ring import PolynomialRing


class FV_SH:
    def __init__(self, degree , pt_modulus, ct_modulus):
        # 파라미터 선언
        self.n = degree
        self.t = pt_modulus
        self.q = ct_modulus
        self.ring_t = PolynomialRing(degree=degree, modulus=pt_modulus)
        self.ring_q = PolynomialRing(degree=degree, modulus=ct_modulus)
        self.delta = math.floor(ct_modulus / pt_modulus)
        self.secret_key = self.generate_small_error()

    
    def generate_small_error(self):
        """
        비밀키, u 등 작은 에러 생성에 사용
        길이 [-1, 0, 1] 중에서 계수를 랜덤으로 선택하여 n - 1 차 다항식 생성
        """
        # 비밀키 생성
        coefficients = np.random.choice([-1, 0, 1], size=self.n)
        return coefficients.tolist()
    
    def generate_public_key(self):
        """
        공개키 생성
        """
        s = self.secret_key
        a = self.ring_q.generate_polynomial()
        e = self.ring_q.generate_polynomial_from_chi()
        
        p0 = self.ring_q.ring_add(self.ring_q.ring_multiply(a, s), e)
        p0_negative = [-coef for coef in p0]

        # mod q 를 적용한 다항식
        p0_negative_mod_q = self.ring_q.centered_mod_list(p0_negative)
        p1 = a

        return [p0_negative_mod_q, p1]
    
    def encrypt(self, pk, m):
        """
        암호화
        """
        p0 = pk[0]
        p1 = pk[1]

        u = self.generate_small_error()

        e1 = self.ring_q.generate_polynomial_from_chi()
        e2 = self.ring_q.generate_polynomial_from_chi()

        delta_mul_m = [coef * self.delta for coef in m]
        
        c0 = self.ring_q.ring_add(self.ring_q.ring_add(self.ring_q.ring_multiply(p0, u), e1) , delta_mul_m)
        c1 = self.ring_q.ring_add(self.ring_q.ring_multiply(p1, u), e2)

        # mod q 를 적용한 다항식
        c0_mod_q = self.ring_q.centered_mod_list(c0)
        c1_mod_q = self.ring_q.centered_mod_list(c1)

        ct = [c0_mod_q, c1_mod_q]
        return ct
    
    def decrypt(self, ct):
        """
        복호화
        """
        c0 = ct[0]
        c1 = ct[1]
        s = self.secret_key

        c0_c1s = self.ring_q.ring_add(c0, self.ring_q.ring_multiply(c1, s))
        # mod q 를 적용한 다항식
        c0_cls_mod_q = self.ring_q.centered_mod_list(c0_c1s)
        
        # 계수에 t/q 를 곱한 후 반올림
        pt = [round(coef * self.t / self.q) for coef in c0_cls_mod_q]

        # mod t 를 적용한 다항식
        pt_mod_t = self.ring_t.centered_mod_list(pt)
        return pt_mod_t