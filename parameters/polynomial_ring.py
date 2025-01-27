import numpy as np

"""
다항식 Ring 클래스
List 형태로 다항식을 표현
예) f(x) = 3x^2 + 2x + 1 -> [3, 2, 1]
"""
class PolynomialRing:
    def __init__(self, degree, modulus):
        """
        n = f(x) : x^n + 1 차수
        modulus : 다항식 모듈러스
        phi(x) = x^n + 1 cyclotomic 다항식
        """
        self.n = degree
        self.modulus = modulus
        self.phi = [1] + [0] * (self.n - 1) + [1]

    def _mod_phi(self, poly):
        """
        다항식을 phi(x) = x^n + 1로 나눈 나머지를 계산
        """
        _, remainder = np.polydiv(poly, self.phi)
        result = np.array(remainder, dtype=int)
        return result

    def _ring_add(self, poly1, poly2):
        """
        다항식 덧셈
        """
        result = np.polyadd(poly1, poly2)
        return self._mod_phi(result)

    def _ring_multiply(self, poly1, poly2):
        """
        다항식 곱셈
        """
        result = np.polymul(poly1, poly2)
        return self._mod_phi(result)
    
    def __centered_modular(self, integer):
        """
        하나의 정수에 대한 모듈러스 연산 -> 범위 : [-modulus/2, modulus/2] 
        """
        r = integer % self.modulus
        # ex) mod 7 일 때 -3 mod 7 = 4, 그러나 Ring 에서 -3 != 4 이므로 음수의 의미를 유지
        if r > self.modulus // 2:
            r -= self.modulus
        return r

    def _centered_mod_list(self, poly):
        """
        다항식 계수 범위를 [-modulus/2, modulus/2] 로 변환
        """
        return [self.__centered_modular(coefficient) for coefficient in poly]
    