import random
import time
import numpy
import numpy as np
from sympy import fft, ifft

"""
다항식 Ring 클래스
List 형태로 다항식을 표현
예) f(x) = 3x^2 + 2x + 1 -> [1, 2, 3]
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
        _, remainder = np.polydiv(poly[::-1], self.phi)
        result = np.array(remainder, dtype=np.object_) # 정수 제한 해제
        return result[::-1]
    

    def _ring_add(self, poly1, poly2):
        """
        다항식 덧셈
        """
        result = np.polyadd(poly1[::-1], poly2[::-1])
        return self._mod_phi(result[::-1])

    def _ring_multiply(self, poly1, poly2):
        """
        다항식 곱셈
        """
        result = np.polymul(poly1[::-1], poly2[::-1])
        return self._mod_phi(result[::-1])
        
    

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
    
    def _generate_polynomial_from_chi(self):
        """
        정규분포에서 샘플링된 값들을 기반으로 n - 1 차 이하 다항식을 생성
        sigma: 정규분포의 표준편차
        B: B Bound 값 ([-B, B] 범위)
        :return: 리스트로 표현된 다항식
        """
        
        """
        정규분포 샘플링을 구현 하였으나, sigma 값은 임의로 설정
        """
        sigma = 3.2  # 표준편차 계산
        B = 10 * sigma  # B Bound 설정

        poly = []
        for _ in range(self.n):
            while True:
                sample = np.random.normal(loc=0, scale=sigma)  # 정규분포에서 샘플링
                if -B <= sample <= B:  # B 범위 내 값만 허용
                    '''
                    단순히 int 형으로 변환 후 사용하였지만
                    실제 사용시에는 discrete gaussian distribution 을 사용해야함
                    '''
                    poly.append(int(round(sample)))
                    break

        return poly
    
    def _generate_polynomial(self):
        """
        차수가 n-1 이하, 계수의 범위가 (-q/2 , q/2] 인 다항식 생성
        
        """
        return [random.randint(-self.modulus // 2 + 1, self.modulus // 2) for _ in range(self.n)]
    def _generate_small_error(self):
        """
        비밀키, u 등 작은 에러 생성에 사용
        길이 [-1, 0, 1] 중에서 계수를 랜덤으로 선택하여 n - 1 차 다항식 생성
        """
        # 비밀키 생성
        coefficients = np.random.choice([-1, 0, 1], size=self.n)
        return coefficients.tolist()
    
    