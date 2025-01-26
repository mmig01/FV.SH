import numpy as np

"""
다항식 Ring 클래스
List 형태로 다항식을 표현
예) f(x) = 3x^2 + 2x + 1 -> [3, 2, 1]
"""
class PolynomialRing:
    def __init__(self, degree, modulus):
        """
        :param n: phi(x) = x^n + 1 에서 n
        :param modulus : 모듈러스
        """
        self.n = degree
        self.modulus = modulus
        self.phi = [1] + [0] * (self.n - 1) + [1]

    def generate_polynomial_from_chi(self):
        """
        χ 로부터 계수를 추출하여 n - 1 차 이하 다항식 생성
        [-2 , -1, 0, 1, 2] 중에서 랜덤으로 선택
        """
        # 병렬로 계수 생성
        coefficients = np.random.choice([-2, -1, 0, 1, 2], size=self.n)
        return coefficients.tolist()
    
    def generate_polynomial(self):
        # 차수가 n-1 이하, 계수의 범위가 (-q/2 , q/2] 인 다항식 생성
        return np.random.randint(
            low=-self.modulus // 2 + 1,
            high=self.modulus // 2 + 1,
            size=self.n
        ).tolist()

    def mod_phi(self, poly):
        """
        다항식을 phi(x) = x^n + 1로 나눈 나머지를 계산
        """
        # x^n + 1로 나눈 나머지 계산
        _, remainder = np.polydiv(poly, self.phi)
        # 각 계수에 modulus 적용
        result = np.array(remainder, dtype=int)
        return result

    def ring_add(self, poly1, poly2):
        """
        다항식 덧셈
        """
        result = np.polyadd(poly1, poly2)
        return self.mod_phi(result)

    def ring_multiply(self, poly1, poly2):
        """
        다항식 곱셈
        """
        result = np.polymul(poly1, poly2)
        return self.mod_phi(result)
    
    def centered_modular(self, integer):
        """
        정수에 대한 모듈러스 연산 -> 범위 : [-modulus/2, modulus/2] 

        """
        r = integer % self.modulus # Apply modulus
        # ex) mod 7 일 때 -3 mod 7 = 4, 그러나 Ring 에서 -3 != 4 이므로 음수의 의미를 유지
        if r > self.modulus // 2:
            r -= self.modulus
        return r

    def centered_mod_list(self, poly):
        """
        다항식 계수 범위를 [-modulus/2, modulus/2] 로 변환
        """
        return [self.centered_modular(coefficient) for coefficient in poly]
    