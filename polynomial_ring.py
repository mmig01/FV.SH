import numpy as np

"""
다항식 Ring 클래스
"""
class PolynomialRing:
    def __init__(self, n, modulus):
        """
        :param n: phi(x) = x^n + 1 에서 n
        :param modulus : 모듈러스
        """
        self.n = n
        self.modulus = modulus

    def mod_phi(self, poly):
        """
        다항식을 phi(x) = x^n + 1로 나눈 나머지를 계산
        """
        poly = np.array(poly, dtype=int) % self.modulus
        while len(poly) > self.n:
            # x^n 이상의 항을 phi(x)와 모듈러 연산
            leading_coeff = poly[-1]
            poly[-self.n - 1] += leading_coeff  # x^n ≡ -1 이므로 x^n 항을 상수로 변환
            poly = poly[:-1]  # 최고차항 제거
            poly %= self.modulus  # 계수 모듈러 연산
        return poly.tolist()

    def add(self, poly1, poly2):
        """
        다항식 덧셈
        """
        max_len = max(len(poly1), len(poly2))
        poly1 = np.pad(poly1, (0, max_len - len(poly1)), 'constant')
        poly2 = np.pad(poly2, (0, max_len - len(poly2)), 'constant')
        return self.mod_phi((poly1 + poly2).tolist())

    def multiply(self, poly1, poly2):
        """
        다항식 곱셈
        """
        product = np.polymul(poly1, poly2)  # 다항식 곱셈
        return self.mod_phi(product.tolist())