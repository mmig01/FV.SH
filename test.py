import numpy as np

from polynomial_ring import PolynomialRing


# 테스트
n = pow(2 , 2)

q = 7
ring_q = PolynomialRing(n, q)

f = [1, 1, 1, 1, 1, 9]  # x^5 + x^4 + x^3 + x^2 + x + 1
g = [4, 5]     # 5x + 4

# Ring 테스트
result_mod = ring_q.mod_phi(f)
print("phi(x)로 나눈 나머지:\n", np.poly1d(result_mod[::-1]))

# 더하기
result_add = ring_q.add(f, g)
print("덧셈 결과: \n", np.poly1d(result_add[::-1]))

# 곱하기
result_mul = ring_q.multiply(f, g)
print("곱셈 결과: \n", np.poly1d(result_mul[::-1]))