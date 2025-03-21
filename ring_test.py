import numpy as np
from parameters.polynomial_ring import PolynomialRing

if '__main__' == __name__:
    # 테스트
    n = pow(2 , 1)
    q = 7
    ring_q = PolynomialRing(n, q)

    # 다항식 생성
    f = ring_q.generate_polynomial()  
    g = ring_q.generate_polynomial()
    e = ring_q.generate_polynomial_from_chi()
    # 출력 테스트
    print("f(x) = \n", np.poly1d(f))
    # print("g(x) = \n", np.poly1d(g[::-1]))
    # print("e(x) = \n", np.poly1d(e[::-1]))

    # Ring 테스트
    result_mod = ring_q.mod_phi(f)
    print("phi(x)로 나눈 나머지:\n", np.poly1d(result_mod))

    # # 더하기
    # result_add = ring_q.add(f, g)
    # print("덧셈 결과: \n", np.poly1d(result_add[::-1]))

    # # 곱하기
    # result_mul = ring_q.multiply(f, g)
    # print("곱셈 결과: \n", np.poly1d(result_mul))

