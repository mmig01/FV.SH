import numpy as np
from parameters.parameter_generator import ParamGenerator

if '__main__' == __name__:
    # 테스트
    n = pow(2 , 1)
    q = 7
    gene = ParamGenerator(degree=n, pt_modulus=3, ct_modulus=q)


    # 다항식 생성
    f = gene._generate_polynomial()  
    g = gene._generate_polynomial()
    
    # # 출력 테스트
    print("f(x) = \n", np.poly1d(f))
    print("g(x) = \n", np.poly1d(g))
   

    # Ring 테스트
    # result_mod = ring_q.mod_phi(f)
    # print("phi(x)로 나눈 나머지:\n", np.poly1d(result_mod))


