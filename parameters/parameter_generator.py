import numpy as np


class ParamGenerator:
    def __init__(self, degree, pt_modulus, ct_modulus):
        self.n = degree
        self.t = pt_modulus
        self.q = ct_modulus

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
                    poly.append(int(round(sample)))
                    break

        # # 테스트를 위해 [-3 , -2, -1, 0, 1, 2, 3] 중에서 랜덤으로 선택
        # for _ in range(self.n):
        #     poly.append(np.random.choice([-3, -2, -1, 0, 1, 2, 3]))

        return poly
    
    def _generate_polynomial(self):
        """
        차수가 n-1 이하, 계수의 범위가 (-q/2 , q/2] 인 다항식 생성
        
        """
        return np.random.randint(
            low=-self.q // 2 + 1,
            high=self.q // 2 + 1,
            size=self.n
        ).tolist()
    
    def _generate_small_error(self):
        """
        비밀키, u 등 작은 에러 생성에 사용
        길이 [-1, 0, 1] 중에서 계수를 랜덤으로 선택하여 n - 1 차 다항식 생성
        """
        # 비밀키 생성
        coefficients = np.random.choice([-1, 0, 1], size=self.n)
        return coefficients.tolist()