import numpy as np

# 정규분포 설정
sigma = 3.2  # 표준편차
B = 10 * sigma  # B Bound 설정

# 이산 가우시안 분포에서 샘플링
num_samples = 100  # 샘플 개수
samples = np.random.normal(loc=0, scale=sigma, size=num_samples)

# B 범위 내로 제한 ([-B, B])
bounded_samples = [int(round(x)) for x in samples if -B <= x <= B]

print(f"B Bound: {B}")
print(f"Original samples: {samples}")
print(f"Bounded samples: {bounded_samples}")