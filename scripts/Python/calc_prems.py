import math

# https://training.cyberwave.network/challenges : It's 1337 time

primes = []

for i in range(1337, 148609):
   if i<2:
      continue
   is_prime = True

   for j in range(2, math.isqrt(i) +1):
      if i % j == 0:
         is_prime = False
         break

   if is_prime:
      primes.append(i)

total = sum(primes)

final_result = total - 966923583

print(final_result)
