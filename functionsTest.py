
def fib(n): # write Fibonacci series up to n
 a, b = 0, 1
 while b < n:
  print b,
  a, b = b, a+b
  return None

def fib2(n): # return Fibonacci series up to n
 result = []
 a, b = 0, 1
 while b < n:
  result.append(b)
  a, b = b, a+b
 return result


print fib(12)