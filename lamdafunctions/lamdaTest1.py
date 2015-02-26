g = lambda x: x ** 2
h = lambda c: c + 3 / 3

print g(8)
print(h(6))


# Eg 1
pairs = [(1, 'one'), (2, 'two'), (3, 'three'), (4, 'four')]
pairs.sort(key=lambda pair: pair[1])
print(pairs)

#Eg 2

a = [(1, 2), (3, 1), (5, 10), (11, -3)]
a.sort(key=lambda x: x[0])
print(a)



x=map(lambda y: y * -1, range(0, 10))
print(x)


#Eg 3
mult3 = filter(lambda x: x % 3 == 0, [1, 2, 3, 4, 5, 6, 7, 8, 9])
print(mult3)
