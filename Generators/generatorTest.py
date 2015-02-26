def reverse(data):
    for index in range(len(data) - 1, -1, -1):
        yield data[index]


for char in reverse('golf'):
    print char

    # print reverse('golf')
kk = [0, 1, 2, 3]


def ytest(ll):
    for k in range(len(ll) - 1, -1, -1):
        yield ll[k]


xx = ytest(kk)
print type(xx)
for i in range(len(kk) - 1):
    print(xx.next())


def generate_ints(N):
    for i in range(N):
        yield i


gen = generate_ints(3)

print gen.next()

