l1=[1,2,3,4,5,6,7,8,9]
l2=[10,11,12,13,14,15,16,17,18,19]

l=l1+l2
print(l)

x=list()
y=list()
def findOddEven(list):
    for i in range(len(list)-1):
        if(list[i]%2==0):
            x.append(list[i])
        else:
            y.append(list[i])

findOddEven(l)
print(x)
print(y)
