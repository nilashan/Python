#find all such numbers which are divisible by 7 but are not a multiple of 5,
#between 2000 and 3200 (both included)

l=[]
for i in range(2000, 3201):
    if (i%7==0) and (i%5!=0):
        l.append(str(i))

print ','.join(l)



for i in range(2000, 3000):
    if(i%9==0) and (i%5!=0):
        print i, ',',
