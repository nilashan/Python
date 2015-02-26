set1 = set()
set1.add("cat")                # Add a single member
set1.update(["dog", "mouse"])

print(set1)
set1.remove("cat")
print(set1)
set1.add("lll")
set1.add("ppp")
set1.add("aaa")
set1.add("zzz")
set1.add("yyy")
set1.add('["dog", "mouse"]')
print(set1)

set1.update(['pli', 'opl', 'psd'])



set2=set()
set2.add(set1.pop())
print(set2)

print(set1)

print '=======================>'
knights = {'gallahad': 'the pure', 'robin' : 'the brave'}
for k, v in knights.iteritems():
    print k, v