from collections import namedtuple
from collections import defaultdict

print('========NamedTuple Example===========')
Point = namedtuple('Point1', ['x','y', 'z'])
pt1 = Point(1.0, 5.0, 9.0)
pt2 = Point(2.5, 1.5, 6.0)

from math import sqrt
line_length = sqrt((pt1.x-pt2.x)**2 + (pt1.y-pt2.y)**2)

print line_length

Employee = namedtuple("Employee", ["id", "title", "salary"])
e = Employee(1, "engineer", 10000)

print(e)
print("Title is", e.title)

"""
pt1 = (1.0, 5.0)
pt2 = (2.5, 1.5)

from math import sqrt
line_length = sqrt((pt1[0]-pt2[0])**2 + (pt1[1]-pt2[1])**2)
"""

print('========Default Dictionary Example===========')

s = {('yellow', 1), ('blue', 2), ('yellow', 3), ('blue', 4), ('red', 1)}
d = defaultdict(list)
for k, v in s:
 d[k].append(v)

print( d.items())

