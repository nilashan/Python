import myExcepTest

myExcepTest.MyError
try:
    raise myExcepTest.MyError(2*2)
except myExcepTest.MyError, e:
     print 'My exception occurred, value:', e.value