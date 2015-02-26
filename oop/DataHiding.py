class JustCounter:
   __secretCount = 0
  
   def count(self):
      self.__secretCount += 1
      self.__mmm='ll'
      print self.__secretCount

counter = JustCounter()
counter.count()
counter.count()
print counter._JustCounter__mmm