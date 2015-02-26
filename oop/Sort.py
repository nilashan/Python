class myclassforsort:
   'Common base class for all employees'
   empCount = 0

   def __init__(self, Arr):
      self.Arr = Arr

   def dosort(self,ddd):
        print ddd;


   def dosort(self):
       l=list(self.Arr)
       for i in range(len(l)-1,0,-1):
                for j in range(i):
                     if l[j]>l[j+1]:
                        temp = l[j]
                        l[j] = l[j+1]
                        l[j+1] = temp
       return l

