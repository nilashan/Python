import sys
try:
    f = open('myfile.txt')
    s = f.readline()
    i = int(s.strip())
    print(i)
except IOError, (errno, strerror):
    print "I/O error(%s): %s" % (errno, strerror)
except ValueError:
    print "Could not convert data to an integer."
except:
    print "Unexpected error:", sys.exc_info()[0]
    raise
finally:
    print "Finally block excecuted"