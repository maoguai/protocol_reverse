import os
import cobra

class TestObject:

    def __init__(self):
        self.x = 10
        self.y = 20
        self.z = 90

    def addToZ(self, val):
        self.z += val

    def getUser(self):
        return cobra.getUserInfo()

def accessTestObject( t ):
    assert( t.x == 10 )
    t.y = 333
    assert( t.y == 333 )
    t.addToZ( 10 )
    assert( t.z == 100 )

dirname = os.path.dirname(__file__)
def openTestFile(name):
    return file(testFileName(name),'rb')

def testFileName(name):
    return os.path.join(dirname, name)

