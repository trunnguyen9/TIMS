		
from DataEnricher import *
# from HostIP import *
# from LocateGeoIP import *
# from datetime import datetime

testHostname = HostIP()
print('Threaded Approach:')
print(datetime.now().strftime("%Y-%m-%d %H:%M:%S") )
testHostname.segmentPush_threaded()
#testHostname.getIP_standard()
print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
# testHostname.displayExtract()
testHostname.updateDB()

testGeo = LocateGeoIP()
print('Threaded Approach:')
print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
testGeo.segmentPush()
print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
# testHostname.displayExtract()
testGeo.updateDB()

















