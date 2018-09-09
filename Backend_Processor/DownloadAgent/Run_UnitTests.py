from DataStore_Modules import *
from IoC_Modules import *
from UnitTest import *



ThreatObject = IoC_EmergingThreats()
print(ThreatObject)
TestObject = IoC_EmergingThreats_Tests


TestObject.CollectingResourceTest()

TestObject.ParseANewResourceTest()

TestObject.ViewThreatsTest()

TestObject.ExportThreatListTest()

TestObject.CreateUniqueKey()
