import xml.etree.ElementTree as ET
tree = ET.parse('country_data.xml')
root = tree.getroot()
ff=root[0]
gg=ff[0],ff[1],ff[2]

print(ff)

print(gg)
print(len(ff))
print(root)