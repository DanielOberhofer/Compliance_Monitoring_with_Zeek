import xml.etree.ElementTree as ET
from statics import source, namespaces
from xml_parser import *
from tsvtransform import *

# ----------------------------------------------------------------------------------------------------------------------------------
# 1 - Read XML
tree = ET.parse(source)
root = tree.getroot()

processes = root.findall("bpmn:process", namespaces)
collaborations = root.findall("bpmn:collaboration", namespaces)

processid_2_participantid = get_processid_2_participantid(search_list=processes, search_tag=tags['task_tag'])

entitys = get_participants(search_list=collaborations, search_tag=tags['participant_tag'])
entitys = set_participants_tasks(processes=processes, participants=entitys)
entitys = set_entity_attributes(processes=processes, entitys=entitys)

participant_2_process = get_participant_2_process(search_list=collaborations, search_tag=tags['participant_tag'])
entitys = set_participants_ip(collaborations=collaborations,
                              participants=entitys,
                              participant_process=participant_2_process)

messages = get_messages(collaborations)
network_connections = get_network_connections(messages=messages,
                                              processid_participantid=processid_2_participantid,
                                              participants=entitys)
# ----------------------------------------------------------------------------------------------------------------------------------
# 2 - Extract necessary Attributes - into special files
# Example: Create and store a list of human Ips,that can be used in the Zeek-Script
# write_security_lvl_file(entitys)
# print(entitys)
write_entities_attributes_file(entitys)
print("\n")
write_communications_file(network_connections)
print("\n")
write_security_lvl_file(entitys)

# ----------------------------------------------------------------------------------------------------------------------------------
# 4 - Ausführen der notwendigen Scripts
#-

# Network interface als CONSTAN definieren und compliance.zeek = ./Zeek/compliance.zeek
# /Users/dan/PycharmProjects/Masterarbeit
# print("Please provide the monitored network interface:")
#path_input = input()
#path_input.strip()
#command = "sudo -S zeek -i {interface} Zeek/compliance.zeek".format(interface=path_input)
# print(command)
#os.system(command)