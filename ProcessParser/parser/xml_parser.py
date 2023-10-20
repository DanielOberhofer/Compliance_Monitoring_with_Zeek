from typing import List, Dict, Union

from classes import Entity, MessageFlow, Connection
from statics import tags


def loop_shortener(func):
    def inner(search_list: List, search_tag: str):
        return_element = {}

        for elements in search_list:
            for element in elements:
                if element.tag == search_tag:
                    return_element = func(return_element, element, elements)
        return return_element
    return inner


@loop_shortener
def get_participants(return_dict, element, elements=None) -> Dict:
    return_dict[element.get('processRef')] = Entity(id=element.get('id'),
                                                    name=element.get('name'),
                                                    processRef=element.get('processRef'))
    return return_dict


@loop_shortener
def get_participant_2_process(return_dict, element, elements=None) -> Dict:
    return_dict[element.get('id')] = element.attrib['processRef']

    return return_dict


@loop_shortener
def get_processid_2_participantid(return_dict, element, elements) -> Dict:
    return_dict[element.attrib['id']] = elements.attrib['id']

    return return_dict


def get_messages(collab_list: List) -> List:
    messages = []
    for collab_elements in collab_list:
        for collab_element in collab_elements:
            if collab_element.tag == tags['messageflow_tag']:
                messages.append(MessageFlow(id=collab_element.get('id'),
                                            name=collab_element.get('name'),
                                            sourceRef=collab_element.get('sourceRef'),
                                            targetRef=collab_element.get('targetRef')))
    return messages


def get_network_connections(messages: List, processid_participantid: Dict, participants: Dict) -> List:
    connections = []
    for connection in messages:
        sender_id = processid_participantid[connection.sourceRef]
        receiver_id = processid_participantid[connection.targetRef]
        sender = participants[sender_id]
        receiver = participants[receiver_id]

        rule_dict = rule_string_2_dict(connection.name)

        connections.append(Connection(id=connection.id, sender=sender, receiver=receiver, attributes=rule_dict))
    return connections


def set_participants_ip(collaborations: List, participants: Dict, participant_process: Dict) -> Dict:
    for collaboration in collaborations:
        associations = []
        text_annotations = []
        for element in collaboration:

            if element.tag == tags['association_tag']:
                associations.append(element.attrib)

            if element.tag == tags['textAnnotation_tag']:
                for config in element:
                    attributes = element.attrib
                    attributes['name'] = config.text
                    text_annotations.append(attributes)
        for text_annotation in text_annotations:
            for association in associations:
                if text_annotation['id'] == association["targetRef"]:
                    process_ref = participant_process[association['sourceRef']]
                    rules = rule_string_2_dict(text_annotation['name'])
                    # Include rules to the participants attributes
                    participants[process_ref].attributes = participants[process_ref].attributes | rules
    return participants


def set_participants_tasks(processes: List, participants: Dict) -> Dict:
    for process in processes:
        for step in process:
            if step.tag == tags['task_tag']:
                participants[process.get('id')].activities.append(step.attrib)

    return participants


def rule_string_2_dict(rule_string: str) -> Dict:
    rule_dict = {}
    if rule_string is not None:
        attrib_list = rule_string.split(';')

        for attrib in attrib_list:
            if attrib != "":
                key = attrib.split(":")[0]
                value = attrib.split(":")[1]
                rule_dict[key] = value
    return rule_dict


def set_entity_attributes(processes: List, entitys: Dict) -> Dict:
    for process in processes:
        data_object_references = []
        associations = []
        text_annotations = []

        for step in process:
            if step.tag == tags['dataObjectReference_tag']:
                data_object_references.append(step.attrib)

            elif step.tag == tags['association_tag']:
                associations.append(step.attrib)

            elif step.tag == tags['textAnnotation_tag']:
                for config in step:
                    attributes = step.attrib
                    attributes['text'] = config.text
                    text_annotations.append(attributes)

        for data_object in data_object_references:
            for association in associations:
                if data_object['id'] == association['sourceRef']:
                    for text_annotation in text_annotations:
                        if association['targetRef'] == text_annotation['id']:
                            rule_dict = rule_string_2_dict(text_annotation["text"])
                            entitys[process.attrib['id']].attributes[data_object['name']] = rule_dict
                            # print(data_object['name'])
                            # print(entitys[process.attrib['id']].attributes[data_object['name']])
            # print(data_object)
    return entitys



