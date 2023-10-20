#! /bin/env python3
import csv
from typing import List, Dict


def communication_booleans(connections: List):
    boolean_attributes = []
    for c in connections:
        for ca in c.attributes:
            if c.attributes[ca].lower() == 'f' or c.attributes[ca].lower() == 't' or \
                    c.attributes[ca].lower() == 'false'\
                    or c.attributes[ca].lower() == 'true':
                if ca not in boolean_attributes:
                    boolean_attributes.append(ca)
    # print(boolean_attributes)
    return boolean_attributes


# Necessayr as Zeek cannot handle &optioanl values well ---> no try catch or vallue.isset function as of now
def entity_booleans(entities: Dict):
    boolean_attributes = []
    for e in entities:
        for a in entities[e].attributes:
            if type(entities[e].attributes[a]) is dict:
                for ic in entities[e].attributes[a]:
                    if entities[e].attributes[a][ic].lower() == 'f' or entities[e].attributes[a][ic].lower() == 't' \
                        or entities[e].attributes[a][ic].lower() == 'false' \
                            or entities[e].attributes[a][ic].lower() == 'true':
                        if ic not in boolean_attributes:
                            boolean_attributes.append(ic)
            else:
                if entities[e].attributes[a] == 'F' or entities[e].attributes[a] == 'T':
                    if a not in boolean_attributes:
                        boolean_attributes.append(a)
    # print(boolean_attributes)
    return boolean_attributes


def write_security_lvl_file(entities: Dict):
    with open('./output_tsv/sl.tsv', 'w', newline='') as tsvfile:
        writer = csv.writer(tsvfile, delimiter='\t', lineterminator='\n')
        writer.writerow(['#fields', "ip", "sl"])
        print("#fields ip sl")
        for x in entities:
            writer.writerow([entities[x].attributes["ip"], entities[x].attributes["security_level"]])
            print(entities[x].attributes["ip"] + ", " + entities[x].attributes["security_level"])


# sender_ip, receiver_ip, protocol, max_package size, encrypted, sender_prt, receiver prt
def write_communications_file(connections: List):
    header = ["#fields","id","sender_ip","sender_port","receiver_ip","receiver_port","protocol"]
    for c in connections:
        for ca in c.attributes:
            if ca not in header:
                header.append(ca)
    print(header)
    booleans = communication_booleans(connections)
    with open('./output_tsv/communications.tsv', 'w', newline='') as tsvfile:
    #with open('/USers/dan/Dokumente_local/Zeek_dev/resources/communications.tsv', 'w', newline='') as tsvfile:
        writer = csv.writer(tsvfile, delimiter='\t', lineterminator='\n')
        writer.writerow(header)
        for c in connections:
            output = []
            try:
                output = [c.id, c.sender.attributes["ip"], c.attributes["sender_port"],
                      c.receiver.attributes["ip"], c.attributes["receiver_port"], c.attributes["protocol"]]
            except KeyError:
                print('Mandatory attributes missing for the connection in between: ' + c.sender.attributes["ip"] +
                      ' --> ' + c.receiver.attributes["ip"])

            for h in header[7:]:
                if h in c.attributes:
                    if h in booleans:
                        if c.attributes[h].lower() == 'true' or c.attributes[h].lower() == 't':
                            output.append('T')
                        else:
                            output.append('F')
                    else:
                        output.append(c.attributes[h])
                else:
                    if h in booleans:
                        output.append('F')
                    else:
                        output.append('-')
            writer.writerow(output)
            print(output)


def calculate_subnet_net_address(entity: Dict):
    subnet = ''
    ip = ''
    for a in entity.attributes:
        if a == "netmask":
            subnet = entity.attributes["netmask"]
        if a == "ip":
            ip = entity.attributes["ip"]

    # Convert the subnet mask to a binary string
    subnet_mask_binary = ''.join(format(int(x), '08b') for x in subnet.split('.'))

    # Convert the IP address to a binary string
    ip_address_binary = ''.join(format(int(x), '08b') for x in ip.split('.'))

    # Calculate the network address by performing bitwise AND operation
    network_address_binary = ''.join(str(int(a) & int(b)) for a, b in zip(subnet_mask_binary, ip_address_binary))

    # Convert the network address back to IPv4 format
    network_address = '.'.join(str(int(network_address_binary[i:i + 8], 2)) for i in range(0, 32, 8))

    # Determine the CIDR notation by counting the number of set bits in the subnet mask
    cidr = sum(1 for bit in subnet_mask_binary if bit == '1')
    return f'{network_address}/{cidr}'


def write_entities_attributes_file(entities: Dict):
    header = ["#fields"]
    for e in entities:
        for a in entities[e].attributes:
            if type(entities[e].attributes[a]) is dict:
                for ic in entities[e].attributes[a]:
                    if ic.strip() not in header:
                        header.append(ic)
            else:
                if a.strip() not in header:
                    header.append(a)
    header.append("CIDR")
    boolean_fields = entity_booleans(entities)
    print(header)
    with open('./output_tsv/entities.tsv', 'w', newline='') as tsvfile:
    # with open('/USers/dan/Dokumente_local/Zeek_dev/resources/entities.tsv', 'w', newline='') as tsvfile:
        writer = csv.writer(tsvfile, delimiter='\t', lineterminator='\n')
        writer.writerow(header)

        for e in entities:
            attributes = []
            for h in header[1:]:
                if h in entities[e].attributes:
                    attributes.append(entities[e].attributes[h])
                else:
                    missing = True
                    for a in entities[e].attributes:
                        if type(entities[e].attributes[a]) is dict:
                            if h in entities[e].attributes[a]:
                                attributes.append(entities[e].attributes[a][h])
                                missing = False
                    if missing:
                        if h in boolean_fields:
                            attributes.append('F')
                        else:
                            if h != 'CIDR':
                                attributes.append('-')
            cidr = calculate_subnet_net_address(entities[e])
            attributes.append(cidr)
            writer.writerow(attributes)
            print(attributes)

