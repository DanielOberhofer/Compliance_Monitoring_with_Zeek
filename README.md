# Compliance_Monitoring_with_Zeek
Download the project and use "docker-compose up" to build th eproject from directory

## Exection Guide
The prototype is executed via command line within the Zeek Docker Container. The according command can be found in the yaml under the Zeek Service.

## Overview

1. Zeek
This container includes the monitoring prototype based on Zeek. As of now it can monitor network traffic and check compliance to 27 Security Requirements of the IEC 62442. In the according functions of the Zeek script, there are place holders for specific code in the use case

2. Process Parser
The Process Parse is written in Python and takes the xml of a BPMN and transforms the data structure into a tsv file, which can be read by Zeek as an Input. It contains the following categories of Attributes: (1) Entitiy = UML-Annotations of BPMN Entitites (e.g. IP9
4. Filebeat
5. Logstash
6. Kibana
7. ELK
