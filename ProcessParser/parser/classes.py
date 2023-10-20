from dataclasses import dataclass, field


@dataclass
class Entity:
    id: str
    name: str
    processRef: str
    activities: list = field(default_factory=list)
    attributes: dict = field(default_factory=dict)


@dataclass
class MessageFlow:
    id: str
    name: str
    sourceRef: str
    targetRef: str


@dataclass
class Process:
    id: str
    isExecutable:  bool


@dataclass
class Connection:
    id: str
    sender: Entity
    receiver: Entity
    attributes: dict


@dataclass
class DataObject:
    id: str
    name: str
    dataObjectRef: str
    values: list = field(default_factory=list)


@dataclass
class Network_Rule:
    id: str
    sci: str
    action: str
    protocol: str
    src: str
    src_prt: str
    dst: str
    dst_prt: str
    options: dict