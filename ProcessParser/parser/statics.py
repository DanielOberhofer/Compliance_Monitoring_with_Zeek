namespaces = {'bpmn': "http://www.omg.org/spec/BPMN/20100524/MODEL"}
source = "./input/input.xml"
# Hier werden die namespaces von xml als static strings hinterlegt um sie im parser zu verwenden
tags = {
    'participant_tag': '{'+namespaces["bpmn"]+'}participant',
    'messageflow_tag': '{'+namespaces["bpmn"]+'}messageFlow',
    'task_tag': '{'+namespaces["bpmn"]+'}task',
    'dataObject_tag': '{'+namespaces["bpmn"]+'}dataObject',
    'dataObjectReference_tag': '{'+namespaces["bpmn"]+'}dataObjectReference',
    'association_tag': '{'+namespaces["bpmn"]+'}association',
    'textAnnotation_tag': '{'+namespaces["bpmn"]+'}textAnnotation',

}
