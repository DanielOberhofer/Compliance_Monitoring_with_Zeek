
type comm_id: record {
    id: string;
};

type Id: record {
    ip: addr;
};

type Val_sl: record {
    sl: int;
};

# boolean attributes are NOT optional and are set to F, by the python parser, if missing in the BPMN
# &defaul is not possible, as it only work implicitly and INPUT is explicitly with optional values '-'
type Val_ent: record{
    isMonitored: bool &optional;
    isMobile: bool &optional;
    # TODO: define default value in python
    auth_attempts: int &optional;
    cert_valid:	bool &optional;
    isHuman: bool &optional;	
    isWireless: bool &optional;	
    max_package_size: int &optional;	
    security_level: int &optional;
    isUntrusted:bool &optional;
    netmask: addr &optional;
    CIDR: subnet &optional;
    isEntryPoint: bool &optional;
};

# "#fields","sender_ip","sender_port","receiver_ip","receiver_port","protocol", max_package_size', 'encrypted', 'isWireless
type Val_comm: record{
    sender_ip: addr;
    # data type port also available --> unsigned integer combiined with protocol (e.g.: 443/https)
    # foor now only as an integter. Parsing still possible
    sender_port: count;
    receiver_ip: addr;
    receiver_port: count;
    protocol: string;
    max_package_size: int &optional;
    encrypted: bool;
    isWireless: bool;
};

type Val_auth: record{
    max_auth_attempts: int;
};

type current_attempts: record{
    counter: int;
};

# known file hashes
type hash_algorithms: record{
    kind: string;
};

type session_type: record{
    counter: int &default=0;
};

# Attributes from the BPMN

global sls: table[addr] of Val_sl = table();
global entities: table[addr] of Val_ent = table();
global communications: table[string] of Val_comm = table();

# Attributes based on the BPMN input
global auth_tracker: table[addr] of current_attempts = table();
global auth_attempts: table[addr] of Val_auth = table();
global humans: set[addr] = set();
global known_protocols: set[AllAnalyzers::Tag] = set();
global available_ports: set[count] = set();


# Other Attributes necessary to check SCIs
global mobile_files_integrity: set[string] = set();
global known_file_hashes: table[string] of hash_algorithms = table();
global session_control: table[string] of session_type = table();
global p2p_protocols: set[Analyzer::Tag] = set();
global p2p_protocols_strings: set[string] = set();
global known_MIME: set[string] = set();

const interface = "en0";
const concurrent_allowed = 3;
# Function to load data with the INPUT framework
# !!!! Asynchronous task --> if this function is called it opens a new thread in the background and the script continues
# 
function load_data(){
    print("Loading BPMN attributes ...");
    Input::add_table([$source="./resources/sl.tsv", $name="sls", $idx=Id, $val=Val_sl, $destination=sls]);
    Input::remove("sls");
    Input::add_table([$source="./resources/entities.tsv", $name="entities", $idx=Id, $val=Val_ent, $destination=entities]);
    Input::remove("entities");
    Input::add_table([$source="./resources/communications.tsv", $name="comms", $idx=comm_id, $val=Val_comm, $destination=communications]);
    Input::remove("comms");
}

function load_protocols(){
    for  (c in communications){
        local sender_port = communications[c]$sender_port;
        local receiver_port = communications[c]$receiver_port;
        local missing_sender = T;
        local missing_receiver = T;
        for (a in available_ports){
            if (sender_port == a ){
                missing_sender = F;
            }
            if (receiver_port == a){
                missing_receiver = F;
            }
        }
        if (missing_sender){
            add available_ports[sender_port];
        }
        if (missing_receiver){
            add available_ports[receiver_port];
        }
    }
}
# Input is an asynchronous task. If the inout is finished this event is triggered
event Input::end_of_data(name: string, source: string) {
    print fmt("The attributes in the file: %s were succesfully loaded", name);
    # re-structure the inputted Entitites file
    if (name == "entities")
    {
       # print(entities);
        for (e in entities){
            auth_attempts[e] = [$max_auth_attempts = entities[e]$auth_attempts];
            auth_tracker[e] = [$counter = 0];
            if (entities[e]$isHuman == T){
                add humans[e];
            }
        }
    # Print statements to test the data input   
       # print(humans);
       # print(auth_attempts);
       # print(auth_tracker);
    }
    # re-structure the inputted SL file
    if (name == "sls")
    {
       print(sls);
    }

    if (name == "comms"){
        #dummy data
        load_protocols();
        # print(available_ports);
        for (c in communications){
            local protocol = to_lower(communications[c]$protocol);
            switch (protocol){
                case "dns":
                    add known_protocols[AllAnalyzers::ANALYZER_ANALYZER_DNS];
                    break;
                case "icmp":
                    add known_protocols[AllAnalyzers::ANALYZER_ANALYZER_ICMP];
                    break;
                case "modbus":
                    add known_protocols[AllAnalyzers::ANALYZER_ANALYZER_MODBUS];
                    break;
                case "mqtt":
                    add known_protocols[AllAnalyzers::ANALYZER_ANALYZER_MQTT];
                    break;
                case "http","https":
                    add known_protocols[AllAnalyzers::ANALYZER_ANALYZER_HTTP];
                    break;   
            }
        }
        # print(known_protocols);
        #print("Communications:");
        # print(communications);
    }
}

event zeek_init(){
    # This part is to test an entry for layer 2 --> remove for actual deployment
    local test: Val_ent = [$isMonitored=F,$auth_attempts=4,$cert_valid=T,$isHuman=T,$isWireless=F,$isMobile=T,$max_package_size=64,$security_level=4, $netmask=255.255.255.0, $CIDR=192.168.0.0/24, $isEntryPoint=T];
    local test_2: Val_ent = [$isMonitored=F,$auth_attempts=4,$cert_valid=T,$isHuman=T,$isWireless=F,$isMobile=T,$max_package_size=64,$security_level=3, $netmask=255.255.255.0, $CIDR=192.168.0.0/24, $isEntryPoint=F];
    entities[192.168.0.195] = test; # Testing purposes local ip
    entities[13.107.42.12] = test_2;
    sls[192.168.0.195] = [$sl = 4];
    sls[13.107.42.12] = [$sl = 3];
    # print(entities[192.168.0.195]);

    # Dummy value for known file hashes
    known_file_hashes["A4A6634125A56A8225314F7BB278DE9E0C0CA263FF15B981C8745D7C7E0BECDB"] = [$kind = "sha256"];
    known_file_hashes["9918794dbca1b23d19abb7fb69facdce8836e5bf"] = [$kind = "sha256"];
    known_file_hashes["a2e16fc09ea5295862625108b331de7cd4db310aa531d1bf7dbbce641b8da451"] = [$kind = "sha256"];
    known_file_hashes["b23fec5f2fe574546bdf4f373fdcfd18"] = [$kind = "sha256"];
    known_file_hashes["2f2877c5d778c31e0f29c7e371df5471bd673173"] = [$kind = "sha256"];
    known_file_hashes["24c7299864e0a2a6964f551c0e8df2461532fa8c48e4dbbb6080716691f190e5"] = [$kind = "sha256"];
    known_file_hashes["034a87db65e8da107be0f3a51b88d92078fe0721"] = [$kind = "sha256"];
    known_file_hashes["505e7f541eb2ddb7329182c81a23cf040b788b4a1e1ce9b281f69e15e6e3b5ad"] = [$kind = "sha256"];
    known_file_hashes["c0b7fca6f41f3fd930548c6f627f37f2"] = [$kind = "sha256"];
    known_file_hashes["e7eea674ca718e3befd90858e09f8372ad0ae2aa"] = [$kind = "sha256"];
    known_file_hashes["d092a8f830b43b2692acd6ea8b0b1646"] = [$kind = "sha256"];

    # p2p protocols
    add p2p_protocols[Analyzer::ANALYZER_HTTP];
    add p2p_protocols[Analyzer::ANALYZER_POP3];
    add p2p_protocols[Analyzer::ANALYZER_IMAP];
    add p2p_protocols[Analyzer::ANALYZER_DNS];

    add p2p_protocols_strings["HTTP"];
    add p2p_protocols_strings["POP3"];
    add p2p_protocols_strings["IMAP"];
    add p2p_protocols_strings["DNS"];

    add known_MIME["application/xml"];
    add known_MIME["text/html"];
    # add known_MIME["application/ocsp-response"];

}
