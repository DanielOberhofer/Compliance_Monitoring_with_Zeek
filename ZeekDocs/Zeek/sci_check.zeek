@load ./layer2_log.zeek
@load ./data.zeek

type Val_ent: record{
    isMonitored: bool &optional;
    isMobile: bool &optional;
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
type entity_type: table[addr] of Val_ent;

# ------------------------------------------
# Misc functions to achieve code modularity

function get_sl (c: connection): int{
    local sl_s: int;
    local sl_r: int;
    local unknown_s = T;
    local unknown_r = T;
    for (e in sls){
        if (e == c$id$orig_h){
            sl_s = sls[e]$sl;
            unknown_s = F;
        }
        if (e == c$id$resp_h){
            sl_r = sls[e]$sl;
            unknown_r = F;
        }
    }
    if (unknown_s){
        sl_s = 0;
    }
    if (unknown_r){
        sl_r = 0;
    }
    if (sl_s >= sl_r){
        return sl_s;
    }else{
        return sl_r;
    }
   
}

function check_human(ip: addr): bool{
    local human = F;
    for( e in humans){
        if (e == ip){
            human =T;
        }
    }
    return human;

}

function check_untrusted(c: connection): bool{
    for (e in entities){
        if (e == c$id$orig_h || e == c$id$resp_h){
            if ( entities[e] ?$ isUntrusted){
                return entities[e]$isUntrusted;
        }
        else{
            return F;
        }}
    }
    return F;
}
# ------------------------------------------
# FR 1: IAC of Users

# SCI 1 and SCI 6: Foundational compliance check against FR 1/2
function check_layer_one(c: connection): bool{
    local identitiy_mismatch = T;
    # Check if the communication kombination is compliant with FR1 and FR2
    if (c$id$orig_h in entities || c$id$resp_h in entities ){
        identitiy_mismatch = F;
    }
    
    return identitiy_mismatch;
}

# Foundational Mismatch with FR 1: IAC for Users
function check_SCI_1(s: addr, r: addr){
    #print fmt("%s --> %s; Foundational Compliance mismatch with FR1: Unknown Entity Authenticated!", s,r);
    print("Compliance Mismatch with SCI 1: Foundational Mismatch with FR1: Unknown Entity Authenticated!");
    print fmt("%s ----> %s",s,r);
}

function check_SCI_2(s: addr){
    print fmt("Certificate based authentication demanded by %s",s );
}

# Check x509 certificates in acordance to SCI3
function check_SCI_2_x509(cert: X509::Certificate){
    local issuer = cert$issuer;
    local key_alg = cert$key_alg;
    local sig_alg = cert$sig_alg;
    local start = cert$not_valid_before;
    local expire = cert$not_valid_after;
    local certificate_detected = T;
    # At this place the certificate can be checked for example if the cert is valid at this time
    print("Certificate was detected and is compliant with SCI 2: Certificate valid");
    # print fmt("Issuer: %s; Key-Algo: %s; Sig-Algo: %s; Valid: %s <--> %s.",issuer,key_alg,sig_alg,start,expire);
}

# Unsuccessful login threshold
function check_SCI_3(s: addr){
    if (auth_tracker[s]$counter >= auth_attempts[s]$max_auth_attempts){
        print fmt("Compliance Mismatch with SCI 3: Max Authentication attempts exceeded by %s", s);
        auth_tracker[s]$counter = 0;
    }

}

# Access Control from untrusted networks
function check_SCI_4(c: connection){
    local sender_known = F;
    local receiver_known = F;
    local untrusted_s = F;
    local untrusted_r = F;
    local sl = get_sl(c);
    for (e in entities){
        if (e == c$id$orig_h){
            sender_known = T;
            untrusted_s = entities[e]$isUntrusted;
        }
        if (e == c$id$resp_h){
            receiver_known = T;
            untrusted_r = entities[e]$isUntrusted;
        }
    }
    if ((untrusted_s || untrusted_r) && sl > 2){
        local known_comm = F;
        local c_port_s = port_to_count(c$id$orig_p);
        local c_port_r = port_to_count(c$id$resp_p);
        for (com in communications){
            if((c$id$orig_h == communications[com]$sender_ip) && (c$id$resp_h == communications[com]$receiver_ip) && (c_port_s == communications[com]$sender_port) && (c_port_r == communications[com]$receiver_port)){
                known_comm = T;
            }
        }
        if(known_comm == F){
            print("Compliance Mismatch with SCI 4: Explicit access requests necessary for untrusted networks");
            print fmt(" -----> Communication unexpected with an entitiy in untrusted networks");
        }
    }
}


# ------------------------------------------
# FR 2: Use Control

function check_SCI_5(s: addr, r: addr){
    # print fmt("Compliance Mismatch with SCI 6: %s --> %s;",s,r);
    print("Compliance Mismatch with SCI 5: Foundational Mismatch with FR2: Misuesed Entity Rights");
    print fmt("%s ----> %s",s,r);
}

# Control and Restriction of Mobile Code
function check_SCI_6(f: fa_file, c: connection) {
    print("Compliance Mismatch with SCI 6: Missing control over mobile Code");
    print fmt(" ----->  Mobile Code origin: %s;", c$id$orig_h);
}

function check_SCI_6_integrity(f: fa_file, h: string, k: string){
    local integrity_mismatch = T;
    for (k in known_file_hashes){
        if (k == h){
            integrity_mismatch = F;
        }
    }
    if (integrity_mismatch){
        print("Compliance Mismatch with SCI 6 - RE1: Integrity check for mobile code");
        print fmt(" -----> File: %s from: %s; Hash: %s", f$id, f$source, h);
    }
}

# Session control of Concurrent and remote sessions
function check_SCI_7(c: connection){
    session_control[c$uid] = [$counter = (session_control[c$uid]$counter + 1) ];
    if (session_control[c$uid]$counter > concurrent_allowed){
        print("Compliance Mismatch with SCI 7: Too many concurrent Sessions");
        print fmt(" -----> In Connection: %s:%s --> %s:%s", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
    }

}

function check_SCI_8_9(c: connection) {
    local sl = get_sl(c);
    local isHuman = check_human(c$id$orig_h);
    if (sl == 3 && isHuman){
        print("Compliance Mismatch with SCI 8: Non-repudiation of Human Users missing");
        # print fmt("%s ----> %s",c$id$orig_h,c$id$resp_h);
    }
    if (sl == 4){
        print("Compliance Mismatch with SCI 8 and SCI 9: Non-repudiation of Users missing");
        print fmt("%s ----> %s",c$id$orig_h,c$id$resp_h);
    }
}


# ------------------------------------------
# FR 3: Integrity

# Cryptographic Integrity Protection
function check_SCI_10(c: connection){
    local sl = get_sl(c);
    if (sl > 2){
        print("Compiant to SCI 10: Integrity Protection with TLS/SSL");
    }
}

# Malicious Code Protection on Entry-Points
# https://de.wikipedia.org/wiki/Internet_Media_Type
function check_SCI_11(m: string) {
    if (m != "application/x-x509-user-cert" && m != "application/x-x509-ca-cert"){
        if (m !in known_MIME){
                print("Compliance Mismatch with SCI 11: Potentially Malicious Code over Entry Point");
                print fmt(" -----> %s", m);
            }
    }
}

# Uniquness of Sessions of SL 3+
function check_SCI_12(c: connection) {
    local sl = get_sl(c);
    if (sl > 2){
        print("Protocol specific Session ID investigations necessary");
    }
    # Possible e.g. based on the MQTT protocol
    # if mqtt detected --> check session id and add to set. if in set than not unique. If sessions exceed threshold delete set

}

# ------------------------------------------
# FR 4: data confidentiality

# Protection in explicit cases + untrusted + zone boundaries
function check_SCI_13_15(c: connection) {
    # final compliance attributes
    local known_comm = F;
    local encryption_mandatory = F;
    local untrusted = check_untrusted(c);
    local sl = get_sl(c);
    for (comm in communications){
        if (communications[comm]$sender_ip == c$id$orig_h){
            if (communications[comm]$receiver_ip == c$id$resp_h){
                    known_comm = T;
                    encryption_mandatory = communications[comm]$encrypted;
                    if (sl > 3){
                        print("Compliant with SCI 15,14,13: Connection encrypted");
                    }else {
                        if (sl > 1){
                            if (untrusted){
                                print("Compliant with SCI 14,13: Encryption of untrusted networks");
                            }
                        }
                    }
                    if (sl == 1){
                        if (encryption_mandatory){
                            print("Compliant with SCI 13: Mandatory encryption detected");
                        }}}}}}

# State of the art crypto used
function check_SCI_16(c: connection, cipher_numb: count) {
    local cipher = SSL::cipher_desc[cipher_numb];
    print fmt("Compliant to SCI 16 with Algo: %s", cipher ); 
}

# ------------------------------------------
# FR 5: Restricted Data Flow

function check_SCI_17(c: connection) {
    local sl = get_sl(c);
    local sender = entities[c$id$orig_h];
    local receiver = entities[c$id$resp_h];
    print fmt("SCI 17 is getting checked: %s --> %s",c$id$orig_h, c$id$resp_h );
    if (sl== 4){
        if ((c$id$orig_h in receiver$CIDR)||(c$id$resp_h in sender$CIDR)){
            print("Compliance Mismatch with SCI 17: Logical Network  Separation required");
            print fmt(" -------> Sender: %s - Mismatch -  Receiver: %s",sender$CIDR,receiver$CIDR );
        }
    }
}

function check_SCI_18(info: AnalyzerConfirmationInfo) {
    local con = info$c;
    local sl = get_sl(con);
    local p2p = F;
    if((con$id$orig_h in humans) || (con$id$resp_h in humans) ){
         p2p = T;
    }
    if(p2p && (sl >= 3)){
        for(p in p2p_protocols_strings){
            if (p in con$service){
                print("Compliance Mismatch with SCI 18: P2P communications must be perhibited");
                print fmt(" -----> %s verwendet %s",con$id$orig_h, con$service);
        }
        }
        
    }
}

# ------------------------------------------
# FR 7: Resource availability
# Checking if ports are open 
function check_SCI_19(c: connection) {
    local sender_port = port_to_count(c$id$orig_p);
    local receiver_port = port_to_count(c$id$resp_p);
    local mismatch_s = T;
    local mismatch_r = T;

    for (p in available_ports){
        if (sender_port == p){
            mismatch_s = F;
        }
        if (receiver_port == p){
            mismatch_r = F;
        }
    }
    if (mismatch_s && mismatch_r){
        print fmt("Compliance Mismatch with SCI 19: Undefined ports used %s, %s", sender_port, receiver_port);
    } else {
        if (mismatch_s){
            print fmt("Compliance Mismatch with SCI 19: Undefined ports used %s", sender_port);
        } else {
            if (mismatch_r){
                print fmt("Compliance Mismatch with SCI 19: Undefined ports used %s", receiver_port);
            }}}}




