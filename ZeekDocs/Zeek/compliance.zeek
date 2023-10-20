@load base/frameworks/notice
@load base/frameworks/input
@load policy/tuning/json-logs.zeek
@load ./data.zeek
@load ./sci_check.zeek
@load ./layer2_log.zeek
@load ./layer1_log.zeek
# Reihenfolge: 1. compliance -> 2. data -> 3. fr1
# dh der entitiy INhalt kann nicht in init angesprochen werden



# /opt/homebrew/Cellar/zeek/
# /USers/dan/Dokumente_local/Zeek_dev
# sudo zeek -i en0 compliance.zeek
# sudo zeek -i <interface> compliance.zeek

global log_layer2: event(rec: SecondLog::Info);
redef Log::default_logdir = "./compliancelogs/";


# ---------
# variable contatining the max auth attempts for each connection

# ------------------------------------------------------------------------------------
# Main Event: Handles the event generated with every newly detected connection
# ------------------------------------------------------------------------------------
event new_connection(c: connection){
    local msg = fmt("IP address %s was detected as the sender with protocol", c$id$orig_h);
    # print(msg);
    local layer_one = check_layer_one(c);
    # print fmt("ENCRYPTED? %s", c$id$orig_h);
    if (layer_one){
        check_SCI_1(c$id$orig_h,c$id$resp_h);
        check_SCI_5(c$id$orig_h,c$id$resp_h);
        local rec: FirstLog::Info = [$ts=network_time(), $id=c$id];
        Log::write(FirstLog::LOG, rec);

    } else {
        # print fmt ("%s --> %s; Detailed Compliance Analysis required",c$id$orig_h,c$id$resp_h);
        
        local sec_rec: SecondLog::Info = [$ts=network_time(), $id=c$id];
        # Loggin connection after the first whitelisting layer
        Log::write(SecondLog::LOG, sec_rec);
        Log::create_stream(SecondLog::LOG, [$columns=FirstLog::Info,$ev=log_layer2]);
    }
}

# ------------------------------------------------------------------------------------
# CUSTOM event triggered in the main event if the connection passes the first compliance layer
# ------------------------------------------------------------------------------------
event log_layer2(rec: SecondLog::Info){
    print("Detailed Compliance Analysis undergoing with other events");
    local c = lookup_connection(rec$id);
    if (c$id$orig_h in entities && c$id$resp_h in entities){
        check_SCI_17(c);
    }
    check_SCI_19(c);
    # This place can be used to start the functions of the sci_check module if no other event is more capable    
}

# ------------------------------------------------------------------------------------
# Internal events
# ------------------------------------------------------------------------------------
event zeek_init()
{
    # Nur notwendig wenn dummy Daten aus Pcap files geladen werden sollen
    # Load the input pcap file - Dummy data for the prototype - Could be changed to default zeek monitoring logs
    print("Use this space to load a pcap file for network analysis");
    load_data(); # Asynchronous task --> Data is loaded after a while
    # disable_logs();
}

event zeek_script_loaded(p: string, level: count){
        local path_main = "./compliance.zeek";
        local path_data = "./data.zeek";
        local path_fr1 = "./FR1_IAC.zeek";

        if (p == path_main || p == path_data || p == path_fr1)
            print fmt("The Script %s was loaded", p);
    
}

event zeek_done()
{
    print("Zeek was shut down!");
    print("Hava a nice Day!!");
}

# ------------------------------------------------------------------------------------
# EVENT Handlers for different event in addition to the compliance layers
# ------------------------------------------------------------------------------------

# Zeek first logs the connection and then second (in the background) analyzes the connection for the protocol
# This event is generated after a protocol was analysed and identified
event analyzer_confirmation_info(atype: AllAnalyzers::Tag, info: AnalyzerConfirmationInfo){
       local unknown = T;  
       for (p in known_protocols){
            if (p == atype){unknown = F;}
       }
       if(unknown){
        print fmt("Compliance Mismatch with SCI 6: Usage of unexpected protocol: %s", atype);
        }
        local c = info$c;
        if (atype in p2p_protocols){
            check_SCI_18(info);
        }
        # print(c$service);
        # print(c$Layer1);
}
# Event generated if the protocol cannot be identified by the Analyzer
event unknown_protocol(analyzer_name: string, protocol: count, first_bytes: string){
    
    print fmt("Compliance Mismatch with SCI 6: Usage of unexpected protocol: %s", analyzer_name);
    # print fmt("Analyzer name: %s; Protocol: %s; First bytes: %s", analyzer_name, protocol, first_bytes);
}

event ssl_server_hello(c: connection, version: count, record_version: count, possible_ts: time, server_random: string, session_id: string, cipher: count, comp_method: count){
    for ( e in entities){
        if (e == c$id$orig_h){
            check_SCI_16(c, cipher);
        }
    }
}

event ssl_change_cipher_spec(c: connection, is_client: bool){
    check_SCI_13_15(c);
    check_SCI_10(c);
}   


# Event used for SCI 3 - PKI Authentication
event x509_certificate(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate){

    # cert is ein record(Leads: issuer string, subject string, not_valid_after time, key_alg, sig_alg, key_length)
    check_SCI_2_x509(cert);

}
event connection_attempt(c: connection){
    local unknown = T;
    local sender = c$id$orig_h;
    for( e in entities){
        if(e == sender){
             auth_tracker[sender]$counter = ($counter = auth_tracker[sender]$counter + 1);
             unknown = F;
             check_SCI_3(sender);
        }
    }    
    if (unknown){
        print("Compliance Mismatch with SCI4: Unknown entitity exceeded auth attempts");
    }  
}

event connection_rejected(c: connection){
    local sender = c$id$orig_h;
    local unknown = T;
    for( e in entities){
        if(e == sender){
             auth_tracker[sender]$counter = ($counter = auth_tracker[sender]$counter + 1);
             unknown = F;
             # SCI 3: Auth attemps
             check_SCI_3(sender);
             # SCI 9: Non repudidation
             check_SCI_8_9(c);
        }
    }    
    if (unknown){
        print("Compliance Mismatch with SCI4: Unknown entitity exceeded auth attempts");
    }   
}

# Event is generated when a connetion terminates and endpoint statistics are generated
# Potentially useful
event conn_stats(c: connection, os: endpoint_stats, rs: endpoint_stats){
   check_SCI_19(c);

}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool){
        local sl = get_sl(c);
        local ip = c$id$orig_h;
        local isMobile = F;
    local unknown_entity = T;
        for (e in entities){
            if (e == ip){
                isMobile = entities[e]$isMobile;
                unknown_entity = F;
            }
        }
        if (isMobile && unknown_entity){
            check_SCI_6(f, c);
        }else{
            if (isMobile && (sl > 2)){
            add mobile_files_integrity[f$id];
            }
        } 
}

event file_state_remove(f: fa_file){  
    if(f ?$ info){
        if( "X509" !in f$info$analyzers){
           
          
        }
    }
}
# used for the integrity check of SL > 2 mobile files
event file_hash(f: fa_file, kind: string, hash: string){
    for(fi in mobile_files_integrity){
        # Check if the file was previously defined as mandatory to check for integrity
        if (f$id == fi){
            check_SCI_6_integrity(f, hash, kind);
        }
    }
    
}

# Another possible event for malicious code protection (In this case based on MIME type discovery)
event file_sniff(f: fa_file, meta: fa_metadata){
    local sender: addr;
    local receiver: addr;

    if (f ?$ conns){
        for (i in f$conns){
            local con = f$conns[i];
 
            if(con$id$orig_h in entities){
                local ip = con$id$orig_h;
                local entryPoint = entities[ip]$isEntryPoint;
                if (entryPoint){
                    if(meta ?$ mime_type){
                        check_SCI_11(meta$mime_type);
                     }
                }
            } 
    }  
}}

event connection_reused(c: connection){
    # used for concurrent sessions
    check_SCI_7(c);
    local sl = get_sl(c);
    if (sl >= 3){
        check_SCI_12(c);
    }
    print("Connection reused");
}
