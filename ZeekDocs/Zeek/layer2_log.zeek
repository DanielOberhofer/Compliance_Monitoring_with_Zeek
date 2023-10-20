module SecondLog;
export {
    # Create an ID for our new stream. By convention, this is
    # called "LOG".
    redef enum Log::ID += { LOG };

    # Define the record type that will contain the data to log.
    type Info: record {
        ts: time        &log;
        id: conn_id     &log;
        service: string &log &optional;
        missed_bytes: count &log &default=0;
    };
}


# This event is handled at a priority higher than zero so that if
# users modify this stream in another script, they can do so at the
# default priority of zero.
event zeek_init() &priority=5
    {
    # Create the stream. This adds a default filter automatically.
    Log::create_stream(SecondLog::LOG, [$columns=Info, $path="./second_layer"]);
    }

