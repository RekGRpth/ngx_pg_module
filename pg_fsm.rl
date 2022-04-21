#include "pg_fsm.h"
#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"

typedef struct pg_fsm_t {
    const uint8_t *string;
    uint16_t cs;
    uint16_t data_row_count;
    uint16_t int2;
    uint16_t row_description_count;
    uint32_t int4;
    uint32_t result_len;
    uint8_t i;
} pg_fsm_t;

%%{
    machine pg_fsm;
    access fsm->;
    alphtype unsigned char;

    action all { if (cb->all(user, 0, p)) fbreak; }
    action authentication_ok { if (cb->authentication_ok(user)) fbreak; }
    action backend_key_data { if (cb->backend_key_data(user)) fbreak; }
    action backend_key_data_key { if (cb->backend_key_data_key(user, fsm->int4)) fbreak; }
    action backend_key_data_pid { if (cb->backend_key_data_pid(user, fsm->int4)) fbreak; }
    action bind_complete { if (cb->bind_complete(user)) fbreak; }
    action close_complete { if (cb->close_complete(user)) fbreak; }
    action command_complete { if (cb->command_complete(user, fsm->int4 - 4)) fbreak; }
    action command_complete_val { if (fsm->string && p - fsm->string > 0 && cb->command_complete_val(user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action copy_data { fsm->result_len = fsm->int4 - 4; if (cb->copy_data(user, fsm->result_len)) fbreak; }
    action copy_done { if (cb->copy_done(user)) fbreak; }
    action copy_out_response { if (cb->copy_out_response(user, fsm->int4 - 4)) fbreak; }
    action data_row_count { fsm->data_row_count = fsm->int2; if (cb->data_row_count(user, fsm->data_row_count)) fbreak; if (!fsm->data_row_count) fnext main; }
    action data_row { if (cb->data_row(user, fsm->int4 - 4)) fbreak; }
    action empty_query_response { if (cb->empty_query_response(user)) fbreak; }
    action error_response_column { if (fsm->string && p - fsm->string > 0 && cb->error_response_column(user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action error_response_constraint { if (fsm->string && p - fsm->string > 0 && cb->error_response_constraint(user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action error_response_context { if (fsm->string && p - fsm->string > 0 && cb->error_response_context(user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action error_response_datatype { if (fsm->string && p - fsm->string > 0 && cb->error_response_datatype(user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action error_response_detail { if (fsm->string && p - fsm->string > 0 && cb->error_response_detail(user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action error_response_file { if (fsm->string && p - fsm->string > 0 && cb->error_response_file(user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action error_response_function { if (fsm->string && p - fsm->string > 0 && cb->error_response_function(user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action error_response_hint { if (fsm->string && p - fsm->string > 0 && cb->error_response_hint(user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action error_response { if (cb->error_response(user, fsm->int4 - 4)) fbreak; }
    action error_response_internal { if (fsm->string && p - fsm->string > 0 && cb->error_response_internal(user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action error_response_line { if (fsm->string && p - fsm->string > 0 && cb->error_response_line(user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action error_response_nonlocalized { if (fsm->string && p - fsm->string > 0 && cb->error_response_nonlocalized(user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action error_response_primary { if (fsm->string && p - fsm->string > 0 && cb->error_response_primary(user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action error_response_query { if (fsm->string && p - fsm->string > 0 && cb->error_response_query(user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action error_response_schema { if (fsm->string && p - fsm->string > 0 && cb->error_response_schema(user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action error_response_severity { if (fsm->string && p - fsm->string > 0 && cb->error_response_severity(user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action error_response_sqlstate { if (fsm->string && p - fsm->string > 0 && cb->error_response_sqlstate(user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action error_response_statement { if (fsm->string && p - fsm->string > 0 && cb->error_response_statement(user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action error_response_table { if (fsm->string && p - fsm->string > 0 && cb->error_response_table(user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action function_call_response { if (cb->function_call_response(user, fsm->int4 - 4)) fbreak; }
    action int2 { if (!fsm->i) { fsm->i = sizeof(fsm->int2); fsm->int2 = 0; } fsm->int2 |= *p << ((2 << 2) * --fsm->i); }
    action int4 { if (!fsm->i) { fsm->i = sizeof(fsm->int4); fsm->int4 = 0; } fsm->int4 |= *p << ((2 << 2) * --fsm->i); }
    action no_data { if (cb->no_data(user)) fbreak; }
    action notice_response { if (cb->notice_response(user, fsm->int4 - 4)) fbreak; }
    action notification_response_extra { if (fsm->string && p - fsm->string > 0 && cb->notification_response_extra(user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; if (p != eof) if (cb->notification_response_done(user)) fbreak; }
    action notification_response { if (cb->notification_response(user, fsm->int4 - 4)) fbreak; }
    action notification_response_pid { if (cb->notification_response_pid(user, fsm->int4)) fbreak; }
    action notification_response_relname { if (fsm->string && p - fsm->string > 0 && cb->notification_response_relname(user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action parameter_status_application_name { if (fsm->string && p - fsm->string > 0 && cb->parameter_status_application_name(user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action parameter_status_client_encoding { if (fsm->string && p - fsm->string > 0 && cb->parameter_status_client_encoding(user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action parameter_status_datestyle { if (fsm->string && p - fsm->string > 0 && cb->parameter_status_datestyle(user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action parameter_status_default_transaction_read_only { if (fsm->string && p - fsm->string > 0 && cb->parameter_status_default_transaction_read_only(user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action parameter_status { if (cb->parameter_status(user, fsm->int4 - 4)) fbreak; }
    action parameter_status_in_hot_standby { if (fsm->string && p - fsm->string > 0 && cb->parameter_status_in_hot_standby(user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action parameter_status_integer_datetimes { if (fsm->string && p - fsm->string > 0 && cb->parameter_status_integer_datetimes(user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action parameter_status_intervalstyle { if (fsm->string && p - fsm->string > 0 && cb->parameter_status_intervalstyle(user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action parameter_status_is_superuser { if (fsm->string && p - fsm->string > 0 && cb->parameter_status_is_superuser(user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action parameter_status_server_encoding { if (fsm->string && p - fsm->string > 0 && cb->parameter_status_server_encoding(user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action parameter_status_server_version { if (fsm->string && p - fsm->string > 0 && cb->parameter_status_server_version(user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action parameter_status_session_authorization { if (fsm->string && p - fsm->string > 0 && cb->parameter_status_session_authorization(user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action parameter_status_standard_conforming_strings { if (fsm->string && p - fsm->string > 0 && cb->parameter_status_standard_conforming_strings(user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action parameter_status_timezone { if (fsm->string && p - fsm->string > 0 && cb->parameter_status_timezone(user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action parse_complete { if (cb->parse_complete(user)) fbreak; }
    action ready_for_query_idle { if (cb->ready_for_query_state(user, pg_ready_for_query_state_idle)) fbreak; }
    action ready_for_query { if (cb->ready_for_query(user)) fbreak; }
    action ready_for_query_inerror { if (cb->ready_for_query_state(user, pg_ready_for_query_state_inerror)) fbreak; }
    action ready_for_query_intrans { if (cb->ready_for_query_state(user, pg_ready_for_query_state_intrans)) fbreak; }
    action result_len { fsm->result_len = fsm->int4; if (cb->result_len(user, fsm->result_len)) fbreak; if (!fsm->result_len || fsm->result_len == (uint32_t)-1) { if (!fsm->data_row_count || !--fsm->data_row_count) fnext main; else fnext data_row; } }
    action result_val { if (p == eof || !fsm->result_len--) { if (fsm->string && p - fsm->string > 0 && cb->result_val(user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; if (fsm->result_len == (uint32_t)-1) { if (cb->result_done(user)) fbreak; fhold; if (!fsm->data_row_count || !--fsm->data_row_count) fnext main; else fnext data_row; } } }
    action row_description_beg { if (cb->row_description_beg(user)) fbreak; }
    action row_description_column { if (cb->row_description_column(user, fsm->int2)) fbreak; }
    action row_description_count { fsm->row_description_count = fsm->int2; if (cb->row_description_count(user, fsm->row_description_count)) fbreak; if (!fsm->row_description_count) fnext main; }
    action row_description_format { if (cb->row_description_format(user, 0)) fbreak; if (!--fsm->row_description_count) fnext main; else fnext row_description; }
    action row_description { if (cb->row_description(user, fsm->int4 - 4)) fbreak; }
    action row_description_length { if (cb->row_description_length(user, fsm->int2)) fbreak; }
    action row_description_mod { if (cb->row_description_mod(user, fsm->int4)) fbreak; }
    action row_description_name { if (fsm->string && p - fsm->string > 0 && cb->row_description_name(user, p - fsm->string, fsm->string)) fbreak; fsm->string = NULL; }
    action row_description_oid { if (cb->row_description_oid(user, fsm->int4)) fbreak; }
    action row_description_table { if (cb->row_description_table(user, fsm->int4)) fbreak; }
    action string { if (!fsm->string) fsm->string = p; }

    char = any - 0;
    int2 = any{2} $int2;
    int4 = any{4} $int4;
    str0 = char * $string 0;

    error_response =
    ( "c" str0 @error_response_column @/error_response_column
    | "C" str0 @error_response_sqlstate @/error_response_sqlstate
    | "d" str0 @error_response_datatype @/error_response_datatype
    | "D" str0 @error_response_detail @/error_response_detail
    | "F" str0 @error_response_file @/error_response_file
    | "H" str0 @error_response_hint @/error_response_hint
    | "L" str0 @error_response_line @/error_response_line
    | "M" str0 @error_response_primary @/error_response_primary
    | "n" str0 @error_response_constraint @/error_response_constraint
    | "p" str0 @error_response_internal @/error_response_internal
    | "P" str0 @error_response_statement @/error_response_statement
    | "q" str0 @error_response_query @/error_response_query
    | "R" str0 @error_response_function @/error_response_function
    | "s" str0 @error_response_schema @/error_response_schema
    | "S" str0 @error_response_severity @/error_response_severity
    | "t" str0 @error_response_table @/error_response_table
    | "V" str0 @error_response_nonlocalized @/error_response_nonlocalized
    | "W" str0 @error_response_context @/error_response_context
    );

    parameter_status =
    ( "application_name" 0 str0 @parameter_status_application_name @/parameter_status_application_name
    | "client_encoding" 0 str0 @parameter_status_client_encoding @/parameter_status_client_encoding
    | "DateStyle" 0 str0 @parameter_status_datestyle @/parameter_status_datestyle
    | "default_transaction_read_only" 0 str0 @parameter_status_default_transaction_read_only @/parameter_status_default_transaction_read_only
    | "in_hot_standby" 0 str0 @parameter_status_in_hot_standby @/parameter_status_in_hot_standby
    | "integer_datetimes" 0 str0 @parameter_status_integer_datetimes @/parameter_status_integer_datetimes
    | "IntervalStyle" 0 str0 @parameter_status_intervalstyle @/parameter_status_intervalstyle
    | "is_superuser" 0 str0 @parameter_status_is_superuser @/parameter_status_is_superuser
    | "server_encoding" 0 str0 @parameter_status_server_encoding @/parameter_status_server_encoding
    | "server_version" 0 str0 @parameter_status_server_version @/parameter_status_server_version
    | "session_authorization" 0 str0 @parameter_status_session_authorization @/parameter_status_session_authorization
    | "standard_conforming_strings" 0 str0 @parameter_status_standard_conforming_strings @/parameter_status_standard_conforming_strings
    | "TimeZone" 0 str0 @parameter_status_timezone @/parameter_status_timezone
    );

    ready_for_query_idle = "I" @ready_for_query_idle;
    ready_for_query_inerror = "E" @ready_for_query_inerror;
    ready_for_query_intrans = "T" @ready_for_query_intrans;
    result = any * $string $result_val $/result_val;

    function_call_response = int4 @result_len result;

    data_row = function_call_response;
    ready_for_query = ready_for_query_inerror | ready_for_query_idle | ready_for_query_intrans;
    row_description = str0 >row_description_beg @row_description_name @/row_description_name int4 @row_description_table int2 @row_description_column int4 @row_description_oid int2 @row_description_length int4 @row_description_mod 0 0 @row_description_format;

    main :=
    ( "1" 0 0 0 4 @parse_complete
    | "2" 0 0 0 4 @bind_complete
    | "3" 0 0 0 4 @close_complete
    | "A" int4 @notification_response int4 @notification_response_pid str0 @notification_response_relname @/notification_response_relname str0 @notification_response_extra @/notification_response_extra
    | "c" 0 0 0 4 @copy_done
    | "C" int4 @command_complete str0 @command_complete_val @/command_complete_val
    | "d" int4 @copy_data result
    | "D" int4 @data_row int2 @data_row_count data_row
    | "E" int4 @error_response error_response + 0
    | "H" int4 @copy_out_response 0 any{2} ( 0 0 ) *
    | "I" 0 0 0 4 @empty_query_response
    | "K" 0 0 0 12 @backend_key_data int4 @backend_key_data_pid int4 @backend_key_data_key
    | "n" 0 0 0 4 @no_data
    | "N" int4 @notice_response error_response + 0
    | "R" 0 0 0 8 @authentication_ok 0 0 0 0
    | "S" int4 @parameter_status parameter_status
    | "T" int4 @row_description int2 @row_description_count row_description
    | "V" int4 @function_call_response function_call_response
    | "Z" 0 0 0 5 @ready_for_query ready_for_query
    ) **;

    write data noentry noerror nofinal;
}%%

size_t pg_fsm_execute(pg_fsm_t *fsm, const pg_fsm_cb_t *cb, const void *user, const uint8_t *p, const uint8_t *pe) {
    const uint8_t *b = p;
    const uint8_t *eof = pe;
    %% write exec;
    if (!fsm->cs) (void)cb->error(user, p - b, p);
    return p - b;
}

size_t pg_fsm_size(void) {
    return sizeof(pg_fsm_t);
}

void pg_fsm_init(pg_fsm_t *fsm) {
    %% write init;
}
