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
    access m->;
    alphtype unsigned char;

    action all { if (f->all(u, 0, p)) fbreak; }
    action authentication_ok { if (f->authentication_ok(u)) fbreak; }
    action backend_key_data { if (f->backend_key_data(u)) fbreak; }
    action backend_key_data_key { if (f->backend_key_data_key(u, m->int4)) fbreak; }
    action backend_key_data_pid { if (f->backend_key_data_pid(u, m->int4)) fbreak; }
    action bind_complete { if (f->bind_complete(u)) fbreak; }
    action close_complete { if (f->close_complete(u)) fbreak; }
    action command_complete { if (f->command_complete(u, m->int4 - 4)) fbreak; }
    action command_complete_val { if (m->string && p - m->string > 0 && f->command_complete_val(u, p - m->string, m->string)) fbreak; m->string = NULL; }
    action copy_data { m->result_len = m->int4 - 4; if (f->copy_data(u, m->result_len)) fbreak; }
    action copy_done { if (f->copy_done(u)) fbreak; }
    action copy_out_response { if (f->copy_out_response(u, m->int4 - 4)) fbreak; }
    action data_row_count { m->data_row_count = m->int2; if (f->data_row_count(u, m->data_row_count)) fbreak; if (!m->data_row_count) fnext main; }
    action data_row { if (f->data_row(u, m->int4 - 4)) fbreak; }
    action empty_query_response { if (f->empty_query_response(u)) fbreak; }
    action error_response_column { if (m->string && p - m->string > 0 && f->error_response_column(u, p - m->string, m->string)) fbreak; m->string = NULL; }
    action error_response_constraint { if (m->string && p - m->string > 0 && f->error_response_constraint(u, p - m->string, m->string)) fbreak; m->string = NULL; }
    action error_response_context { if (m->string && p - m->string > 0 && f->error_response_context(u, p - m->string, m->string)) fbreak; m->string = NULL; }
    action error_response_datatype { if (m->string && p - m->string > 0 && f->error_response_datatype(u, p - m->string, m->string)) fbreak; m->string = NULL; }
    action error_response_detail { if (m->string && p - m->string > 0 && f->error_response_detail(u, p - m->string, m->string)) fbreak; m->string = NULL; }
    action error_response_file { if (m->string && p - m->string > 0 && f->error_response_file(u, p - m->string, m->string)) fbreak; m->string = NULL; }
    action error_response_function { if (m->string && p - m->string > 0 && f->error_response_function(u, p - m->string, m->string)) fbreak; m->string = NULL; }
    action error_response_hint { if (m->string && p - m->string > 0 && f->error_response_hint(u, p - m->string, m->string)) fbreak; m->string = NULL; }
    action error_response { if (f->error_response(u, m->int4 - 4)) fbreak; }
    action error_response_internal { if (m->string && p - m->string > 0 && f->error_response_internal(u, p - m->string, m->string)) fbreak; m->string = NULL; }
    action error_response_line { if (m->string && p - m->string > 0 && f->error_response_line(u, p - m->string, m->string)) fbreak; m->string = NULL; }
    action error_response_nonlocalized { if (m->string && p - m->string > 0 && f->error_response_nonlocalized(u, p - m->string, m->string)) fbreak; m->string = NULL; }
    action error_response_primary { if (m->string && p - m->string > 0 && f->error_response_primary(u, p - m->string, m->string)) fbreak; m->string = NULL; }
    action error_response_query { if (m->string && p - m->string > 0 && f->error_response_query(u, p - m->string, m->string)) fbreak; m->string = NULL; }
    action error_response_schema { if (m->string && p - m->string > 0 && f->error_response_schema(u, p - m->string, m->string)) fbreak; m->string = NULL; }
    action error_response_severity { if (m->string && p - m->string > 0 && f->error_response_severity(u, p - m->string, m->string)) fbreak; m->string = NULL; }
    action error_response_sqlstate { if (m->string && p - m->string > 0 && f->error_response_sqlstate(u, p - m->string, m->string)) fbreak; m->string = NULL; }
    action error_response_statement { if (m->string && p - m->string > 0 && f->error_response_statement(u, p - m->string, m->string)) fbreak; m->string = NULL; }
    action error_response_table { if (m->string && p - m->string > 0 && f->error_response_table(u, p - m->string, m->string)) fbreak; m->string = NULL; }
    action function_call_response { if (f->function_call_response(u, m->int4 - 4)) fbreak; }
    action int2 { if (!m->i) { m->i = sizeof(m->int2); m->int2 = 0; } m->int2 |= *p << ((2 << 2) * --m->i); }
    action int4 { if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
    action no_data { if (f->no_data(u)) fbreak; }
    action notice_response { if (f->notice_response(u, m->int4 - 4)) fbreak; }
    action notification_response_extra { if (m->string && p - m->string > 0 && f->notification_response_extra(u, p - m->string, m->string)) fbreak; m->string = NULL; if (p != eof) if (f->notification_response_done(u)) fbreak; }
    action notification_response { if (f->notification_response(u, m->int4 - 4)) fbreak; }
    action notification_response_pid { if (f->notification_response_pid(u, m->int4)) fbreak; }
    action notification_response_relname { if (m->string && p - m->string > 0 && f->notification_response_relname(u, p - m->string, m->string)) fbreak; m->string = NULL; }
    action parameter_status_application_name { if (m->string && p - m->string > 0 && f->parameter_status_application_name(u, p - m->string, m->string)) fbreak; m->string = NULL; }
    action parameter_status_client_encoding { if (m->string && p - m->string > 0 && f->parameter_status_client_encoding(u, p - m->string, m->string)) fbreak; m->string = NULL; }
    action parameter_status_datestyle { if (m->string && p - m->string > 0 && f->parameter_status_datestyle(u, p - m->string, m->string)) fbreak; m->string = NULL; }
    action parameter_status_default_transaction_read_only { if (m->string && p - m->string > 0 && f->parameter_status_default_transaction_read_only(u, p - m->string, m->string)) fbreak; m->string = NULL; }
    action parameter_status { if (f->parameter_status(u, m->int4 - 4)) fbreak; }
    action parameter_status_in_hot_standby { if (m->string && p - m->string > 0 && f->parameter_status_in_hot_standby(u, p - m->string, m->string)) fbreak; m->string = NULL; }
    action parameter_status_integer_datetimes { if (m->string && p - m->string > 0 && f->parameter_status_integer_datetimes(u, p - m->string, m->string)) fbreak; m->string = NULL; }
    action parameter_status_intervalstyle { if (m->string && p - m->string > 0 && f->parameter_status_intervalstyle(u, p - m->string, m->string)) fbreak; m->string = NULL; }
    action parameter_status_is_superuser { if (m->string && p - m->string > 0 && f->parameter_status_is_superuser(u, p - m->string, m->string)) fbreak; m->string = NULL; }
    action parameter_status_server_encoding { if (m->string && p - m->string > 0 && f->parameter_status_server_encoding(u, p - m->string, m->string)) fbreak; m->string = NULL; }
    action parameter_status_server_version { if (m->string && p - m->string > 0 && f->parameter_status_server_version(u, p - m->string, m->string)) fbreak; m->string = NULL; }
    action parameter_status_session_authorization { if (m->string && p - m->string > 0 && f->parameter_status_session_authorization(u, p - m->string, m->string)) fbreak; m->string = NULL; }
    action parameter_status_standard_conforming_strings { if (m->string && p - m->string > 0 && f->parameter_status_standard_conforming_strings(u, p - m->string, m->string)) fbreak; m->string = NULL; }
    action parameter_status_timezone { if (m->string && p - m->string > 0 && f->parameter_status_timezone(u, p - m->string, m->string)) fbreak; m->string = NULL; }
    action parse_complete { if (f->parse_complete(u)) fbreak; }
    action ready_for_query_idle { if (f->ready_for_query_state(u, pg_ready_for_query_state_idle)) fbreak; }
    action ready_for_query { if (f->ready_for_query(u)) fbreak; }
    action ready_for_query_inerror { if (f->ready_for_query_state(u, pg_ready_for_query_state_inerror)) fbreak; }
    action ready_for_query_intrans { if (f->ready_for_query_state(u, pg_ready_for_query_state_intrans)) fbreak; }
    action result_len { m->result_len = m->int4; if (f->result_len(u, m->result_len)) fbreak; if (!m->result_len || m->result_len == (uint32_t)-1) { if (!m->data_row_count || !--m->data_row_count) fnext main; else fnext data_row; } }
    action result_val { if (p == eof || !m->result_len--) { if (m->string && p - m->string > 0 && f->result_val(u, p - m->string, m->string)) fbreak; m->string = NULL; if (m->result_len == (uint32_t)-1) { if (f->result_done(u)) fbreak; fhold; if (!m->data_row_count || !--m->data_row_count) fnext main; else fnext data_row; } } }
    action row_description_beg { if (f->row_description_beg(u)) fbreak; }
    action row_description_column { if (f->row_description_column(u, m->int2)) fbreak; }
    action row_description_count { m->row_description_count = m->int2; if (f->row_description_count(u, m->row_description_count)) fbreak; if (!m->row_description_count) fnext main; }
    action row_description_format { if (f->row_description_format(u, 0)) fbreak; if (!--m->row_description_count) fnext main; else fnext row_description; }
    action row_description { if (f->row_description(u, m->int4 - 4)) fbreak; }
    action row_description_length { if (f->row_description_length(u, m->int2)) fbreak; }
    action row_description_mod { if (f->row_description_mod(u, m->int4)) fbreak; }
    action row_description_name { if (m->string && p - m->string > 0 && f->row_description_name(u, p - m->string, m->string)) fbreak; m->string = NULL; }
    action row_description_oid { if (f->row_description_oid(u, m->int4)) fbreak; }
    action row_description_table { if (f->row_description_table(u, m->int4)) fbreak; }
    action string { if (!m->string) m->string = p; }

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

size_t pg_fsm_execute(pg_fsm_t *m, const pg_fsm_cb_t *f, const void *u, const uint8_t *p, const uint8_t *pe) {
    const uint8_t *b = p;
    const uint8_t *eof = pe;
    %% write exec;
    if (!m->cs) (void)f->error(u, p - b, p);
    return p - b;
}

size_t pg_fsm_size(void) {
    return sizeof(pg_fsm_t);
}

void pg_fsm_init(pg_fsm_t *m) {
    %% write init;
}
