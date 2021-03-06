/*
 * ngx_http_header_inspect - Inspect HTTP headers
 *
 * Copyright (c) 2011, Andreas Jaggi <andreas.jaggi@waterwave.ch>
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_array.h>



typedef struct {
	ngx_flag_t inspect;
	ngx_flag_t log;
	ngx_flag_t log_uninspected;
	ngx_flag_t block;

	ngx_uint_t range_max_byteranges;
} ngx_header_inspect_loc_conf_t;



static ngx_int_t ngx_header_inspect_init(ngx_conf_t *cf);
static ngx_int_t ngx_header_inspect_http_date(u_char *data, ngx_uint_t maxlen, ngx_uint_t *len);
static ngx_int_t ngx_header_inspect_parse_base64(char* header, ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, u_char *data, ngx_uint_t maxlen);
static ngx_int_t ngx_header_inspect_parse_entity_tag(u_char *data, ngx_uint_t maxlen, ngx_uint_t *len);
static ngx_int_t ngx_header_inspect_parse_languagerange(u_char *data, ngx_uint_t maxlen, ngx_uint_t *len);
static ngx_int_t ngx_header_inspect_range_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);
static ngx_int_t ngx_header_inspect_acceptencoding_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);
static ngx_int_t ngx_header_inspect_contentencoding_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);
static ngx_int_t ngx_header_inspect_acceptlanguage_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);
static ngx_int_t ngx_header_inspect_contentlanguage_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);
static ngx_int_t ngx_header_inspect_acceptcharset_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);
static ngx_int_t ngx_header_inspect_digit_header(char* header, ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);
static ngx_int_t ngx_header_inspect_ifmatch_header(char* header, ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);
static ngx_int_t ngx_header_inspect_allow_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);
static ngx_int_t ngx_header_inspect_host_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);
static ngx_int_t ngx_header_inspect_accept_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);
static ngx_int_t ngx_header_inspect_connection_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);
static ngx_int_t ngx_header_inspect_contentrange_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);
static ngx_int_t ngx_header_inspect_useragent_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);
static ngx_int_t ngx_header_inspect_upgrade_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);
static ngx_int_t ngx_header_inspect_via_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);
static ngx_int_t ngx_header_inspect_from_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);
static ngx_int_t ngx_header_inspect_ifrange_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);
static ngx_int_t ngx_header_inspect_pragma_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);
static ngx_int_t ngx_header_inspect_contenttype_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);
static ngx_int_t ngx_header_inspect_date_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, char *header, ngx_str_t value);
static ngx_int_t ngx_header_inspect_contentmd5_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);
static ngx_int_t ngx_header_inspect_authorization_header(char* header, ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);
static ngx_int_t ngx_header_inspect_expect_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);
static ngx_int_t ngx_header_inspect_warning_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);
static ngx_int_t ngx_header_inspect_trailer_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);
static ngx_int_t ngx_header_inspect_transferencoding_header(char* header, ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);
static ngx_int_t ngx_header_inspect_referer_header(char* header, ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);
static ngx_int_t ngx_header_inspect_cachecontrol_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value);
static ngx_int_t ngx_header_inspect_process_request(ngx_http_request_t *r);

static void *ngx_header_inspect_create_conf(ngx_conf_t *cf);
static char *ngx_header_inspect_merge_conf(ngx_conf_t *cf, void *parent, void *child);



static ngx_command_t ngx_header_inspect_commands[] = {
	{
		ngx_string("inspect_headers"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
		ngx_conf_set_flag_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_header_inspect_loc_conf_t, inspect),
		NULL
	},
	{
		ngx_string("inspect_headers_log_violations"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
		ngx_conf_set_flag_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_header_inspect_loc_conf_t, log),
		NULL
	},
	{
		ngx_string("inspect_headers_block_violations"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
		ngx_conf_set_flag_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_header_inspect_loc_conf_t, block),
		NULL
	},
	{
		ngx_string("inspect_headers_log_uninspected"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
		ngx_conf_set_flag_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_header_inspect_loc_conf_t, log_uninspected),
		NULL
	},
	{
		ngx_string("inspect_headers_range_max_byteranges"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_num_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_header_inspect_loc_conf_t, range_max_byteranges),
		NULL
	},
	ngx_null_command
};

static ngx_http_module_t ngx_header_inspect_module_ctx = {
	NULL,                             /* preconfiguration */
	ngx_header_inspect_init,          /* postconfiguration */

	NULL,                             /* create main configuration */
	NULL,                             /* init main configuration */

	NULL,                             /* create server configuration */
	NULL,                             /* merge server configuration */

	ngx_header_inspect_create_conf,   /* create location configuration */
	ngx_header_inspect_merge_conf,    /* merge location configuration */
};

ngx_module_t ngx_http_header_inspect_module = {
	NGX_MODULE_V1,
	&ngx_header_inspect_module_ctx, /* module context */
	ngx_header_inspect_commands,    /* module directives */
	NGX_HTTP_MODULE,                /* module type */
	NULL,                           /* init master */
	NULL,                           /* init module */
	NULL,                           /* init process */
	NULL,                           /* init thread */
	NULL,                           /* exit thread */
	NULL,                           /* exit process */
	NULL,                           /* exit master */
	NGX_MODULE_V1_PADDING
};



static ngx_int_t ngx_header_inspect_init(ngx_conf_t *cf) {
	ngx_http_handler_pt       *h;
	ngx_http_core_main_conf_t *cmcf;

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

	h = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
	if (h == NULL) {
		return NGX_ERROR;
	}

	*h = ngx_header_inspect_process_request;

	return NGX_OK;
}

static ngx_int_t ngx_header_inspect_range_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
	ngx_uint_t i,a,b,setcount;
	ngx_int_t rc = NGX_OK;
	enum range_header_states {RHS_NEWSET,RHS_NUM1,DELIM,RHS_NUM2,RHS_SUFDELIM,RHS_SUFNUM} state;

	if ( (value.len < 6) || (ngx_strncmp("bytes=", value.data, 6) != 0) ) {
		if ( conf->log ) {
			ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: Range header does not start with \"bytes=\"");
		}
		rc = NGX_ERROR;
	}

	setcount = 1;
	a = 0;
	b = 0;
	state = RHS_NEWSET;

	i = 6; /* start after bytes= */
	for ( ; i < value.len ; i++ ) {

		switch (value.data[i]) {
			case ',':
				if ( (state != DELIM) && (state != RHS_NUM2) && (state != RHS_SUFNUM) ) {
					if ( conf->log ) {
						ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected ',' at position %d in Range header \"%s\"", i, value.data);
					}
					rc = NGX_ERROR;
				}
				if ( state == RHS_NUM2 ) {
					/* verify a <= b in 'a-b' sets */
					if ( a > b ) {
						if ( conf->log ) {
							ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: invalid range definition at position %d in Range header \"%s\"", i, value.data);
						}
						rc = NGX_ERROR;
					}
				}
				setcount++;
				a = 0;
				b = 0;
				state = RHS_NEWSET;
				break;

			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
				if ((state == RHS_NEWSET) || (state == RHS_NUM1)) {
					a = a*10 + (value.data[i] - '0');
					state = RHS_NUM1;
				} else if ((state == DELIM) || (state == RHS_NUM2)) {
					b = b*10 + (value.data[i] - '0');
					state = RHS_NUM2;
				} else if ((state == RHS_SUFDELIM) || (state == RHS_SUFNUM)) {
					state = RHS_SUFNUM;
				} else {
					if ( conf->log ) {
						ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected digit at position %d in Range header \"%s\"", i, value.data);
					}
					rc = NGX_ERROR;
				}
				break;

			case '-':
				if (state == RHS_NEWSET) {
					state = RHS_SUFDELIM;
				} else if (state == RHS_NUM1) {
					state = DELIM;
				} else {
					if ( conf->log ) {
						ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected '-' at position %d in Range header \"%s\"", i, value.data);
					}
					rc = NGX_ERROR;
				}
				break;

			default:
				if ( conf->log ) {
					ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: illegal char at position %d in Range header \"%s\"", i, value.data);
				}
				rc = NGX_ERROR;
		}

		if (setcount > conf->range_max_byteranges) {
			if ( conf->log ) {
				ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: Range header contains more than %d byteranges", conf->range_max_byteranges);
			}
			return NGX_ERROR;
			break;
		}
	}

	if ((state != DELIM) && (state != RHS_NUM2) && (state != RHS_SUFNUM)) {
		if ( conf->log ) {
			ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: Range header \"%s\" contains incomplete byteset definition", value.data);
		}
		rc = NGX_ERROR;
	}
	if ( state == RHS_NUM2 ) {
		/* verify a <= b in 'a-b' sets */
		if ( a > b ) {
			if ( conf->log ) {
				ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: invalid range definition at position %d in Range header \"%s\"", i, value.data);
			}
			rc = NGX_ERROR;
		}
	}

	return rc;
}

static ngx_int_t ngx_header_inspect_http_date(u_char *data, ngx_uint_t maxlen, ngx_uint_t *len) {
	ngx_uint_t i = 0;
	enum http_date_type {RFC1123, RFC850, ASCTIME} type;

	if ( maxlen < 24 ) {
		*len = i;
		return NGX_ERROR;
	}

	if ((data[0] == 'M') && (data[1] == 'o') && (data[2] == 'n')) {
	/* Mon(day) */
		switch (data[3]) {
			case ',':
				type = RFC1123;
				i = 4;
				break;
			case ' ':
				type = ASCTIME;
				i = 3;
				break;
			case 'd':
				type = RFC850;
				if (
					(data[4] != 'a') ||
					(data[5] != 'y') ||
					(data[6] != ',')
				) {
					*len = i;
					return NGX_ERROR;
				}
				i = 7;
				break;
			default:
				*len = i;
				return NGX_ERROR;
		}
	} else if ((data[0] == 'T') && (data[1] == 'u') && (data[2] == 'e')) {
	/* Tue(sday) */
		switch (data[3]) {
			case ',':
				type = RFC1123;
				i = 4;
				break;
			case ' ':
				type = ASCTIME;
				i = 3;
				break;
			case 's':
				type = RFC850;
				if (
					(data[4] != 'd') ||
					(data[5] != 'a') ||
					(data[6] != 'y') ||
					(data[7] != ',')
				) {
					*len = i;
					return NGX_ERROR;
				}
				i = 8;
				break;
			default:
				*len = i;
				return NGX_ERROR;
		}
	} else if ((data[0] == 'W') && (data[1] == 'e') && (data[2] == 'd')) {
	/* Wed(nesday) */
		switch (data[3]) {
			case ',':
				type = RFC1123;
				i = 4;
				break;
			case ' ':
				type = ASCTIME;
				i = 3;
				break;
			case 'n':
				type = RFC850;
				if (
					(data[4] != 'e') ||
					(data[5] != 's') ||
					(data[6] != 'd') ||
					(data[7] != 'a') ||
					(data[8] != 'y') ||
					(data[9] != ',')
				) {
					*len = i;
					return NGX_ERROR;
				}
				i = 10;
				break;
			default:
				*len = i;
				return NGX_ERROR;
		}
	} else if ((data[0] == 'T') && (data[1] == 'h') && (data[2] == 'u')) {
	/* Thu(rsday) */
		switch (data[3]) {
			case ',':
				type = RFC1123;
				i = 4;
				break;
			case ' ':
				type = ASCTIME;
				i = 3;
				break;
			case 'r':
				type = RFC850;
				if (
					(data[4] != 's') ||
					(data[5] != 'd') ||
					(data[6] != 'a') ||
					(data[7] != 'y') ||
					(data[8] != ',')
				) {
					*len = i;
					return NGX_ERROR;
				}
				i = 9;
				break;
			default:
				*len = i;
				return NGX_ERROR;
		}
	} else if ((data[0] == 'F') && (data[1] == 'r') && (data[2] == 'i')) {
	/* Fri(day) */
		switch (data[3]) {
			case ',':
				type = RFC1123;
				i = 4;
				break;
			case ' ':
				type = ASCTIME;
				i = 3;
				break;
			case 'd':
				type = RFC850;
				if (
					(data[4] != 'a') ||
					(data[5] != 'y') ||
					(data[6] != ',')
				) {
					*len = i;
					return NGX_ERROR;
				}
				i = 7;
				break;
			default:
				*len = i;
				return NGX_ERROR;
		}
	} else if ((data[0] == 'S') && (data[1] == 'a') && (data[2] == 't')) {
	/* Sat(urday) */
		switch (data[3]) {
			case ',':
				type = RFC1123;
				i = 4;
				break;
			case ' ':
				type = ASCTIME;
				i = 3;
				break;
			case 'u':
				type = RFC850;
				if (
					(data[4] != 'r') ||
					(data[5] != 'd') ||
					(data[6] != 'a') ||
					(data[7] != 'y') ||
					(data[8] != ',')
				) {
					*len = i;
					return NGX_ERROR;
				}
				i = 9;
				break;
			default:
				*len = i;
				return NGX_ERROR;
		}
	} else if ((data[0] == 'S') && (data[1] == 'u') && (data[2] == 'n')) {
	/* Sun(day) */
		switch (data[3]) {
			case ',':
				type = RFC1123;
				i = 4;
				break;
			case ' ':
				type = ASCTIME;
				i = 3;
				break;
			case 'd':
				type = RFC850;
				if (
					(data[4] != 'a') ||
					(data[5] != 'y') ||
					(data[6] != ',')
				) {
					*len = i;
					return NGX_ERROR;
				}
				i = 7;
				break;
			default:
				*len = i;
				return NGX_ERROR;
		}
	} else {
		*len = i;
		return NGX_ERROR;
	}

	switch (type) {
		case RFC1123:
			if (maxlen < 29) {
				*len = i;
				return NGX_ERROR;
			}
			break;
		case RFC850:
			if (maxlen < 30) {
				*len = i;
				return NGX_ERROR;
			}
			break;
		case ASCTIME:
			if (maxlen < 24) {
				*len = i;
				return NGX_ERROR;
			}
			break;
		default:
			*len = i;
			return NGX_ERROR;
	}

	if (data[i] != ' ') {
		*len = i;
		return NGX_ERROR;
	}
	i++;

	if (type == RFC1123) {
	/* rfc1123: day */
		if ((data[i] < '0') || (data[i] > '9')) {
			*len = i;
			return NGX_ERROR;
		}
		i++;
		if ((data[i] < '0') || (data[i] > '9')) {
			*len = i;
			return NGX_ERROR;
		}
		i++;
		if (data[i] != ' ') {
			*len = i;
			return NGX_ERROR;
		}
		i++;
	} else if (type == RFC850) {
	/* rfc850: day */
		if ((data[i] < '0') || (data[i] > '9')) {
			*len = i;
			return NGX_ERROR;
		}
		i++;
		if ((data[i] < '0') || (data[i] > '9')) {
			*len = i;
			return NGX_ERROR;
		}
		i++;
		if (data[i] != '-') {
			*len = i;
			return NGX_ERROR;
		}
		i++;
	}

	/* month: Nov */
	if (
		((data[i] == 'J') && (data[i+1] == 'a') && (data[i+2] == 'n')) ||
		((data[i] == 'F') && (data[i+1] == 'e') && (data[i+2] == 'b')) ||
		((data[i] == 'M') && (data[i+1] == 'a') && (data[i+2] == 'r')) ||
		((data[i] == 'A') && (data[i+1] == 'p') && (data[i+2] == 'r')) ||
		((data[i] == 'M') && (data[i+1] == 'a') && (data[i+2] == 'y')) ||
		((data[i] == 'J') && (data[i+1] == 'u') && (data[i+2] == 'n')) ||
		((data[i] == 'J') && (data[i+1] == 'u') && (data[i+2] == 'l')) ||
		((data[i] == 'A') && (data[i+1] == 'u') && (data[i+2] == 'g')) ||
		((data[i] == 'S') && (data[i+1] == 'e') && (data[i+2] == 'p')) ||
		((data[i] == 'O') && (data[i+1] == 'c') && (data[i+2] == 't')) ||
		((data[i] == 'N') && (data[i+1] == 'o') && (data[i+2] == 'v')) ||
		((data[i] == 'D') && (data[i+1] == 'e') && (data[i+2] == 'c'))
	) {
		i += 3;
	} else {
		*len = i;
		return NGX_ERROR;
	}

	if (type == RFC1123) {
	/* rfc1123: year */
		if (data[i] != ' ') {
			*len = i;
			return NGX_ERROR;
		}
		i++;
		if ((data[i] < '0') || (data[i] > '9')) {
			*len = i;
			return NGX_ERROR;
		}
		i++;
		if ((data[i] < '0') || (data[i] > '9')) {
			*len = i;
			return NGX_ERROR;
		}
		i++;
		if ((data[i] < '0') || (data[i] > '9')) {
			*len = i;
			return NGX_ERROR;
		}
		i++;
	} else if (type == RFC850) {
	/* rfc850: year */
		if (data[i] != '-') {
			*len = i;
			return NGX_ERROR;
		}
		i++;
		if ((data[i] < '0') || (data[i] > '9')) {
			*len = i;
			return NGX_ERROR;
		}
		i++;
	} else if (type == ASCTIME) {
	/* asctime: day */
		if (data[i] != ' ') {
			*len = i;
			return NGX_ERROR;
		}
		i++;
		if ((data[i] != ' ') || (data[i] < '0') || (data[i] > '9')) {
			*len = i;
			return NGX_ERROR;
		}
		i++;
	}
	if ((data[i] < '0') || (data[i] > '9')) {
		*len = i;
		return NGX_ERROR;
	}
	i++;
	if (data[i] != ' ') {
		*len = i;
		return NGX_ERROR;
	}
	i++;

	/* time 08:49:37 */
	if (
		(data[i] < '0') || (data[i] > '9') ||
		(data[i+1] < '0') || (data[i+1] > '9') ||
		(data[i+2] != ':')
	) {
		*len = i;
		return NGX_ERROR;
	}
	i += 3;
	if (
		(data[i] < '0') || (data[i] > '9') ||
		(data[i+1] < '0') || (data[i+1] > '9') ||
		(data[i+2] != ':')
	) {
		*len = i;
		return NGX_ERROR;
	}
	i += 3;
	if (
		(data[i] < '0') || (data[i] > '9') ||
		(data[i+1] < '0') || (data[i+1] > '9') ||
		(data[i+2] != ' ')
	) {
		*len = i;
		return NGX_ERROR;
	}
	i += 3;

	if (type == ASCTIME) {
	/* asctime: year: 1994 */
		if (
			(data[i] < '0') || (data[i] > '9') ||
			(data[i+1] < '0') || (data[i+1] > '9') ||
			(data[i+2] < '0') || (data[i+2] > '9') ||
			(data[i+3] < '0') || (data[i+3] > '9')
		) {
			*len = i;
			return NGX_ERROR;
		}
		i += 4;
	} else {
		/* GMT */
		if ((data[i] != 'G') || (data[i+1] != 'M') || (data[i+2] != 'T')) {
			*len = i;
			return NGX_ERROR;
		}
		i += 3;
	}

	*len = i;
	return NGX_OK;
}

static ngx_int_t ngx_header_inspect_parse_entity_tag(u_char *data, ngx_uint_t maxlen, ngx_uint_t *len) {
	ngx_uint_t i = 0;

	if ( maxlen < 2 ) {
		*len = 0;
		return NGX_ERROR;
	}

	if ( data[0] == 'W' ) {
		if ( data[1] != '/' ) {
			*len = 2;
			return NGX_ERROR;
		}
		i = 2;
	}

	if ( i+1 >= maxlen ) {
		*len = i;
		return NGX_ERROR;
	}

	if ( data[i] != '"' ) {
		*len = i+1;
		return NGX_ERROR;
	}
	i++;

	for ( ; i < maxlen-1 ; i++ ) {
		if ( data[i] == '"' ) {
			*len = i+1;
			return NGX_OK;
		}
	}

	*len = maxlen;
	return NGX_ERROR;
}

static ngx_int_t ngx_header_inspect_parse_qvalue(u_char *data, ngx_uint_t maxlen, ngx_uint_t *len) {

	*len = 0;

	if ((maxlen < 3) || (data[0] != 'q') || (data[1] != '=')) {
		return NGX_ERROR;
	}

	if (data[2] == '0') {
		if ((maxlen == 3) || (data[3] != '.')) {
			*len = 3;
			return NGX_OK;
		}
		if ((data[4] < '0') || (data[4] > '9')) {
			*len = 4;
			return NGX_OK;
		}
		if ((data[5] < '0') || (data[5] > '9')) {
			*len = 5;
			return NGX_OK;
		}
		if ((data[6] < '0') || (data[6] > '9')) {
			*len = 6;
		} else {
			*len = 7;
		}
		return NGX_OK;
	} else if (data[2] == '1') {
		if ((maxlen == 3) || (data[3] != '.')) {
			*len = 3;
			return NGX_OK;
		}
		if (data[4] != '0') {
			*len = 4;
			return NGX_OK;
		}
		if (data[5] != '0') {
			*len = 5;
			return NGX_OK;
		}
		if (data[6] != '0') {
			*len = 6;
		} else {
			*len = 7;
		}
		return NGX_OK;
	} else {
		*len = 2;
		return NGX_ERROR;
	}
}

static ngx_int_t ngx_header_inspect_parse_contentcoding(u_char *data, ngx_uint_t maxlen, ngx_uint_t *len) {

	if (maxlen < 1) {
		*len = 0;
		return NGX_ERROR;
	}
	*len = 1;

	switch (data[0]) {
		case '*':
			return NGX_OK;
			break;
		case 'c':
			if ( (maxlen < 8) || (ngx_strncmp("compress", data, 8) != 0)) {
				return NGX_ERROR;
			}
			*len = 8;
			break;
		case 'd':
			if ( (maxlen < 7) || (ngx_strncmp("deflate", data, 7) != 0)) {
				return NGX_ERROR;
			}
			*len = 7;
			break;
		case 'e':
			if ( (maxlen < 3) || (ngx_strncmp("exi", data, 3) != 0)) {
				return NGX_ERROR;
			}
			*len = 3;
			break;
		case 'g':
			if ( (maxlen < 4) || (ngx_strncmp("gzip", data, 4) != 0)) {
				return NGX_ERROR;
			}
			*len = 4;
			break;
		case 'i':
			if ( (maxlen < 8) || (ngx_strncmp("identity", data, 8) != 0)) {
				return NGX_ERROR;
			}
			*len = 8;
			break;
		case 'p':
			if ( (maxlen < 12) || (ngx_strncmp("pack200-gzip", data, 12) != 0)) {
				return NGX_ERROR;
			}
			*len = 12;
			break;
		default:
			return NGX_ERROR;
	}

	return NGX_OK;
}

static ngx_int_t ngx_header_inspect_parse_mediatype(u_char *data, ngx_uint_t maxlen, ngx_uint_t *len) {
	ngx_uint_t i = 0;
	u_char d;
	ngx_uint_t secondpart = 0;
	ngx_uint_t parameter = 0;

	if (maxlen < 1) {
		*len = 0;
		return NGX_ERROR;
	}

	*len = 1;
	while ( i < maxlen ) {
		d = data[i];
		if ( d == '/' ) {
			if ( i < 1 ) {
				*len = 1;
				return NGX_ERROR;
			} else {
				if ( secondpart == 0 ) {
					secondpart = 1;
					i++;
					continue;
				} else {
					*len = i;
					return NGX_ERROR;
				}
			}
		}

		if (
			((d < '0') || (d > '9')) &&
			((d < 'a') || (d > 'z')) &&
			((d < 'A') || (d > 'Z')) &&
			(d != '-') && (d != '_') &&
			(d != '+') && (d != '.') &&
			(d != ':') && (d != '*')
			/* TODO: check with RFC which chars are valid */
		) {
			*len = i;
			if (secondpart == 0) {
				return NGX_ERROR;
			} else {
				if ( d == ';' ) {
					parameter = 1;
					break;
				} else {
					return NGX_OK;
				}
			}
		}
		i++;
	}

	if ( parameter ) {
		if ( i+4 > maxlen ) {
			return NGX_ERROR;
		}
		while ( i < maxlen ) {
			if ( data[i] != ';' ) {
				*len = i;
				return NGX_OK;
			}
			i++;

			while ( (i < maxlen) && (data[i] == ' ') ) { i++; }
			if ( i == maxlen ) {
				*len = i;
				return NGX_ERROR;
			}

			/* attribute */
			while ( i < maxlen ) {
				d = data[i];

				if ( d == '=' ) {
					break;
				}

				if (
					((d < '0') || (d > '9')) &&
					((d < 'a') || (d > 'z')) &&
					((d < 'A') || (d > 'Z')) &&
					(d != '-') && (d != '_') &&
					(d != '+') && (d != '.') &&
					(d != ':') && (d != '*')
				) {
					*len = i;
					return NGX_ERROR;
				}
				i++;
			}
			if ( i == maxlen ) {
				*len = i;
				return NGX_ERROR;
			}
			i++;

			/* value */
			/* TODO: what if value is double-quoted? */
			while ( i < maxlen ) {
				d = data[i];

				if ( d == ';' ) {
					break;
				}

				if (
					((d < '0') || (d > '9')) &&
					((d < 'a') || (d > 'z')) &&
					((d < 'A') || (d > 'Z')) &&
					(d != '-') && (d != '_') &&
					(d != '+') && (d != '.') &&
					(d != ':') && (d != '*')
				) {
					*len = i;
					return NGX_OK;
				}
				i++;
			}
			while ( (i < maxlen) && (data[i] == ' ') ) { i++; }
		}
	}

	*len = i;
	if (secondpart == 0) {
		return NGX_ERROR;
	} else {
		return NGX_OK;
	}
}

static ngx_int_t ngx_header_inspect_parse_charset(u_char *data, ngx_uint_t maxlen, ngx_uint_t *len) {
	ngx_uint_t i;
	u_char d;
	ngx_uint_t alphacount = 0;

	if (maxlen < 1) {
		*len = 0;
		return NGX_ERROR;
	}

	if (data[0] == '*') {
		*len = 1;
		return NGX_OK;
	}

	*len = 1;
	for ( i = 0; i < maxlen; i++ ) {
		d = data[i];
		if (
			(d == '-') ||
			(d == '_') ||
			(d == '+') ||
			(d == '.') ||
			(d == ':')
		) {
			if (alphacount == 0) {
				*len = i;
				return NGX_ERROR;
			}
			alphacount = 0;
			continue;
		}
		if (
			((d < '0') || (d > '9')) &&
			((d < 'a') || (d > 'z')) &&
			((d < 'A') || (d > 'Z'))
		) {
			*len = i;
			if (alphacount == 0) {
				return NGX_ERROR;
			} else {
				return NGX_OK;
			}
		}
		alphacount++;
	}

	*len = i;
	if (alphacount == 0) {
		return NGX_ERROR;
	} else {
		return NGX_OK;
	}
}

static ngx_int_t ngx_header_inspect_parse_languagerange(u_char *data, ngx_uint_t maxlen, ngx_uint_t *len) {
	ngx_uint_t i;
	u_char d;
	ngx_uint_t alphacount = 0;

	if (maxlen < 1) {
		*len = 0;
		return NGX_ERROR;
	}

	if (data[0] == '*') {
		*len = 1;
		return NGX_OK;
	}

	*len = 1;
	for ( i = 0; i < maxlen; i++ ) {
		d = data[i];
		if (d == '-') {
			if (alphacount == 0) {
				*len = i;
				return NGX_ERROR;
			}
			alphacount = 0;
			continue;
		}
		if (
			((d < 'a') || (d > 'z')) &&
			((d < 'A') || (d > 'Z'))
		) {
			*len = i;
			if (alphacount == 0) {
				return NGX_ERROR;
			} else {
				return NGX_OK;
			}
		}
		if (alphacount == 8) {
			*len = i;
			return NGX_ERROR;
		}
		alphacount++;
	}

	*len = i;
	if (alphacount == 0) {
		return NGX_ERROR;
	} else {
		return NGX_OK;
	}
}

static ngx_int_t ngx_header_inspect_ifmatch_header(char* header, ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
	ngx_int_t rc = NGX_AGAIN;
	ngx_uint_t i = 0;
	ngx_uint_t v;

	if ( (value.len == 1) && (value.data[0] == '*') ) {
		return NGX_OK;
	}

	if ( value.len < 2 ) {
		if ( conf->log ) {
			ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: %s header \"%s\" too short", header, value.data);
		}
		return NGX_ERROR;
	}

	while ( i < value.len ) {
		if ( ngx_header_inspect_parse_entity_tag(&(value.data[i]), value.len-i, &v) != NGX_OK ) {
			if ( conf->log ) {
				ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: invalid entity-tag at position %d in %s header \"%s\"", i, header, value.data);
			}
			rc = NGX_ERROR;
			break;
		}
		i += v;
		if ((value.data[i] == ' ') && (i < value.len)) {
			i++;
		}
		if (i == value.len) {
			rc = NGX_OK;
			break;
		}
		if (value.data[i] != ',') {
			if ( conf->log ) {
				ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: illegal char at position %d in %s header \"%s\"", i, header, value.data);
			}
			rc = NGX_ERROR;
			break;
		}
		i++;
		if ((value.data[i] == ' ') && (i < value.len)) {
			i++;
		}
	}

	if (rc == NGX_AGAIN) {
		if ( conf->log ) {
			ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of %s header \"%s\"", header, value.data);
		}
		rc = NGX_ERROR;
	}

	return rc;
}

static ngx_int_t ngx_header_inspect_digit_header(char* header, ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
	ngx_uint_t i = 0;

	if ( value.len <= 0 ) {
		if ( conf->log ) {
			ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: %s header \"%s\" is empty", header, value.data);
		}
		return NGX_ERROR;
	}

	for ( i = 0; i < value.len; i++ ) {
		if ( (value.data[i] < '0') || (value.data[i] > '9') ) {
			if ( conf->log ) {
				ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: invalid digit at position %d in %s header \"%s\"", i, header, value.data);
			}
			return NGX_ERROR;
		}
	}

	return NGX_OK;
}

static ngx_int_t ngx_header_inspect_acceptcharset_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
	ngx_int_t rc = NGX_AGAIN;
	ngx_uint_t i = 0;
	ngx_uint_t v;

	if ((value.len == 0) || ((value.len == 1) && (value.data[0] == '*'))) {
		return NGX_OK;
	}

	while ( i < value.len ) {
		if (ngx_header_inspect_parse_charset(&(value.data[i]), value.len-i, &v) != NGX_OK) {
			if ( conf->log ) {
				ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: invalid charset at position %d in Accept-Charset header \"%s\"", i, value.data);
			}
			rc = NGX_ERROR;
			break;
		}
		i += v;
		if ((value.data[i] == ' ') && (i < value.len)) {
			i++;
		}
		if (i == value.len) {
			rc = NGX_OK;
			break;
		}
		if (value.data[i] == ';') {
			i++;
			if (i >= value.len) {
				if ( conf->log ) {
					ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of Accept-Charset header \"%s\"", value.data);
				}
				rc = NGX_ERROR;
				break;
			}
			if ((value.data[i] == ' ') && (i < value.len)) {
				i++;
			}
			if (ngx_header_inspect_parse_qvalue(&(value.data[i]), value.len-i, &v) != NGX_OK) {
				if ( conf->log ) {
					ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: invalid qvalue at position %d in Accept-Charset header \"%s\"", i, value.data);
				}
				rc = NGX_ERROR;
				break;
			}
			i += v;
			if ((value.data[i] == ' ') && (i < value.len)) {
				i++;
			}
			if (i == value.len) {
				rc = NGX_OK;
				break;
			}
		}
		if (value.data[i] != ',') {
			if ( conf->log ) {
				ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: illegal char at position %d in Accept-Charset header \"%s\"", i, value.data);
			}
			rc = NGX_ERROR;
			break;
		}
		i++;
		if ((value.data[i] == ' ') && (i < value.len)) {
			i++;
		}
	}

	if (rc == NGX_AGAIN) {
		if ( conf->log ) {
			ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of Accept-Charset header \"%s\"", value.data);
		}
		rc = NGX_ERROR;
	}

	return rc;
}

static ngx_int_t ngx_header_inspect_contentlanguage_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
	ngx_int_t rc = NGX_AGAIN;
	ngx_uint_t i = 0;
	ngx_uint_t v;

	if ((value.len == 0) || ((value.len == 1) && (value.data[0] == '*'))) {
		if ( conf->log ) {
			ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: Content-Language header \"%s\" too short", value.data);
		}
		return NGX_ERROR;
	}

	while ( i < value.len ) {
		if (value.data[i] == '*') {
		/* hack, to prevent parse_languagerange from matching '*' */
			if ( conf->log ) {
				ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: illegal char at position %d in Content-Language header \"%s\"", i, value.data);
			}
			rc = NGX_ERROR;
			break;
		}
		if (ngx_header_inspect_parse_languagerange(&(value.data[i]), value.len-i, &v) != NGX_OK) {
			if ( conf->log ) {
				ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: invalid language-range at position %d in Content-Language header \"%s\"", i, value.data);
			}
			rc = NGX_ERROR;
			break;
		}
		i += v;
		if ((value.data[i] == ' ') && (i < value.len)) {
			i++;
		}
		if (i == value.len) {
			rc = NGX_OK;
			break;
		}
		if (value.data[i] != ',') {
			if ( conf->log ) {
				ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: illegal char at position %d in Content-Language header \"%s\"", i, value.data);
			}
			rc = NGX_ERROR;
			break;
		}
		i++;
		if ((value.data[i] == ' ') && (i < value.len)) {
			i++;
		}
	}

	if (rc == NGX_AGAIN) {
		if ( conf->log ) {
			ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of Content-Language header \"%s\"", value.data);
		}
		rc = NGX_ERROR;
	}

	return rc;

}

static ngx_int_t ngx_header_inspect_acceptlanguage_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
	ngx_int_t rc = NGX_AGAIN;
	ngx_uint_t i = 0;
	ngx_uint_t v;

	if ((value.len == 0) || ((value.len == 1) && (value.data[0] == '*'))) {
		return NGX_OK;
	}

	while ( i < value.len ) {
		if (ngx_header_inspect_parse_languagerange(&(value.data[i]), value.len-i, &v) != NGX_OK) {
			if ( conf->log ) {
				ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: invalid language-range at position %d in Accept-Language header \"%s\"", i, value.data);
			}
			rc = NGX_ERROR;
			break;
		}
		i += v;
		if ((value.data[i] == ' ') && (i < value.len)) {
			i++;
		}
		if (i == value.len) {
			rc = NGX_OK;
			break;
		}
		if (value.data[i] == ';') {
			i++;
			if (i >= value.len) {
				if ( conf->log ) {
					ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of Accept-Language header \"%s\"", value.data);
				}
				rc = NGX_ERROR;
				break;
			}
			if ((value.data[i] == ' ') && (i < value.len)) {
				i++;
			}
			if (ngx_header_inspect_parse_qvalue(&(value.data[i]), value.len-i, &v) != NGX_OK) {
				if ( conf->log ) {
					ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: invalid qvalue at position %d in Accept-Language header \"%s\"", i, value.data);
				}
				rc = NGX_ERROR;
				break;
			}
			i += v;
			if ((value.data[i] == ' ') && (i < value.len)) {
				i++;
			}
			if (i == value.len) {
				rc = NGX_OK;
				break;
			}
		}
		if (value.data[i] != ',') {
			if ( conf->log ) {
				ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: illegal char at position %d in Accept-Language header \"%s\"", i, value.data);
			}
			rc = NGX_ERROR;
			break;
		}
		i++;
		if ((value.data[i] == ' ') && (i < value.len)) {
			i++;
		}
	}

	if (rc == NGX_AGAIN) {
		if ( conf->log ) {
			ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of Accept-Language header \"%s\"", value.data);
		}
		rc = NGX_ERROR;
	}

	return rc;
}

static ngx_int_t ngx_header_inspect_contentencoding_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
	ngx_int_t rc = NGX_AGAIN;
	ngx_uint_t i = 0;
	ngx_uint_t v;

	if ((value.len == 0) || ((value.len == 1) && (value.data[0] == '*'))) {
		if ( conf->log ) {
			ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: Content-Encoding header \"%s\" too short", value.data);
		}
		return NGX_ERROR;
	}

	while ( i < value.len) {
		if (value.data[i] == '*') {
			if ( conf->log ) {
				ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: illegal char at position %d in Content-Encoding header \"%s\"", i, value.data);
			}
			rc = NGX_ERROR;
			break;
		}
		if (ngx_header_inspect_parse_contentcoding(&(value.data[i]), value.len-i, &v) != NGX_OK) {
			if ( conf->log ) {
				ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: invalid content-coding at position %d in Content-Encoding header \"%s\"", i, value.data);
			}
			rc = NGX_ERROR;
			break;
		}
		i += v;
		if ((value.data[i] == ' ') && (i < value.len)) {
			i++;
		}
		if (i == value.len) {
			rc = NGX_OK;
			break;
		}
		if (value.data[i] != ',') {
			if ( conf->log ) {
				ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: illegal char at position %d in Content-Encoding header \"%s\"", i, value.data);
			}
			rc = NGX_ERROR;
			break;
		}
		i++;
		if ((value.data[i] == ' ') && (i < value.len)) {
			i++;
		}
	}

	if (rc == NGX_AGAIN) {
		if ( conf->log ) {
			ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of Content-Encoding header \"%s\"", value.data);
		}
		rc = NGX_ERROR;
	}

	return rc;

}

static ngx_int_t ngx_header_inspect_acceptencoding_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
	ngx_int_t rc = NGX_AGAIN;
	ngx_uint_t i = 0;
	ngx_uint_t v;

	if ((value.len == 0) || ((value.len == 1) && (value.data[0] == '*'))) {
		return NGX_OK;
	}

	while ( i < value.len) {
		if (ngx_header_inspect_parse_contentcoding(&(value.data[i]), value.len-i, &v) != NGX_OK) {
			if ( conf->log ) {
				ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: invalid content-coding at position %d in Accept-Encoding header \"%s\"", i, value.data);
			}
			rc = NGX_ERROR;
			break;
		}
		i += v;
		if ((value.data[i] == ' ') && (i < value.len)) {
			i++;
		}
		if (i == value.len) {
			rc = NGX_OK;
			break;
		}
		if (value.data[i] == ';') {
			i++;
			if (i >= value.len) {
				if ( conf->log ) {
					ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of Accept-Encoding header \"%s\"", value.data);
				}
				rc = NGX_ERROR;
				break;
			}
			if ((value.data[i] == ' ') && (i < value.len)) {
				i++;
			}
			if (ngx_header_inspect_parse_qvalue(&(value.data[i]), value.len-i, &v) != NGX_OK) {
				if ( conf->log ) {
					ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: invalid qvalue at position %d in Accept-Encoding header \"%s\"", i, value.data);
				}
				rc = NGX_ERROR;
				break;
			}
			i += v;
			if ((value.data[i] == ' ') && (i < value.len)) {
				i++;
			}
			if (i == value.len) {
				rc = NGX_OK;
				break;
			}
		}
		if (value.data[i] != ',') {
			if ( conf->log ) {
				ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: illegal char at position %d in Accept-Encoding header \"%s\"", i, value.data);
			}
			rc = NGX_ERROR;
			break;
		}
		i++;
		if ((value.data[i] == ' ') && (i < value.len)) {
			i++;
		}
	}

	if (rc == NGX_AGAIN) {
		if ( conf->log ) {
			ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of Accept-Encoding header \"%s\"", value.data);
		}
		rc = NGX_ERROR;
	}

	return rc;
}

static ngx_int_t ngx_header_inspect_parse_cache_directive(u_char *data, ngx_uint_t maxlen, ngx_uint_t *len) {
	ngx_uint_t i = 0;
	if ( (maxlen >= 8) && (ngx_strncmp("no-cache", data, 8) == 0) ) {
		*len = 8;
		return NGX_OK;
	}
	if ( (maxlen >= 8) && (ngx_strncmp("no-store", data, 8) == 0) ) {
		*len = 8;
		return NGX_OK;
	}
	if ( (maxlen >= 12) && (ngx_strncmp("no-transform", data, 12) == 0) ) {
		*len = 12;
		return NGX_OK;
	}
	if ( (maxlen >= 14) && (ngx_strncmp("only-if-cached", data, 14) == 0) ) {
		*len = 14;
		return NGX_OK;
	}
	if ( (maxlen >= 9) && (ngx_strncmp("max-stale", data, 9) == 0) ) {
		*len = 9;
		if ( maxlen >= 11 ) {
			if ( (data[9] == '=') && (data[10] >= '0') && (data[10] <= '9') ) {
				i = 11;
				while ( (i <= maxlen) && (data[i] >= '0') && (data[i] <= '9') ) {
					i++;
				}
				*len = i;
			}
		}
		return NGX_OK;
	}
	if ( (maxlen >= 9) && (ngx_strncmp("max-age=", data, 8) == 0) && (data[8] >= '0') && (data[8] <= '9') ) {
		i = 9;
		while ( (i < maxlen) && (data[i] >= '0') &&(data[i] <= '9') ) {
			i++;
		}
		*len = i;
		return NGX_OK;
	}
	if ( (maxlen >= 11) && (ngx_strncmp("min-fresh=", data, 10) == 0) && (data[10] >= '0') && (data[10] <= '9') ) {
		i = 11;
		while ( (i < maxlen) && (data[i] >= '0') &&(data[i] <= '9') ) {
			i++;
		}
		*len = i;
		return NGX_OK;
	}

	return NGX_ERROR;
}

static ngx_int_t ngx_header_inspect_cachecontrol_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
	ngx_int_t rc = NGX_AGAIN;
	ngx_uint_t i = 0;
	ngx_uint_t v;

	if (value.len < 1) {
		if ( conf->log ) {
			ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: Cache-Control header \"%s\" too short", value.data);
		}
		return NGX_ERROR;
	}

	while ( i < value.len ) {
		if ( ngx_header_inspect_parse_cache_directive(&(value.data[i]), value.len-i, &v) != NGX_OK ) {
			if ( conf->log ) {
				ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: invalid cache-directive at position %d in Cache-Control header \"%s\"", i, value.data);
			}
			rc = NGX_ERROR;
			break;
		}
		i += v;
		if ((value.data[i] == ' ') && (i < value.len)) {
			i++;
		}
		if (i == value.len) {
			rc = NGX_OK;
			break;
		}
		if (value.data[i] != ',') {
			if ( conf->log ) {
				ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: illegal char at position %d in Cache-Control header \"%s\"", i, value.data);
			}
			rc = NGX_ERROR;
			break;
		}
		i++;
		if ((value.data[i] == ' ') && (i < value.len)) {
			i++;
		}
	}
	if ( rc == NGX_AGAIN ) {
		if ( conf->log ) {
			ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of Cache-Control header \"%s\"", value.data);
		}
		rc = NGX_ERROR;
	}

	return rc;
}

static ngx_int_t ngx_header_inspect_referer_header(char* header, ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
	enum referer_header_states { RS_START, RS_SCHEME, RS_COLON, RS_SLASH1, RS_SLASH2, RS_HOST, RS_BR1, RS_IP6, RS_BR2, RS_COLON2, RS_PORT, RS_PATH } state;
	ngx_uint_t i;
	ngx_int_t rc = NGX_OK;
	u_char d;

	if ( value.len < 1 ) {
		if ( conf->log ) {
			ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: %s header \"%s\" too short", header, value.data);
		}
		return NGX_ERROR;
	}

	switch ( value.data[0] ) {
		case '/':
			/* relativePath */
			return NGX_OK;
			break;
		case 'h':
		case 'f':
			/* absoluteURI */
			state = RS_START;
			for ( i = 0; i < value.len ; i++ ) {
				d = value.data[i];

				if (
					((d >= 'g') && (d <= 'z')) ||
					((d >= 'G') && (d <= 'Z')) ||
					(d == '.')
				) {
					switch ( state ) {
						case RS_START:
							if (
								!(
								((value.len > 4) && (ngx_strncmp("http:", value.data, 5) == 0)) ||
								((value.len > 5) && (ngx_strncmp("https:", value.data, 6) == 0)) ||
								((value.len > 3) && (ngx_strncmp("ftp:", value.data, 4) == 0)) ||
								((value.len > 4) && (ngx_strncmp("ftps:", value.data, 5) == 0))
								)
							) {
								if ( conf->log ) {
									ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unknown scheme at begin of %s header \"%s\"", header, value.data);
								}
								return NGX_ERROR;
							}
							state = RS_SCHEME;
							break;
						case RS_SLASH2:
							state = RS_HOST;
							break;
						case RS_HOST:
						case RS_PATH:
						case RS_SCHEME:
							break;
						default:
							rc = NGX_ERROR;
					}
				} else if (
					((d >= 'a') && (d <= 'f')) ||
					((d >= 'A') && (d <= 'F'))
				) {
					switch ( state ) {
						case RS_START:
							if (
								!(
								((value.len > 4) && (ngx_strncmp("http:", value.data, 5) == 0)) ||
								((value.len > 5) && (ngx_strncmp("https:", value.data, 6) == 0)) ||
								((value.len > 3) && (ngx_strncmp("ftp:", value.data, 4) == 0)) ||
								((value.len > 4) && (ngx_strncmp("ftps:", value.data, 5) == 0))
								)
							) {
								if ( conf->log ) {
									ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unknown scheme at begin of %s header \"%s\"", header, value.data);
								}
								return NGX_ERROR;
							}
							state = RS_SCHEME;
							break;
						case RS_SLASH2:
							state = RS_HOST;
							break;
						case RS_BR1:
							state = RS_IP6;
							break;
						case RS_HOST:
						case RS_PATH:
						case RS_SCHEME:
						case RS_IP6:
							break;
						default:
							rc = NGX_ERROR;
					}
				} else if ( (d >= '0') && (d <= '9') ) {
					switch ( state ) {
						case RS_SLASH2:
							state = RS_HOST;
							break;
						case RS_COLON2:
							state = RS_PORT;
							break;
						case RS_BR1:
							state = RS_IP6;
							break;
						case RS_PORT:
						case RS_HOST:
						case RS_PATH:
						case RS_IP6:
							break;
						default:
							rc = NGX_ERROR;
					}
				} else if ( d == '/' ) {
					switch ( state ) {
						case RS_COLON:
							state = RS_SLASH1;
							break;
						case RS_SLASH1:
							state = RS_SLASH2;
							break;
						case RS_PORT:
						case RS_HOST:
						case RS_BR2:
							state = RS_PATH;
							break;
						case RS_PATH:
							break;
						default:
							rc = NGX_ERROR;
					}
				} else if ( d == ':' ) {
					switch ( state ) {
						case RS_SCHEME:
							state = RS_COLON;
							break;
						case RS_HOST:
						case RS_BR2:
							state = RS_COLON2;
							break;
						case RS_BR1:
							state = RS_IP6;
							break;
						case RS_PATH:
						case RS_IP6:
							break;
						default:
							rc = NGX_ERROR;
					}
				} else if ( d == '[' ) {
					switch ( state ) {
						case RS_SLASH2:
							state = RS_BR1;
							break;
						case RS_PATH:
							break;
						default:
							rc = NGX_ERROR;
					}
				} else if ( d == ']' ) {
					switch ( state ) {
						case RS_IP6:
							state = RS_BR2;
							break;
						case RS_PATH:
							break;
						default:
							rc = NGX_ERROR;
					}
				} else {
					switch ( state ) {
						case RS_PATH:
							break;
						default:
							rc = NGX_ERROR;
					}
				}
				if ( rc == NGX_ERROR ) {
					if ( conf->log ) {
						ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: illegal character at position %d of %s header \"%s\"", i, header, value.data);
					}
					return NGX_ERROR;
				}
			}
			switch ( state ) {
				case RS_PATH:
				case RS_PORT:
				case RS_HOST:
				case RS_BR2:
					return NGX_OK;
				default:
					if ( conf->log ) {
						ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of %s header \"%s\"", header, value.data);
					}
					return NGX_ERROR;
			}
			break;
		default:
			if ( conf->log ) {
				ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: illegal character at begin of %s header \"%s\"", header, value.data);
			}
			return NGX_ERROR;
	}
}

static ngx_int_t ngx_header_inspect_transferencoding_header(char* header, ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
	ngx_uint_t i;
	ngx_int_t rc = NGX_OK;
	enum transferencoding_header_states { TS_START, TS_FIELD, TS_PARDELIM, TS_PARKEY, TS_PAREQ, TS_PARVAL, TS_PARVALQ, TS_PARVALQE, TS_DELIM, TS_SPACE } state;
	u_char d;
	ngx_uint_t te_header = 0;

	if ( ngx_strncmp("TE", header, 2) == 0 ) {
		te_header = 1;
	}

	state = TS_START;
	for ( i = 0; i < value.len; i++ ) {
		d = value.data[i];

		if (
			((d >= 'a') && (d <= 'z')) ||
			((d >= 'A') && (d <= 'Z')) ||
			((d >= '0') && (d <= '9'))
		) {
			switch ( state ) {
				case TS_START:
				case TS_SPACE:
					/* ensure transfer-codings is one of chunked, compress, deflate, gzip or identity */
					state = TS_FIELD;
					if (
						!(
							((value.len-i>=7) && (ngx_strncmp("chunked", &(value.data[i]),7) == 0) && ((value.data[i+7] == ',')||(value.data[i+7] == ';')||(value.data[i+7] == '\0'))) ||
							((value.len-i>=8) && (ngx_strncmp("compress", &(value.data[i]),8) == 0) && ((value.data[i+8] == ',')||(value.data[i+8] == ';')||(value.data[i+8] == '\0'))) ||
							((value.len-i>=7) && (ngx_strncmp("deflate", &(value.data[i]),7) == 0) && ((value.data[i+7] == ',')||(value.data[i+7] == ';')||(value.data[i+7] == '\0'))) ||
							((value.len-i>=4) && (ngx_strncmp("gzip", &(value.data[i]),4) == 0) && ((value.data[i+4] == ',')||(value.data[i+4] == ';')||(value.data[i+4] == '\0'))) ||
							((value.len-i>=8) && (ngx_strncmp("identity", &(value.data[i]),8) == 0) && ((value.data[i+8] == ',')||(value.data[i+8] == ';')||(value.data[i+8] == '\0'))) ||
							((te_header == 1) && (value.len-i>=8) && (ngx_strncmp("trailers", &(value.data[i]),8) == 0) && ((value.data[i+8] == ',')||(value.data[i+8] == ';')||(value.data[i+8] == '\0')))
						)
					) {
						if ( conf->log ) {
							ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: illegal field at position %d in %s header \"%s\"", i, header, value.data);
						}
						return NGX_ERROR;
					}
					break;
				case TS_PARDELIM:
					/* TODO: if parkey is 'q', validate q-value */
					state = TS_PARKEY;
					break;
				case TS_PAREQ:
					state = TS_PARVAL;
					break;
				case TS_FIELD:
				case TS_PARKEY:
				case TS_PARVAL:
				case TS_PARVALQ:
					break;
				default:
					rc = NGX_ERROR;
			}
		} else if ( d == '.' ) {
			switch ( state ) {
				case TS_PARVAL:
				case TS_PARVALQ:
					break;
				default:
					rc = NGX_ERROR;
			}
		} else if ( d == ',' ) {
			switch ( state ) {
				case TS_FIELD:
				case TS_PARVAL:
				case TS_PARVALQE:
					state = TS_DELIM;
					break;
				case TS_PARVALQ:
					break;
				default:
					rc = NGX_ERROR;
			}
		} else if ( d == ' ' ) {
			switch ( state ) {
				case TS_DELIM:
					state = TS_SPACE;
					break;
				case TS_PARVAL:
				case TS_PARVALQ:
				case TS_PARDELIM:
					break;
				default:
					rc = NGX_ERROR;
			}
		} else if ( d == ';' ) {
			switch ( state ) {
				case TS_FIELD:
				case TS_PARVAL:
				case TS_PARVALQE:
					state = TS_PARDELIM;
					break;
				case TS_PARVALQ:
					break;
				default:
					rc = NGX_ERROR;
			}
		} else if ( d == '=' ) {
			switch ( state ) {
				case TS_PARKEY:
					state = TS_PAREQ;
					break;
				case TS_PARVALQ:
					break;
				default:
					rc = NGX_ERROR;
			}
		} else if ( d == '"' ) {
			switch ( state ) {
				case TS_PAREQ:
					state = TS_PARVALQ;
					break;
				case TS_PARVALQ:
					state = TS_PARVALQE;
					break;
				default:
					rc = NGX_ERROR;
			}
		} else {
			switch ( state ) {
				case TS_PARVALQ:
					break;
				default:
					rc = NGX_ERROR;
			}
		}
		if ( rc == NGX_ERROR ) {
			if ( conf->log ) {
				ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: illegal char at position %d in %s header \"%s\"", i, header, value.data);
			}
			return NGX_ERROR;
		}
	}
	switch ( state ) {
		case TS_FIELD:
		case TS_PARVAL:
		case TS_PARVALQE:
			break;
		case TS_START:
			if ( te_header == 1 ) {
				break;
			}
		default:
			if ( conf->log ) {
				ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of %s header \"%s\"", header, value.data);
			}
			return NGX_ERROR;
	}

	return NGX_OK;
}

static ngx_int_t ngx_header_inspect_trailer_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
	ngx_uint_t i;
	ngx_int_t rc = NGX_OK;
	enum trail_header_states { TS_START, TS_FIELD, TS_DELIM, TS_SPACE } state;
	u_char d;

	state = TS_START;
	for ( i = 0; i < value.len; i++ ) {
		d = value.data[i];

		if (
			((d >= 'a') && (d <= 'z')) ||
			((d >= 'A') && (d <= 'Z')) ||
			((d >= '0') && (d <= '9')) ||
			(d == '-')
		) {
			switch ( state ) {
				case TS_START:
				case TS_SPACE:
					/* ensure field is not Transfer-Encondig, Content-Length or Trailer */
					if (
						(((value.len-i)>=17) && (ngx_strncmp("Transfer-Encoding", &(value.data[i]), 17) == 0) && ((value.data[i+17] == ',') || (value.data[i+17] == '\0'))) ||
						(((value.len-i)>=14) && (ngx_strncmp("Content-Length", &(value.data[i]), 14) == 0) && ((value.data[i+14] == ',') || (value.data[i+14] == '\0'))) ||
						(((value.len-i)>=7) && (ngx_strncmp("Trailer", &(value.data[i]), 7) == 0) && ((value.data[i+7] == ',') || (value.data[i+7] == '\0')))
					) {
						if ( conf->log ) {
							ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: illegal field at position %d in Trailer header \"%s\"", i, value.data);
						}
						return NGX_ERROR;
					}
					state = TS_FIELD;
					break;
				case TS_FIELD:
					break;
				default:
					rc = NGX_ERROR;
			}
		} else if ( d == ',' ) {
			switch ( state ) {
				case TS_FIELD:
					state = TS_DELIM;
					break;
				default:
					rc = NGX_ERROR;
			}
		} else if ( d == ' ' ) {
			switch ( state ) {
				case TS_DELIM:
					state = TS_SPACE;
					break;
				default:
					rc = NGX_ERROR;
			}
		} else {
			rc = NGX_ERROR;
		}
		if ( rc == NGX_ERROR ) {
			if ( conf->log ) {
				ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: illegal character at position %d in Trailer header \"%s\"", i, value.data);
			}
			return NGX_ERROR;
		}
	}
	if ( state != TS_FIELD ) {
		if ( conf->log ) {
			ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of Trailer header \"%s\"", value.data);
		}
		return NGX_ERROR;
	}

	return NGX_OK;
}

static ngx_int_t ngx_header_inspect_warning_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
	ngx_uint_t i;
	ngx_uint_t v;
	ngx_int_t rc = NGX_OK;
	enum warn_header_states { WS_START, WS_CODE1, WS_CODE2, WS_CODE3, WS_SP1, WS_HOST, WS_COLON, WS_PORT, WS_SP2, WS_TXT, WS_TXTE, WS_SP3, WS_DATE, WS_DELIM, WS_SPACE } state;
	u_char d;

	state = WS_START;
	for ( i = 0; i < value.len ; i++ ) {
		d = value.data[i];

		if ( (d >= '0') && (d <= '9') ) {
			switch ( state ) {
				case WS_START:
				case WS_SPACE:
					state = WS_CODE1;
					break;
				case WS_CODE1:
					state = WS_CODE2;
					break;
				case WS_CODE2:
					state = WS_CODE3;
					break;
				case WS_SP1:
					state = WS_HOST;
					break;
				case WS_COLON:
					state = WS_PORT;
					break;
				case WS_HOST:
				case WS_PORT:
				case WS_TXT:
					break;
				default:
					rc = NGX_ERROR;
			}
		} else if ( ((d >= 'a') && (d <= 'z')) || ((d >= 'A') && (d <= 'Z')) ) {
			switch ( state ) {
				case WS_SP1:
					state = WS_HOST;
					break;
				case WS_HOST:
				case WS_TXT:
					break;
				default:
					rc = NGX_ERROR;
			}
		} else if ( (d == '-') || (d == '.') ) {
			switch ( state ) {
				case WS_HOST:
				case WS_TXT:
					break;
				default:
					rc = NGX_ERROR;
			}
		} else if ( d == ':' ) {
			switch ( state ) {
				case WS_HOST:
					state = WS_COLON;
					break;
				case WS_TXT:
					break;
				default:
					rc = NGX_ERROR;
			}
		} else if ( d == ',' ) {
			switch ( state ) {
				case WS_DATE:
				case WS_TXTE:
					state = WS_DELIM;
					break;
				case WS_TXT:
					break;
				default:
					rc = NGX_ERROR;
			}
		} else if ( d == ' ' ) {
			switch ( state ) {
				case WS_CODE3:
					state = WS_SP1;
					break;
				case WS_HOST:
				case WS_PORT:
					state = WS_SP2;
					break;
				case WS_TXTE:
					state = WS_SP3;
					break;
				case WS_DELIM:
					state = WS_SPACE;
					break;
				case WS_TXT:
					break;
				default:
					rc = NGX_ERROR;
			}
		} else if ( d == '"' ) {
			switch ( state ) {
				case WS_SP2:
					state = WS_TXT;
					break;
				case WS_TXT:
					state = WS_TXTE;
					break;
				case WS_SP3:
					state = WS_DATE;
					i++; /* skip qoute */
					if ( ngx_header_inspect_http_date(&(value.data[i]), value.len-i, &v) != NGX_OK ) {
						if ( conf->log ) {
							ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: illegal date at position %d in Warning header \"%s\"", i, value.data);
						}
						return NGX_ERROR;
					}
					i += v;
					if ( i >= value.len ) {
						if ( conf->log ) {
							ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of Warning header \"%s\"", value.data);
						}
						return NGX_ERROR;
					}
					if ( value.data[i] != '"' ) {
						rc = NGX_ERROR;
					}
					break;
				default:
					rc = NGX_ERROR;
			}
		} else {
			switch ( state ) {
				case WS_TXT:
					break;
				default:
					rc = NGX_ERROR;
			}
		}
		if ( rc == NGX_ERROR ) {
			if ( conf->log ) {
				ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: illegal character at position %d in Warning header \"%s\"", i, value.data);
			}
			return NGX_ERROR;
		}
	}
	switch ( state ) {
		case WS_TXTE:
		case WS_DATE:
			break;
		default:
			if ( conf->log ) {
				ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of Warning header \"%s\"", value.data);
			}
			return NGX_ERROR;
	}

	return NGX_OK;
}

static ngx_int_t ngx_header_inspect_expect_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {

	/* currently only the 'known' "100-continue" value is allowed */
	if ( (value.len == 12) && (ngx_strncasecmp((u_char *)"100-continue", value.data, 12) == 0) ) {
		return NGX_OK;
	} else {
		if ( conf->log ) {
			ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unknown value in Expect header \"%s\"", value.data);
		}
		return NGX_ERROR;
	}
}

static ngx_int_t ngx_header_inspect_authorization_header(char* header, ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
	ngx_uint_t i;
	ngx_int_t rc = NGX_OK;
	enum digest_header_states { DS_START, DS_KEY, DS_EQ, DS_VAL, DS_VALQ, DS_VALQE, DS_DELIM, DS_SPACE } state;
	u_char d;

	if ( value.len == 0 ) {
		return NGX_OK;
	}

	if ( (value.len >= 6) && (ngx_strncmp("Basic ", value.data, 6) == 0) ) {
		return ngx_header_inspect_parse_base64(header, conf, log, &(value.data[6]), value.len-6);
	}

	if ( (value.len >= 7) && (ngx_strncmp("Digest ", value.data, 7) == 0) ) {
		i = 7; /* start after "Digest " */
		state = DS_START;
		for ( ; i < value.len; i++ ) {
			d = value.data[i];

			if ( (d >= 'a') && (d <= 'z') ) {
				switch ( state ) {
					case DS_START:
					case DS_SPACE:
						state = DS_KEY;
						if (
							!(
								(((value.len-i) >= 9) && (ngx_strncmp("username=", &(value.data[i]), 9) == 0)) ||
								(((value.len-i) >= 6) && (ngx_strncmp("realm=", &(value.data[i]), 6) == 0)) ||
								(((value.len-i) >= 6) && (ngx_strncmp("nonce=", &(value.data[i]), 6) == 0)) ||
								(((value.len-i) >= 4) && (ngx_strncmp("uri=", &(value.data[i]), 4) == 0)) ||
								(((value.len-i) >= 9) && (ngx_strncmp("response=", &(value.data[i]), 9) == 0)) ||
								(((value.len-i) >= 10) && (ngx_strncmp("algorithm=", &(value.data[i]), 10) == 0)) ||
								(((value.len-i) >= 7) && (ngx_strncmp("cnonce=", &(value.data[i]), 7) == 0)) ||
								(((value.len-i) >= 7) && (ngx_strncmp("opaque=", &(value.data[i]), 7) == 0)) ||
								(((value.len-i) >= 4) && (ngx_strncmp("qop=", &(value.data[i]), 4) == 0)) ||
								(((value.len-i) >= 3) && (ngx_strncmp("nc=", &(value.data[i]), 3) == 0))
							)
						) {
							if ( conf->log ) {
								ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unknown auth-param at position %d in %s header \"%s\"", i, header, value.data);
							}
							return NGX_ERROR;
						}
						break;
					case DS_EQ:
						state = DS_VAL;
						break;
					case DS_VAL:
					case DS_VALQ:
					case DS_KEY:
						break;
					default:
						rc = NGX_ERROR;
				}
			} else if ( d == ',' ) {
				switch ( state ) {
					case DS_VAL:
					case DS_VALQE:
					case DS_EQ:
						state = DS_DELIM;
						break;
					case DS_VALQ:
						break;
					default:
						rc = NGX_ERROR;
				}
			} else if ( d == '=' ) {
				switch ( state ) {
					case DS_KEY:
						state = DS_EQ;
						break;
					case DS_VALQ:
						break;
					default:
						rc = NGX_ERROR;
				}

			} else if ( d == ' ' ) {
				switch ( state ) {
					case DS_DELIM:
						state = DS_SPACE;
						break;
					case DS_VALQ:
						break;
					default:
						rc = NGX_ERROR;
				}
			} else if ( d == '"' ) {
				switch ( state ) {
					case DS_EQ:
						state = DS_VALQ;
						break;
					case DS_VALQ:
						state = DS_VALQE;
						break;
					default:
						rc = NGX_ERROR;
				}
			} else if ( (d != '"') ) {
				switch ( state ) {
					case DS_VAL:
					case DS_VALQ:
						break;
					default:
						rc = NGX_ERROR;
				}
			} else {
				rc = NGX_ERROR;
			}
			if ( rc == NGX_ERROR ) {
				if ( conf->log ) {
					ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: illegal character at position %d in %s header \"%s\"", i, header, value.data);
				}
				return NGX_ERROR;
			}
		}
		switch ( state ) {
			case DS_VALQE:
			case DS_VAL:
				break;
			default:
				if ( conf->log ) {
					ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of %s header \"%s\"", header, value.data);
				}
				return NGX_ERROR;
		}
		return NGX_OK;
	}

	if ( conf->log ) {
		ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unknown auth-scheme in %s header \"%s\"", header, value.data);
	}
	return NGX_ERROR;
}

static ngx_int_t ngx_header_inspect_contentmd5_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
	return ngx_header_inspect_parse_base64("Content-MD5", conf, log, value.data, value.len);
}

static ngx_int_t ngx_header_inspect_parse_base64(char* header, ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, u_char *data, ngx_uint_t maxlen) {
	ngx_uint_t i;
	u_char d;

	if ( maxlen == 0 ) {
		if ( conf->log ) {
			ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: empty base64 value in %s header", header);
		}
		return NGX_ERROR;
	}

	for ( i = 0; i < maxlen; i++ ) {
		d = data[i];

		if ( (d >= '0') && (d <= '9') ) {
			continue;
		}
		if ( (d >= 'a') && (d <= 'z') ) {
			continue;
		}
		if ( (d >= 'A') && (d <= 'Z') ) {
			continue;
		}
		if ( (d == '+') || (d == '/') ) {
			continue;
		}
		if ( d == '=' ) {
			continue;
			i++;
			while ( i < maxlen ) {
				if ( data[i] != '=' ) {
					if ( conf->log ) {
						ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: trailing characters at position %d in base64 value \"%s\" of %s header", i, data, header);
					}
					return NGX_ERROR;
				}
				i++;
			}
			break;
		}
		if ( conf->log ) {
			ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: illegal character at position %d in base64 value \"%s\" of %s header", i, data, header);
		}
		return NGX_ERROR;
	}

	return NGX_OK;
}

static ngx_int_t ngx_header_inspect_contenttype_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
	ngx_uint_t v;

	if ( value.len < 3 ) {
		if ( conf->log ) {
			ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: Content-Type header \"%s\" too short", value.data);
		}
		return NGX_ERROR;
	}

	if (ngx_header_inspect_parse_mediatype(value.data, value.len, &v) != NGX_OK) {
		if ( conf->log ) {
			ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: invalid media-type in Content-Type header \"%s\"", value.data);
		}
		return NGX_ERROR;
	}

	return NGX_OK;
}

static ngx_int_t ngx_header_inspect_pragma_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
	/* currently only the 'known' "no-cache" value is allowed */
	if ( (value.len == 8) && (ngx_strncasecmp((u_char *)"no-cache", value.data, 8) == 0) ) {
		return NGX_OK;
	} else {
		if ( conf->log ) {
			ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unknown value in Pragama header \"%s\"", value.data);
		}
		return NGX_ERROR;
	}
}

static ngx_int_t ngx_header_inspect_from_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
	ngx_uint_t i = 0;
	u_char d;
	ngx_int_t rc = NGX_OK;
	enum from_header_states { FS_START, FS_LOCALPART, FS_AT, FS_DOMAIN, FS_DOT } state;

	if ( value.len < 3 ) {
		if ( conf->log ) {
			ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: From header \"%s\" too short", value.data);
		}
		return NGX_ERROR;
	}

	state = FS_START;
	for ( i = 0; i < value.len; i++ ) {
		d = value.data[i];
		if (
			((d >= '0') && (d <= '9')) ||
			((d >= 'a') && (d <= 'z')) ||
			((d >= 'A') && (d <= 'Z')) ||
			(d == '-')
		) {
			switch ( state ) {
				case FS_START:
					state = FS_LOCALPART;
					break;
				case FS_AT:
				case FS_DOT:
					state = FS_DOMAIN;
					break;
				case FS_LOCALPART:
				case FS_DOMAIN:
					break;
				default:
					rc = NGX_ERROR;
			}
		} else if (d == '+') {
			switch ( state ) {
				case FS_START:
					state = FS_LOCALPART;
					break;
				case FS_LOCALPART:
					break;
				default:
					rc = NGX_ERROR;
			}
		} else if (d == '.') {
			switch ( state ) {
				case FS_START:
					state = FS_LOCALPART;
					break;
				case FS_LOCALPART:
					break;
				case FS_DOMAIN:
					state = FS_DOT;
					break;
				default:
					rc = NGX_ERROR;
			}
		} else if (d == '@') {
			switch ( state ) {
				case FS_LOCALPART:
					state = FS_AT;
					break;
				default:
					rc = NGX_ERROR;
			}
		} else {
			rc = NGX_ERROR;
		}
		if ( rc == NGX_ERROR ) {
			if ( conf->log ) {
				ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: illegal character at position %d in From header \"%s\"", i, value.data);
			}
			return NGX_ERROR;
		}
	}
	if ( state != FS_DOMAIN ) {
		if ( conf->log ) {
			ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of From header \"%s\"", value.data);
		}
		return NGX_ERROR;
	}

	return NGX_OK;
}

static ngx_int_t ngx_header_inspect_via_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
	ngx_uint_t i = 0;
	u_char d;
	ngx_int_t rc = NGX_OK;
	enum via_header_states { VS_START, VS_PROT, VS_SLASH, VS_VER, VS_SPACE1, VS_HOST, VS_COLON, VS_PORT, VS_DELIM, VS_SPACE2, VS_PAREN, VS_PARENEND, VS_SPACE3 } state;

	if ( value.len < 3 ) {
		if ( conf->log ) {
			ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: Via header \"%s\" too short", value.data);
		}
		return NGX_ERROR;
	}

	state = VS_START;
	for ( i = 0; i < value.len; i++ ) {
		d = value.data[i];
		if ( ((d >= '0') && (d <= '9')) ) {
			switch ( state ) {
				case VS_START:
				case VS_SPACE3:
					state = VS_PROT;
					break;
				case VS_SLASH:
					state = VS_VER;
					break;
				case VS_SPACE1:
					state = VS_HOST;
					break;
				case VS_COLON:
					state = VS_PORT;
					break;
				case VS_PROT:
				case VS_VER:
				case VS_PORT:
				case VS_HOST:
				case VS_PAREN:
					break;
				default:
					rc = NGX_ERROR;
			}
		} else if (
			((d >= 'a') && (d <= 'z')) ||
			((d >= 'A') && (d <= 'Z')) ||
			(d == '-') || (d == '.')
		) {
			switch ( state ) {
				case VS_START:
				case VS_SPACE3:
					state = VS_PROT;
					break;
				case VS_SLASH:
					state = VS_VER;
					break;
				case VS_SPACE1:
					state = VS_HOST;
					break;
				case VS_PROT:
				case VS_VER:
				case VS_HOST:
				case VS_PAREN:
					break;
				default:
					rc = NGX_ERROR;
			}
		} else if (d == ' ') {
			switch ( state ) {
				case VS_PROT:
				case VS_VER:
					state = VS_SPACE1;
					break;
				case VS_HOST:
				case VS_PORT:
					state = VS_SPACE2;
					break;
				case VS_DELIM:
					state = VS_SPACE3;
					break;
				case VS_SPACE1:
				case VS_SPACE2:
				case VS_SPACE3:
				case VS_PAREN:
					break;
				default:
					rc = NGX_ERROR;
			}
		} else if (d == '/') {
			switch ( state ) {
				case VS_PROT:
					state = VS_SLASH;
					break;
				case VS_PAREN:
					break;
				default:
					rc = NGX_ERROR;
			}
		} else if (d == ':') {
			switch ( state ) {
				case VS_HOST:
					state = VS_COLON;
					break;
				case VS_PAREN:
					break;
				default:
					rc = NGX_ERROR;
			}
		} else if (d == '(') {
			switch ( state ) {
				case VS_SPACE2:
					state = VS_PAREN;
					break;
				default:
					rc = NGX_ERROR;
			}
		} else if (d == ')') {
			switch ( state ) {
				case VS_PAREN:
					state = VS_PARENEND;
					break;
				default:
					rc = NGX_ERROR;
			}
		} else if (d == ',') {
			switch ( state ) {
				case VS_HOST:
				case VS_PORT:
				case VS_PARENEND:
					state = VS_DELIM;
					break;
				case VS_PAREN:
					break;
				default:
					rc = NGX_ERROR;
			}
		} else {
			rc = NGX_ERROR;
		}
		if ( rc == NGX_ERROR ) {
			if ( conf->log ) {
				ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: illegal character at position %d in Via header \"%s\"", i, value.data);
			}
			return NGX_ERROR;
		}
	}
	switch ( state ) {
		case VS_HOST:
		case VS_PORT:
		case VS_PARENEND:
			break;
		default:
			if ( conf->log ) {
				ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of Via header \"%s\"", value.data);
			}
			return NGX_ERROR;
	}

	return NGX_OK;
}

static ngx_int_t ngx_header_inspect_upgrade_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
	ngx_uint_t i = 0;
	u_char d;
	ngx_int_t rc = NGX_OK;
	enum upgrade_header_states { UPS_START, UPS_PROD, UPS_SLASH, UPS_VER, UPS_DELIM, UPS_SPACE } state;

	if ( value.len < 1 ) {
		if ( conf->log ) {
			ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: Upgrade header \"%s\" too short", value.data);
		}
		return NGX_ERROR;
	}

	state = UPS_START;
	for ( i = 0; i < value.len ; i++ ) {
		d = value.data[i];

		if (
			((d >= '0') && (d <= '9')) ||
			((d >= 'a') && (d <= 'z')) ||
			((d >= 'A') && (d <= 'Z')) ||
			(d == '-') || (d == '.')
		) {
			switch ( state ) {
				case UPS_START:
				case UPS_SPACE:
					state = UPS_PROD;
					break;
				case UPS_SLASH:
					state = UPS_VER;
					break;
				case UPS_PROD:
				case UPS_VER:
					break;
				default:
					rc = NGX_ERROR;
			}
		} else if ( d == '/' ) {
			switch ( state ) {
				case UPS_PROD:
					state = UPS_SLASH;
					break;
				default:
					rc = NGX_ERROR;
			}
		} else if ( d == ' ' ) {
			switch ( state ) {
				case UPS_DELIM:
					state = UPS_SPACE;
					break;
				case UPS_SPACE:
					break;
				default:
					rc = NGX_ERROR;
			}
		} else if ( d == ',' ) {
			switch ( state ) {
				case UPS_PROD:
				case UPS_VER:
					state = UPS_DELIM;
					break;
				default:
					rc = NGX_ERROR;
			}
		} else {
			rc = NGX_ERROR;
		}
		if ( rc == NGX_ERROR ) {
			if ( conf->log ) {
				ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: illegal character at position %d in Upgrade header \"%s\"", i, value.data);
			}
			return NGX_ERROR;
		}
	}
	switch ( state ) {
		case UPS_PROD:
		case UPS_VER:
			break;
		default:
			if ( conf->log ) {
				ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of Upgrade header \"%s\"", value.data);
			}
			return NGX_ERROR;
	}

	return NGX_OK;
}

static ngx_int_t ngx_header_inspect_useragent_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
	ngx_uint_t i = 0;
	u_char d;
	ngx_int_t rc = NGX_OK;
	enum useragent_header_states { UAS_START, UAS_PROD, UAS_SLASH, UAS_VER, UAS_SPACE, UAS_PAREN } state;


	if ( value.len < 1 ) {
		if ( conf->log ) {
			ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: User-Agent header \"%s\" too short", value.data);
		}
		return NGX_ERROR;
	}

	state = UAS_START;
	for ( i = 0; i < value.len ; i++ ) {
		d = value.data[i];
		if (
			((d >= '0') && (d <= '9')) ||
			((d >= 'a') && (d <= 'z')) ||
			((d >= 'A') && (d <= 'Z')) ||
			(d == '-') || (d == '.')
		) {
			switch ( state ) {
				case UAS_START:
				case UAS_SPACE:
					state = UAS_PROD;
					break;
				case UAS_PROD:
				case UAS_VER:
				case UAS_PAREN:
					break;
				case UAS_SLASH:
					state = UAS_VER;
					break;
				default:
					rc = NGX_ERROR;
			}
		} else if ( d == '/' ) {
			switch ( state ) {
				case UAS_PROD:
					state = UAS_SLASH;
					break;
				default:
					rc = NGX_ERROR;
			}
		} else if ( d == ' ' ) {
			switch ( state ) {
				case UAS_VER:
					state = UAS_SPACE;
					break;
				case UAS_SPACE:
				case UAS_PAREN:
					break;
				default:
					rc = NGX_ERROR;
			}
		} else if ( d == '(' ) {
			switch ( state ) {
				case UAS_SPACE:
					state = UAS_PAREN;
					break;
				default:
					rc = NGX_ERROR;
			}
		} else if ( d == ')' ) {
			switch ( state ) {
				case UAS_PAREN:
					state = UAS_SPACE;
					break;
				default:
					rc = NGX_ERROR;
			}
		} else if (
			(d == ',') || (d == ':') || (d == ';') ||
			(d == '+') || (d == '_')
		) {
			switch ( state ) {
				case UAS_PAREN:
					break;
				default:
					rc = NGX_ERROR;
			}
		} else {
			rc = NGX_ERROR;
		}
		if ( rc == NGX_ERROR ) {
			if ( conf->log ) {
				ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: illegal character at position %d in User-Agent header \"%s\"", i, value.data);
			}
			return NGX_ERROR;
		}
	}
	switch ( state ) {
		case UAS_SPACE:
		case UAS_PROD:
		case UAS_VER:
			break;
		default:
			if ( conf->log ) {
				ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of User-Agent header \"%s\"", value.data);
			}
			return NGX_ERROR;
	}

	return NGX_OK;
}

static ngx_int_t ngx_header_inspect_contentrange_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
	ngx_uint_t i = 0;
	ngx_int_t rc = NGX_OK;
	ngx_int_t a,b,c;
	enum contentrange_header_states {RHS_START, RHS_STAR1, RHS_NUM1,DELIM,RHS_NUM2,RHS_SLASH,RHS_STAR2, RHS_NUM3} state;

	if ( (value.len < 6) || (ngx_strncmp("bytes ", value.data, 6) != 0) ) {
		if ( conf->log ) {
			ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: Content-Range header \"%s\"  does not start with \"bytes \"", value.data);
		}
		return NGX_ERROR;
	}
	if ( value.len < 9 ) {
		if ( conf->log ) {
			ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: Content-Range header \"%s\" is too short", value.data);
		}
		return NGX_ERROR;
	}

	state = RHS_START;
	a = -1;
	b = -1;
	c = -1;

	i = 6; /* start after "bytes " */
	for ( ; i < value.len ; i++ ) {
		switch ( value.data[i] ) {
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
				switch ( state ) {
					case RHS_START:
						state = RHS_NUM1;
						a = (value.data[i] - '0');
						break;
					case RHS_NUM1:
						a = a*10+(value.data[i] - '0');
						break;
					case RHS_NUM2:
						b = b*10+(value.data[i] - '0');
						break;
					case RHS_NUM3:
						c = c*10+(value.data[i] - '0');
						break;
					case DELIM:
						state = RHS_NUM2;
						b = (value.data[i] - '0');
						break;
					case RHS_SLASH:
						state = RHS_NUM3;
						c = (value.data[i] - '0');
						break;
					default:
						rc = NGX_ERROR;
				}
				break;
			case '*':
				switch ( state ) {
					case RHS_START:
						state = RHS_STAR1;
						break;
					case RHS_SLASH:
						state = RHS_STAR2;
						break;
					default:
						rc = NGX_ERROR;
				}
				break;
			case '/':
				switch ( state ) {
					case RHS_STAR1:
					case RHS_NUM2:
						state = RHS_SLASH;
						break;
					default:
						rc = NGX_ERROR;
				}
				break;
			case '-':
				switch ( state ) {
					case RHS_NUM1:
						state = DELIM;
						break;
					default:
						rc = NGX_ERROR;
				}
				break;
			default:
				rc = NGX_ERROR;
		}
		if ( rc == NGX_ERROR ) {
			if ( conf->log ) {
				ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: illegal character at position %d in Content-Range header \"%s\"", i, value.data);
			}
			return NGX_ERROR;
		}
	}
	switch ( state ) {
		case RHS_NUM3:
		case RHS_STAR2:
			break;
		default:
			if ( conf->log ) {
				ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of Content-Range header \"%s\"", value.data);
			}
			return NGX_ERROR;
	}

	/* in "a-b/c" ensure a < b and b < c if any of them are defined */
	if ( (a != -1) && (b != -1) ) {
		if ( (a >= b) || ((c != -1) && (b >= c)) ) {
			if ( conf->log ) {
				ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: illegal range specification in Content-Range header \"%s\"", value.data);
			}
			return NGX_ERROR;
		}
	}

	return NGX_OK;
}

static ngx_int_t ngx_header_inspect_connection_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
	ngx_uint_t i = 0;

	while ( i < value.len ) {
		/* as per 13.5.1 of RFC2616 only allow Keep-Alive, Proxy-Authenticate, Proxy-Authorization, TE, Trailer, Transfer-Encoding and Upgrade headers in Connection header */
		if ( ((i+5) <= value.len) && (ngx_strncmp("close", &(value.data[i]), 5) == 0 ) ) {
			i += 5;
		} else if ( ((i+10) <= value.len) && (ngx_strncmp("keep-alive", &(value.data[i]), 10) == 0 ) ) {
			i += 10;
		} else if ( ((i+10) <= value.len) && (ngx_strncmp("Keep-Alive", &(value.data[i]), 10) == 0 ) ) {
			i += 10;
		} else if ( ((i+18) <= value.len) && (ngx_strncmp("Proxy-Authenticate", &(value.data[i]), 18) == 0 ) ) {
			i += 18;
		} else if ( ((i+19) <= value.len) && (ngx_strncmp("Proxy-Authorization", &(value.data[i]), 19) == 0 ) ) {
			i += 19;
		} else if ( ((i+2) <= value.len) && (ngx_strncmp("TE", &(value.data[i]), 2) == 0 ) ) {
			i += 2;
		} else if ( ((i+7) <= value.len) && (ngx_strncmp("Trailer", &(value.data[i]), 7) == 0 ) ) {
			i += 7;
		} else if ( ((i+17) <= value.len) && (ngx_strncmp("Transfer-Encoding", &(value.data[i]), 17) == 0 ) ) {
			i += 17;
		} else if ( ((i+7) <= value.len) && (ngx_strncmp("Upgrade", &(value.data[i]), 7) == 0 ) ) {
			i += 7;
		} else {
			if ( conf->log ) {
				ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: illegal value at position %d in Connection header \"%s\"", i, value.data);
			}
			return NGX_ERROR;
		}

		if ( (i < value.len) && (value.data[i] == ' ') ) {
			i++;
		}

		if ( i == value.len ) {
			return NGX_OK;
		}

		if ( (i < value.len) && (value.data[i] != ',') ) {
			if ( conf->log ) {
				ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: illegal character at position %d in Connection header \"%s\"", i, value.data);
			}
			return NGX_ERROR;
		}
		i++;

		if ( (i < value.len) && (value.data[i] == ' ') ) {
			i++;
		}
	}

	if ( conf->log ) {
		ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of Connection header \"%s\"", value.data);
	}
	return NGX_ERROR;
}

static ngx_int_t ngx_header_inspect_accept_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
	ngx_int_t rc = NGX_AGAIN;
	ngx_uint_t i = 0;
	ngx_uint_t v;

	if (value.len == 0) {
		return NGX_OK;
	}

	while ( i < value.len ) {
		if (ngx_header_inspect_parse_mediatype(&(value.data[i]), value.len-i, &v) != NGX_OK) {
			if ( conf->log ) {
				ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: invalid media-type at position %d in Accept header \"%s\"", i, value.data);
			}
			rc = NGX_ERROR;
			break;
		}
		i += v;
		if ((value.data[i] == ' ') && (i < value.len)) {
			i++;
		}
		if (i == value.len) {
			rc = NGX_OK;
			break;
		}
		if (value.data[i] == ';') {
			i++;
			if (i >= value.len) {
				if ( conf->log ) {
					ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of Accept header \"%s\"", value.data);
				}
				rc = NGX_ERROR;
				break;
			}
			if ((value.data[i] == ' ') && (i < value.len)) {
				i++;
			}
			if (ngx_header_inspect_parse_qvalue(&(value.data[i]), value.len-i, &v) != NGX_OK) {
				if ( conf->log ) {
					ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: invalid qvalue at position %d in Accept header \"%s\"", i, value.data);
				}
				rc = NGX_ERROR;
				break;
			}
			/* TODO: parse additional parameters */
			i += v;
			if ((value.data[i] == ' ') && (i < value.len)) {
				i++;
			}
			if (i == value.len) {
				rc = NGX_OK;
				break;
			}
		}
		if (value.data[i] != ',') {
			if ( conf->log ) {
				ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: illegal char at position %d in Accept header \"%s\"", i, value.data);
			}
			rc = NGX_ERROR;
			break;
		}
		i++;
		if ((value.data[i] == ' ') && (i < value.len)) {
			i++;
		}
	}

	if (rc == NGX_AGAIN) {
		if ( conf->log ) {
			ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of Accept header \"%s\"", value.data);
		}
		rc = NGX_ERROR;
	}

	return rc;
}

static ngx_int_t ngx_header_inspect_host_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
	u_char d = '\0';
	ngx_uint_t i = 0;

	if ( value.len == 0 ) {
		return NGX_OK;
	}

	if ( value.data[0] == '[' ) {
		i++;
		/* IPv6 address */
		while ( i < value.len ) {
			d = value.data[i];
			if (
				((d < '0') || (d > '9'))
				&& ((d < 'a') || (d > 'z'))
				&& ((d < 'A') || (d > 'Z'))
				&& (d != ':') && (d != '.')
				&& (d != ']')
			) {
				if ( conf->log ) {
					ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: illegal char at position %d in Host header \"%s\"", i, value.data);
				}
				return NGX_ERROR;
			}
			if ( d == ']' ) {
				break;
			}
			i++;
		}
		if ( d != ']' ) {
			if ( conf->log ) {
				ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of Host header \"%s\"", value.data);
			}
			return NGX_ERROR;
		}
		if ( i+1 < value.len ) {
			d = value.data[i+1];
		}
		i++;
	} else {
		/* IPv4 address or domain name */
		while ( i < value.len ) {
			d = value.data[i];

			if ( 
				((d < '0') || (d > '9'))
				&& ((d < 'a') || (d > 'z'))
				&& ((d < 'A') || (d > 'Z'))
				&& (d != '.') && (d != '-')
				&& ((d != ':') || (i == 0))
			) {
				if ( conf->log ) {
					ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: illegal char at position %d in Host header \"%s\"", i, value.data);
				}
				return NGX_ERROR;
			}
			if ( d == ':' ) {
				break;
			}
			i++;
		}
	}

	if ( (d == ':') && (i+1 < value.len) ) {
		i++;
		for ( ; i < value.len ; i++ ) {
			if ( (value.data[i] < '0') || (value.data[i] > '9') ) {
				if ( conf->log ) {
					ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: illegal char at position %d in Host header \"%s\"", i, value.data);
				}
				return NGX_ERROR;
			}
		}
	}

	if ( i != value.len ) {
		if ( conf->log ) {
			ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of Host header \"%s\"", value.data);
		}
		return NGX_ERROR;
	}

	return NGX_OK;
}

static ngx_int_t ngx_header_inspect_allow_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
	ngx_int_t rc = NGX_AGAIN;
	ngx_uint_t i = 0;

	if ( value.len == 0 ) {
		return NGX_OK;
	}

	while ( i < value.len ) {
		if ( (i+3 <= value.len) && (ngx_strncmp("GET", &(value.data[i]), 3) == 0) ) {
			i += 3;
		} else if ( (i+4 <= value.len) && (ngx_strncmp("POST", &(value.data[i]), 4) == 0) ) {
			i += 4;
		} else if ( (i+3 <= value.len) && (ngx_strncmp("PUT", &(value.data[i]), 3) == 0) ) {
			i += 3;
		} else if ( (i+4 <= value.len) && (ngx_strncmp("HEAD", &(value.data[i]), 4) == 0) ) {
			i += 4;
		} else if ( (i+6 <= value.len) && (ngx_strncmp("DELETE", &(value.data[i]), 6) == 0) ) {
			i += 6;
		} else if ( (i+7 <= value.len) && (ngx_strncmp("OPTIONS", &(value.data[i]), 7) == 0) ) {
			i += 7;
		} else if ( (i+5 <= value.len) && (ngx_strncmp("TRACE", &(value.data[i]), 5) == 0) ) {
			i += 5;
		} else if ( (i+7 <= value.len) && (ngx_strncmp("CONNECT", &(value.data[i]), 7) == 0) ) {
			i += 7;
		} else {
			if ( conf->log ) {
				ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: illegal method at position %d in Allow header \"%s\"", i, value.data);
				rc = NGX_ERROR;
				break;
			}
		}
		if ((value.data[i] == ' ') && (i < value.len)) {
			i++;
		}
		if (i == value.len) {
			rc = NGX_OK;
			break;
		}
		if (value.data[i] != ',') {
			if ( conf->log ) {
				ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: illegal char at position %d in Allow header \"%s\"", i, value.data);
			}
			rc = NGX_ERROR;
			break;
		}
		i++;
		if ((value.data[i] == ' ') && (i < value.len)) {
			i++;
		}
	}
	if (rc == NGX_AGAIN) {
		if ( conf->log ) {
			ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: unexpected end of Allow header \"%s\"", value.data);
		}
		rc = NGX_ERROR;
	}

	return rc;
}

static ngx_int_t ngx_header_inspect_ifrange_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, ngx_str_t value) {
	ngx_uint_t v = 0;

	if (((value.data[0] == 'W') && (value.data[1] == '/'))|| (value.data[0] == '"')) {
	/* 1. entity-tag */
		if ( (ngx_header_inspect_parse_entity_tag(value.data, value.len, &v) != NGX_OK) || (v != value.len) ) {
			if ( conf->log ) {
				ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: invalid entity-tag in If-Range header \"%s\"", value.data);
			}
			return NGX_ERROR;
		}
	} else {
	/* 2. HTTP-date */
		return ngx_header_inspect_date_header(conf, log, "If-Range", value);
	}

	return NGX_OK;
}

static ngx_int_t ngx_header_inspect_date_header(ngx_header_inspect_loc_conf_t *conf, ngx_log_t *log, char *header, ngx_str_t value) {
	ngx_uint_t v;

	/* HTTP-date */
	if ( ngx_header_inspect_http_date(value.data, value.len, &v) != NGX_OK ) {
		if ( conf->log ) {
			ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: invalid HTTP-date in \"%s\" header \"%s\"", header, value.data);
		}
		return NGX_ERROR;
	}
	if ( value.len != v ) {
		if ( conf->log ) {
			ngx_log_error(NGX_LOG_ALERT, log, 0, "header_inspect: trailing characters in \"%s\" header \"%s\"", header, value.data);
		}
		return NGX_ERROR;
	}

	return NGX_OK;
}



static ngx_int_t ngx_header_inspect_process_request(ngx_http_request_t *r) {
	ngx_header_inspect_loc_conf_t *conf;
	ngx_table_elt_t *h;
	ngx_list_part_t *part;
	ngx_uint_t i;
	ngx_int_t rc;

	conf = ngx_http_get_module_loc_conf(r, ngx_http_header_inspect_module);

	if (conf->inspect) {
		part = &r->headers_in.headers.part;
		do {
			h = part->elts;
			for (i = 0; i < part->nelts; i++) {
				if ((h[i].key.len == 5) && (ngx_strcmp("Range", h[i].key.data) == 0)) {
					rc = ngx_header_inspect_range_header(conf, r->connection->log, h[i].value);
					if ((rc != NGX_OK) && conf->block) {
						return NGX_HTTP_BAD_REQUEST;
					}
				} else if ((h[i].key.len == 8) && (ngx_strcmp("If-Range", h[i].key.data) == 0) ) {
					rc = ngx_header_inspect_ifrange_header(conf, r->connection->log, h[i].value);
					if ((rc != NGX_OK) && conf->block) {
						return NGX_HTTP_BAD_REQUEST;
					}
				} else if ((h[i].key.len == 19) && (ngx_strcmp("If-Unmodified-Since", h[i].key.data) == 0) ) {
					rc = ngx_header_inspect_date_header(conf, r->connection->log, "If-Unmodified-Since", h[i].value);
					if ((rc != NGX_OK) && conf->block) {
						return NGX_HTTP_BAD_REQUEST;
					}
				} else if ((h[i].key.len == 17) && (ngx_strcmp("If-Modified-Since", h[i].key.data) == 0) ) {
					rc = ngx_header_inspect_date_header(conf, r->connection->log, "If-Modified-Since", h[i].value);
					if ((rc != NGX_OK) && conf->block) {
						return NGX_HTTP_BAD_REQUEST;
					}
				} else if ((h[i].key.len == 4) && (ngx_strcmp("Date", h[i].key.data) == 0) ) {
					rc = ngx_header_inspect_date_header(conf, r->connection->log, "Date", h[i].value);
					if ((rc != NGX_OK) && conf->block) {
						return NGX_HTTP_BAD_REQUEST;
					}
				} else if ((h[i].key.len == 7) && (ngx_strcmp("Expires", h[i].key.data) == 0) ) {
					rc = ngx_header_inspect_date_header(conf, r->connection->log, "Expires", h[i].value);
					if ((rc != NGX_OK) && conf->block) {
						return NGX_HTTP_BAD_REQUEST;
					}
				} else if ((h[i].key.len == 13) && (ngx_strcmp("Last-Modified", h[i].key.data) == 0) ) {
					rc = ngx_header_inspect_date_header(conf, r->connection->log, "Last-Modified", h[i].value);
					if ((rc != NGX_OK) && conf->block) {
						return NGX_HTTP_BAD_REQUEST;
					}
				} else if ((h[i].key.len == 16) && (ngx_strcmp("Content-Encoding", h[i].key.data) == 0) ) {
					rc = ngx_header_inspect_contentencoding_header(conf, r->connection->log, h[i].value);
					if ((rc != NGX_OK) && conf->block) {
						return NGX_HTTP_BAD_REQUEST;
					}
				} else if ((h[i].key.len == 15) && (ngx_strcmp("Accept-Encoding", h[i].key.data) == 0) ) {
					rc = ngx_header_inspect_acceptencoding_header(conf, r->connection->log, h[i].value);
					if ((rc != NGX_OK) && conf->block) {
						return NGX_HTTP_BAD_REQUEST;
					}
				} else if ((h[i].key.len == 16) && (ngx_strcmp("Content-Language", h[i].key.data) == 0) ) {
					rc = ngx_header_inspect_contentlanguage_header(conf, r->connection->log, h[i].value);
					if ((rc != NGX_OK) && conf->block) {
						return NGX_HTTP_BAD_REQUEST;
					}
				} else if ((h[i].key.len == 15) && (ngx_strcmp("Accept-Language", h[i].key.data) == 0) ) {
					rc = ngx_header_inspect_acceptlanguage_header(conf, r->connection->log, h[i].value);
					if ((rc != NGX_OK) && conf->block) {
						return NGX_HTTP_BAD_REQUEST;
					}
				} else if ((h[i].key.len == 14) && (ngx_strcmp("Accept-Charset", h[i].key.data) == 0) ) {
					rc = ngx_header_inspect_acceptcharset_header(conf, r->connection->log, h[i].value);
					if ((rc != NGX_OK) && conf->block) {
						return NGX_HTTP_BAD_REQUEST;
					}
				} else if ((h[i].key.len == 14) && (ngx_strcmp("Content-Length", h[i].key.data) == 0) ) {
					rc = ngx_header_inspect_digit_header("Content-Length", conf, r->connection->log, h[i].value);
					if ((rc != NGX_OK) && conf->block) {
						return NGX_HTTP_BAD_REQUEST;
					}
				} else if ((h[i].key.len == 12) && (ngx_strcmp("Max-Forwards", h[i].key.data) == 0) ) {
					rc = ngx_header_inspect_digit_header("Max-Forwards", conf, r->connection->log, h[i].value);
					if ((rc != NGX_OK) && conf->block) {
						return NGX_HTTP_BAD_REQUEST;
					}
				} else if ((h[i].key.len == 8) && (ngx_strcmp("If-Match", h[i].key.data) == 0) ) {
					rc = ngx_header_inspect_ifmatch_header("If-Match", conf, r->connection->log, h[i].value);
					if ((rc != NGX_OK) && conf->block) {
						return NGX_HTTP_BAD_REQUEST;
					}
				} else if ((h[i].key.len == 13) && (ngx_strcmp("If-None-Match", h[i].key.data) == 0) ) {
					rc = ngx_header_inspect_ifmatch_header("If-None-Match", conf, r->connection->log, h[i].value);
					if ((rc != NGX_OK) && conf->block) {
						return NGX_HTTP_BAD_REQUEST;
					}
				} else if ((h[i].key.len == 5) && (ngx_strcmp("Allow", h[i].key.data) == 0) ) {
					rc = ngx_header_inspect_allow_header(conf, r->connection->log, h[i].value);
					if ((rc != NGX_OK) && conf->block) {
						return NGX_HTTP_BAD_REQUEST;
					}
				} else if ((h[i].key.len == 4) && (ngx_strcmp("Host", h[i].key.data) == 0) ) {
					rc = ngx_header_inspect_host_header(conf, r->connection->log, h[i].value);
					if ((rc != NGX_OK) && conf->block) {
						return NGX_HTTP_BAD_REQUEST;
					}
				} else if ((h[i].key.len == 6) && (ngx_strcmp("Accept", h[i].key.data) == 0) ) {
					rc = ngx_header_inspect_accept_header(conf, r->connection->log, h[i].value);
					if ((rc != NGX_OK) && conf->block) {
						return NGX_HTTP_BAD_REQUEST;
					}
				} else if ((h[i].key.len == 10) && (ngx_strcmp("Connection", h[i].key.data) == 0) ) {
					rc = ngx_header_inspect_connection_header(conf, r->connection->log, h[i].value);
					if ((rc != NGX_OK) && conf->block) {
						return NGX_HTTP_BAD_REQUEST;
					}
				} else if ((h[i].key.len == 13) && (ngx_strcmp("Content-Range", h[i].key.data) == 0) ) {
					rc = ngx_header_inspect_contentrange_header(conf, r->connection->log, h[i].value);
					if ((rc != NGX_OK) && conf->block) {
						return NGX_HTTP_BAD_REQUEST;
					}
				} else if ((h[i].key.len == 10) && (ngx_strcmp("User-Agent", h[i].key.data) == 0) ) {
					rc = ngx_header_inspect_useragent_header(conf, r->connection->log, h[i].value);
					if ((rc != NGX_OK) && conf->block) {
						return NGX_HTTP_BAD_REQUEST;
					}
				} else if ((h[i].key.len == 7) && (ngx_strcmp("Upgrade", h[i].key.data) == 0) ) {
					rc = ngx_header_inspect_upgrade_header(conf, r->connection->log, h[i].value);
					if ((rc != NGX_OK) && conf->block) {
						return NGX_HTTP_BAD_REQUEST;
					}
				} else if ((h[i].key.len == 3) && (ngx_strcmp("Via", h[i].key.data) == 0) ) {
					rc = ngx_header_inspect_via_header(conf, r->connection->log, h[i].value);
					if ((rc != NGX_OK) && conf->block) {
						return NGX_HTTP_BAD_REQUEST;
					}
				} else if ((h[i].key.len == 4) && (ngx_strcmp("From", h[i].key.data) == 0) ) {
					rc = ngx_header_inspect_from_header(conf, r->connection->log, h[i].value);
					if ((rc != NGX_OK) && conf->block) {
						return NGX_HTTP_BAD_REQUEST;
					}
				} else if ((h[i].key.len == 6) && (ngx_strcmp("Pragma", h[i].key.data) == 0) ) {
					rc = ngx_header_inspect_pragma_header(conf, r->connection->log, h[i].value);
					if ((rc != NGX_OK) && conf->block) {
						return NGX_HTTP_BAD_REQUEST;
					}
				} else if ((h[i].key.len == 12) && (ngx_strcmp("Content-Type", h[i].key.data) == 0) ) {
					rc = ngx_header_inspect_contenttype_header(conf, r->connection->log, h[i].value);
					if ((rc != NGX_OK) && conf->block) {
						return NGX_HTTP_BAD_REQUEST;
					}
				} else if ((h[i].key.len == 11) && (ngx_strcmp("Content-MD5", h[i].key.data) == 0) ) {
					rc = ngx_header_inspect_contentmd5_header(conf, r->connection->log, h[i].value);
					if ((rc != NGX_OK) && conf->block) {
						return NGX_HTTP_BAD_REQUEST;
					}
				} else if ((h[i].key.len == 13) && (ngx_strcmp("Authorization", h[i].key.data) == 0) ) {
					rc = ngx_header_inspect_authorization_header("Authorization", conf, r->connection->log, h[i].value);
					if ((rc != NGX_OK) && conf->block) {
						return NGX_HTTP_BAD_REQUEST;
					}
				} else if ((h[i].key.len == 19) && (ngx_strcmp("Proxy-Authorization", h[i].key.data) == 0) ) {
					rc = ngx_header_inspect_authorization_header("Proxy-Authorization", conf, r->connection->log, h[i].value);
					if ((rc != NGX_OK) && conf->block) {
						return NGX_HTTP_BAD_REQUEST;
					}
				} else if ((h[i].key.len == 6) && (ngx_strcmp("Expect", h[i].key.data) == 0) ) {
					rc = ngx_header_inspect_expect_header(conf, r->connection->log, h[i].value);
					if ((rc != NGX_OK) && conf->block) {
						return NGX_HTTP_BAD_REQUEST;
					}
				} else if ((h[i].key.len == 7) && (ngx_strcmp("Warning", h[i].key.data) == 0) ) {
					rc = ngx_header_inspect_warning_header(conf, r->connection->log, h[i].value);
					if ((rc != NGX_OK) && conf->block) {
						return NGX_HTTP_BAD_REQUEST;
					}
				} else if ((h[i].key.len == 7) && (ngx_strcmp("Trailer", h[i].key.data) == 0) ) {
					rc = ngx_header_inspect_trailer_header(conf, r->connection->log, h[i].value);
					if ((rc != NGX_OK) && conf->block) {
						return NGX_HTTP_BAD_REQUEST;
					}
				} else if ((h[i].key.len == 17) && (ngx_strcmp("Transfer-Encoding", h[i].key.data) == 0) ) {
					rc = ngx_header_inspect_transferencoding_header("Transfer-Encoding", conf, r->connection->log, h[i].value);
					if ((rc != NGX_OK) && conf->block) {
						return NGX_HTTP_BAD_REQUEST;
					}
				} else if ((h[i].key.len == 2) && (ngx_strcmp("TE", h[i].key.data) == 0) ) {
					rc = ngx_header_inspect_transferencoding_header("TE", conf, r->connection->log, h[i].value);
					if ((rc != NGX_OK) && conf->block) {
						return NGX_HTTP_BAD_REQUEST;
					}
				} else if ((h[i].key.len == 7) && (ngx_strcmp("Referer", h[i].key.data) == 0) ) {
					rc = ngx_header_inspect_referer_header("Referer", conf, r->connection->log, h[i].value);
					if ((rc != NGX_OK) && conf->block) {
						return NGX_HTTP_BAD_REQUEST;
					}
				} else if ((h[i].key.len == 16) && (ngx_strcmp("Content-Location", h[i].key.data) == 0) ) {
					rc = ngx_header_inspect_referer_header("Content-Location", conf, r->connection->log, h[i].value);
					if ((rc != NGX_OK) && conf->block) {
						return NGX_HTTP_BAD_REQUEST;
					}
				} else if ((h[i].key.len == 13) && (ngx_strcmp("Cache-Control", h[i].key.data) == 0) ) {
					rc = ngx_header_inspect_cachecontrol_header(conf, r->connection->log, h[i].value);
					if ((rc != NGX_OK) && conf->block) {
						return NGX_HTTP_BAD_REQUEST;
					}
				} else {
					/* TODO: support for other headers */
					if (conf->log_uninspected) {
						ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "header_inspect: uninspected header \"%s: %s\"", h[i].key.data, h[i].value.data);
					}
				}
			}
			part = part->next;
		} while ( part != NULL );
	}

	return NGX_DECLINED;
}



static void *ngx_header_inspect_create_conf(ngx_conf_t *cf) {
	ngx_header_inspect_loc_conf_t *conf;

	conf = ngx_pcalloc(cf->pool, sizeof(ngx_header_inspect_loc_conf_t));
	if (conf == NULL) {
		return NGX_CONF_ERROR;
	}

	conf->inspect = NGX_CONF_UNSET;
	conf->log = NGX_CONF_UNSET;
	conf->block = NGX_CONF_UNSET;
	conf->log_uninspected = NGX_CONF_UNSET;

	conf->range_max_byteranges = NGX_CONF_UNSET_UINT;

	return conf;
}

static char *ngx_header_inspect_merge_conf(ngx_conf_t *cf, void *parent, void *child) {
	ngx_header_inspect_loc_conf_t *prev = parent;
	ngx_header_inspect_loc_conf_t *conf = child;

	ngx_conf_merge_off_value(conf->inspect, prev->inspect, 0);
	ngx_conf_merge_off_value(conf->log, prev->log, 1);
	ngx_conf_merge_off_value(conf->block, prev->block, 0);
	ngx_conf_merge_off_value(conf->log_uninspected, prev->log_uninspected, 0);

	ngx_conf_merge_uint_value(conf->range_max_byteranges, prev->range_max_byteranges, 5);

	return NGX_CONF_OK;
}
