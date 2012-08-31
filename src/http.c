/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * Copyright [2012] [Erik Nordström <erik.nordstrom@gmail.com>]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <csocket/csocket.h>
#include "debug.h"
#include "list.h"
#include "http.h"

/*
  This is a simple, non-complete, HTTP parser. It currently supports
  parsing HTTP responses.
 */
#define HTTP_BUFSIZE (4*1024)

static const char *http_request_method_strings[] = {
    [HTTP_REQ_HEAD] = "HEAD",
    [HTTP_REQ_GET] = "GET",
    [HTTP_REQ_POST] = "POST",
    [HTTP_REQ_PUT] = "PUT",
    [HTTP_REQ_DELETE] = "DELETE",
    [HTTP_REQ_TRACE] = "TRACE",
    [HTTP_REQ_OPTIONS] = "OPTIONS",
    [HTTP_REQ_CONNECT] = "CONNECT",
    [HTTP_REQ_PATCH] = "PATCH",
    NULL
};

#if ENABLE_NOT_USED
static const char *http_status_code_strings[] = {
    [HTTP_STATUS_CONTINUE] = "Continue",
    [HTTP_STATUS_SWITCHING_PROTOCOLS] = "Switching Protocols",
    [HTTP_STATUS_PROCESSING] = "Processing",
    /* 2xx Success */
    [HTTP_STATUS_OK] = "OK",
    [HTTP_STATUS_CREATED] = "Created",
    [HTTP_STATUS_ACCEPTED] = "Accepted",
    [HTTP_STATUS_NON_AUTHORITATIVE_INFORMATION] = "Non-Authoritative Information",
    [HTTP_STATUS_NO_CONTENT] = "No Content",
    [HTTP_STATUS_RESET_CONTENT] = "Reset Content",
    [HTTP_STATUS_PARTIAL_CONTENT] = "Partial Content",
    [HTTP_STATUS_MULTI_STATUS] = "Multi-Status",
    [HTTP_STATUS_ALREADY_REPORTED] = "Already Reported",
    [HTTP_STATUS_IM_USED] = "IM Used",
    /* 3xx Redirection */
    [HTTP_STATUS_MULTIPLE_CHOICES] = "Multiple Choices",
    [HTTP_STATUS_TEMPORARY_REDIRECT] = "Temporary Redirect",
    /* 4xx Client errors */
    [HTTP_STATUS_BAD_REQUEST] = "Bad Request",
    [HTTP_STATUS_UNAUTHORIZED] = "Unautorized",
    [HTTP_STATUS_PAYMENT_REQUIRED] = "Payment Required",
    [HTTP_STATUS_FORBIDDEN] = "Forbidden",
    [HTTP_STATUS_NOT_FOUND] = "Not Found",
    [HTTP_STATUS_METHOD_NOT_ALLOWED] = "Method Not Allowed",
    [HTTP_STATUS_NOT_ACCEPTABLE] = "Not Acceptable",
    [HTTP_STATUS_PROXY_AUTHENTICATION_REQUIRED] = "Proxy Authentication Required",
    [HTTP_STATUS_REQUEST_TIMEOUT] = "Request Timeout",
    [HTTP_STATUS_CONFLICT] = "Conflict",
    [HTTP_STATUS_GONE] = "Gone",
    [HTTP_STATUS_LENGTH_REQUIRED] = "Length Required",
    /* 5xx Server errors */
    [HTTP_STATUS_INTERNAL_SERVER_ERROR] = "Internal Server Error",
    [HTTP_STATUS_NOT_IMPLEMENTED] = "Not Implemented",
    [HTTP_STATUS_BAD_GATEWAY] = "Bad Gateway",
    [HTTP_STATUS_SERVICE_UNAVAILABLE] = "Service Unavailable",
    [HTTP_STATUS_GATEWAY_TIMEOUT] = "Gateway Timeout",
    [HTTP_STATUS_HTTP_VERSION_NOT_SUPPORTED] = "HTTP Version Not Supported",
    [HTTP_STATUS_NETWORK_AUTHENTICATION_REQUIRED] = "Network Authentication Required",
    NULL
};
#endif 

static const char *http_request_field_strings[] = {
    [HTTP_REQ_FIELD_ACCEPT] = "Accept",
    [HTTP_REQ_FIELD_ACCEPT_CHARSET] = "Accept-Charset",
    [HTTP_REQ_FIELD_ACCEPT_ENCODING] = "Accept-Encoding",
    [HTTP_REQ_FIELD_ACCEPT_LANGUAGE] = "Accept-Language",
    [HTTP_REQ_FIELD_ACCEPT_DATETIME] = "Accept-Datetime",
    [HTTP_REQ_FIELD_AUTHORIZATION] = "Autorization",
    [HTTP_REQ_FIELD_CONNECTION] = "Connection",
    [HTTP_REQ_FIELD_CONTENT_LENGTH] = "Content-Length",
    [HTTP_REQ_FIELD_CONTENT_MD5] = "Content-MD5",
    [HTTP_REQ_FIELD_CONTENT_TYPE] = "Content-Type",
    [HTTP_REQ_FIELD_DATE] = "Date",
    [HTTP_REQ_FIELD_EXPECT] = "Expect",
    [HTTP_REQ_FIELD_FROM] = "From",
    [HTTP_REQ_FIELD_HOST] = "Host",
    [HTTP_REQ_FIELD_PRAGMA] = "Pragma",
    [HTTP_REQ_FIELD_USER_AGENT] = "User-Agent",
    [HTTP_REQ_FIELD_RANGE] = "Range",
    [HTTP_REQ_FIELD_WARNING] = "Warning",
    NULL
};

static const char *http_response_field_strings[] = {
    [HTTP_RESP_FIELD_ACCEPT_RANGES] = "Accept-Ranges",
    [HTTP_RESP_FIELD_AGE] = "Age",
    [HTTP_RESP_FIELD_ALLOW] = "Allow",
    [HTTP_RESP_FIELD_CACHE_CONTROL] = "Cache-Control",
    [HTTP_RESP_FIELD_CONNECTION] = "Connection",
    [HTTP_RESP_FIELD_CONTENT_ENCODING] = "Content-Encoding",
    [HTTP_RESP_FIELD_CONTENT_LANGUAGE] = "Content-Languge",
    [HTTP_RESP_FIELD_CONTENT_LENGTH] = "Content-Length",
    [HTTP_RESP_FIELD_CONTENT_LOCATION] = "Content-Location",
    [HTTP_RESP_FIELD_CONTENT_MD5] = "Content-MD5",
    [HTTP_RESP_FIELD_CONTENT_RANGE] = "Content-Range",
    [HTTP_RESP_FIELD_CONTENT_TYPE] = "Content-Type",
    [HTTP_RESP_FIELD_DATE] = "Date",
    [HTTP_RESP_FIELD_EXPIRES] = "Expires",
    [HTTP_RESP_FIELD_LAST_MODIFIED] = "Last-Modified",
    [HTTP_RESP_FIELD_PRAGMA] = "Pragma",
    [HTTP_RESP_FIELD_SERVER] = "Server",
    [HTTP_RESP_FIELD_SET_COOKIE] = "Set-Cookie",
    [HTTP_RESP_FIELD_TRANSFER_ENCODING] = "Transfer-Encoding",
    [HTTP_RESP_FIELD_VARY] = "Vary",
    [HTTP_RESP_FIELD_WARNING] = "Warning",
    NULL
};

struct http_request_field {
    struct list_node node;
    enum http_request_field_type type;
    size_t content_alloc_len;
    size_t content_len;
    char *content;
};

struct http_response_field {
    struct list_node node;
    enum http_response_field_type type;
    size_t content_alloc_len;
    size_t content_len;
    char *content;
};

struct http_msg {
    unsigned int num_fields;
    unsigned int tot_fields;
    const char *header;     /* Pointer to the raw serialized message header */
    const char *body;       /* Pointer to the raw message body */
    size_t header_alloc_len; 
    size_t header_len;
    size_t body_alloc_len;
    size_t body_len;
    struct list_node fields;
};

struct http_request {
    enum http_request_method method;
    struct http_msg msg;
    char uri[0];
};

struct http_response {
    unsigned int version_major;
    unsigned int version_minor;
    unsigned int status_code;
    const char *status_reason;
    struct http_msg msg;
};

static 
struct http_request_field *http_request_field_alloc(enum http_request_field_type type,
                                                    const char *content, 
                                                    size_t content_len)
{
    struct http_request_field *field;

    field = malloc(sizeof(*field));
    
    if (!field)
        return NULL;
    
    memset(field, 0, sizeof(*field));
    field->type = type;
    INIT_LIST_NODE(&field->node);
    
    if (content_len) {
        field->content = malloc(content_len + 1);
        
        if (!field->content) {
            free(field);
            return NULL;
        }
        field->content_alloc_len = content_len + 1;
        field->content_len = content_len;
        memcpy(field->content, content, content_len);
        field->content[content_len] = '\0';
    }

    return field;
}

static 
struct http_response_field *http_response_field_alloc(enum http_response_field_type type,
                                                      const char *content, 
                                                      size_t content_len)
{
    struct http_response_field *field;

    field = malloc(sizeof(*field));
    
    if (!field)
        return NULL;
    
    memset(field, 0, sizeof(*field));

    field->type = type;
    INIT_LIST_NODE(&field->node);

    if (content_len) {
        field->content = malloc(content_len + 1);
        
        if (!field->content) {
            free(field);
            return NULL;
        }
        field->content_alloc_len = content_len + 1;
        field->content_len = content_len;
        memcpy(field->content, content, content_len);
        field->content[content_len] = '\0';
    }
    
    return field;
}

void http_request_field_free(struct http_request_field *field)
{
    if (field->content_alloc_len && field->content)
        free(field->content);
    free(field);
}

void http_response_field_free(struct http_response_field *field)
{
    if (field->content_alloc_len && field->content)
        free(field->content);
    free(field);
}

struct http_request *http_request_alloc(enum http_request_method method,
                                        const char *uri)
{
    struct http_request *req;
    size_t req_size = sizeof(*req) + strlen(uri) + 1;

    req = malloc(req_size);
    
    if (!req)
        return NULL;

    memset(req, 0, req_size);

    *req = (struct http_request) {
        .method = method,
        .msg.fields = INIT_LIST_NODE(&req->msg.fields),
    };

    strcpy(req->uri, uri);
    
    return req;
}

struct http_response *http_response_alloc(void)
{
    struct http_response *rsp;
    size_t rsp_size = sizeof(*rsp);
    
    rsp = malloc(rsp_size);
    
    if (!rsp)
        return NULL;
    
    memset(rsp, 0, rsp_size);
    
    *rsp = (struct http_response) {
        .msg.fields = INIT_LIST_NODE(&rsp->msg.fields),
    };

    return rsp;
}

void http_request_free(struct http_request *req)
{
    while (!list_is_empty(&req->msg.fields)) {
        struct http_request_field *field = 
            list_first_type(&req->msg.fields, 
                            struct http_request_field, node);
        list_remove(&field->node);
        http_request_field_free(field);
    }
    
    free(req);
}

void http_response_free(struct http_response *resp)
{
    free(resp);
}

struct http_request_field *http_request_add_field(struct http_request *req, 
                                                  enum http_request_field_type type, 
                                                  const char *content,
                                                  size_t content_len)
{
    struct http_request_field *field;
    
    field = http_request_field_alloc(type, content, content_len);

    if (!field)
        return NULL;
    
    list_insert_tail(&req->msg.fields, &field->node);
    req->msg.num_fields++;
    
    return field;
}

struct http_request_field *http_request_get_field(struct http_request *req,
                                                  enum http_request_field_type type)
{
    struct http_request_field *field;

    list_foreach_type(field, &req->msg.fields, node) {
        if (field->type == type)
            return field;
    }
    return NULL;
}


const char *http_request_field_content(struct http_request_field *field)
{
    if (!field)
        return NULL;

    return field->content;
}

struct http_response_field *http_response_add_field(struct http_response *req, 
                                                    enum http_response_field_type type, 
                                                    const char *content,
                                                    size_t content_len)
{
    struct http_response_field *field;
    
    field = http_response_field_alloc(type, content, content_len);

    if (!field)
        return NULL;
    
    list_insert_tail(&req->msg.fields, &field->node);
    req->msg.num_fields++;
    
    return field;
}

struct http_response_field *http_response_get_field(struct http_response *req,
                                                  enum http_response_field_type type)
{
    struct http_response_field *field;

    list_foreach_type(field, &req->msg.fields, node) {
        if (field->type == type)
            return field;
    }
    return NULL;
}

const char *http_response_field_content(struct http_response_field *field)
{
    if (!field)
        return NULL;

    return field->content;
}

static int print_file(void *arg, const char *fmt, ...)
{
    FILE *fp = (FILE *)arg;
    va_list ap;
    int ret;

    va_start (ap, fmt);
    ret = vfprintf(fp, fmt, ap);
    va_end(ap);

    return ret;
}

static int print_socket(void *arg, const char *fmt, ...)
{
    struct socket *sock = (struct socket *)arg;
    va_list ap;
    int ret;

    va_start (ap, fmt);
    ret = socket_vprintf(sock, fmt, ap);
    va_end(ap);
    
    return ret;
}

static int http_request_print(struct http_request *req, 
                              int (*print_func)(void *arg, const char *fmt, ...),
                              void *arg)
{
    int ret, tot_len = 0;
    struct http_request_field *field;
    
    if (!req->uri) {
        LOG_ERR("No REQUEST URI\n");
        return -1;
    }

    ret = print_func(arg, "%s %s HTTP/1.1\r\n",
                     http_request_method_strings[req->method],
                     req->uri);
    
    if (ret == -1) {
        LOG_ERR("could not send request method\n");
        return -1;
    }
    
    tot_len += ret;
    
    list_foreach_type(field, &req->msg.fields, node) {
        ret = print_func(arg, "%s: %s\r\n",
                         http_request_field_strings[field->type],
                         field->content);
        
        if (ret == -1) {
            LOG_ERR("could not send request method\n");
            return -1;
        }
        tot_len += ret;
    }

    ret = print_func(arg, "\r\n");
    
    if (ret == -1) {
        return -1;
    }
    
    tot_len += ret;
    
    return tot_len;
}

int http_request_send(struct socket *sock, struct http_request *req)
{
    return http_request_print(req, print_socket, sock);
}

int http_request_fprintf(FILE *fp, struct http_request *req)
{
    return http_request_print(req, print_file, fp);
}

const char *http_response_body(struct http_response *rsp)
{
    if (!rsp)
        return NULL;
    return rsp->msg.body;
}

size_t http_response_body_len(struct http_response *rsp)
{
    if (!rsp)
        return 0;
    return rsp->msg.body_len;
}

/*
  Octets in HTTP, from RFC2616:

       OCTET          = <any 8-bit sequence of data>
       CHAR           = <any US-ASCII character (octets 0 - 127)>
       UPALPHA        = <any US-ASCII uppercase letter "A".."Z">
       LOALPHA        = <any US-ASCII lowercase letter "a".."z">
       ALPHA          = UPALPHA | LOALPHA
       DIGIT          = <any US-ASCII digit "0".."9">
       CTL            = <any US-ASCII control character
                        (octets 0 - 31) and DEL (127)>
       CR             = <US-ASCII CR, carriage return (13)>
       LF             = <US-ASCII LF, linefeed (10)>
       SP             = <US-ASCII SP, space (32)>
       HT             = <US-ASCII HT, horizontal-tab (9)>
       <">            = <US-ASCII double-quote mark (34)>
*/

static const unsigned char http_octets[] = {
    /* CTL (octets 0 - 31) */
    /* NUL    SOH       STX       ETX       EOT       ENQ       ACK       BEL */
    0,        0,        0,        0,        0,        0,        0,        0,
    /* BS     TAB       LF        VT        FF        CR        SO        SI  */
    0,        0,        0,        0,        0,        0,        0,        0,
    /* DLE    DC1       DC2       DC3       DC4       NAK       SYN       ETB */
    0,        0,        0,        0,        0,        0,        0,        0,
    /* CAN    EM        SUB       ESC       FS        GS        RS        US  */
    0,        0,        0,        0,        0,        0,        0,        0,
    /* ' '    !         "         #         $         %         &         '   */
    0,      '!',        0,      '#',      '$',      '%',      '&',     '\'', 
    /* (      )         *         +         ,         -         .          /  */
    0,        0,      '*',      '+',        0,      '-',      '.',      '/',
    /* 0      1         2         3         4         5         6          7  */
    '0',    '1',      '2',      '3',      '4',      '5',      '6',      '7',
    /* 8      9         :         ;         <         =         >          ?  */
    '8',    '9',        0,        0,        0,        0,        0,        0,
    /* @      A         B         C         D         E         F          G  */
    0,      'a',      'b',      'c',      'd',      'e',      'f',       'g',
    /* H      I         J         K         L         M         N          O  */
    'h',    'i',      'j',      'k',      'l',      'm',      'n',       'o',
    /* P      Q         R         S         T         U         V          W  */
    'p',    'q',      'r',      's',      't',      'u',      'v',       'w',
    /* X      Y         Z         [         \         ]         ^          -  */
    'x',    'y',      'z',        0,       0,         0,        0,        0,
    /* `      a         b         c         d         e         f          g  */
    0,      'a',      'b',      'c',      'd',      'e',      'f',       'g',
    /* h      i         j         k         l         m         n          o  */
    'h',    'i',      'j',      'k',      'l',      'm',      'n',       'o',
    /* p      q         r         s         t         u         v          w  */
    'p',    'q',      'r',      's',      't',      'u',      'v',       'w',
    /* x      y         z         {         |         }         ~        DEL  */
    'x',    'y',      'z',        0,      '|',        0,        0,         0
     
};

#define HTTP_OCTET(c) ((const char)http_octets[(unsigned char)(c)])
#define NUMERIC(c) (c >= '0' && c <= '9')
            
#define LOWER(c) (unsigned char)(c | 0x20)
#define ALPHA(c) (LOWER(c) >= 'a' && LOWER(c) <= 'z')

/*
 * This is static definition of a trie that defines the valid fields
 * that can exist in an HTTP response. This allows for faster matching
 * than brute-force testing a field against all valid fields.
 */
struct entry {
    const char *str;
    enum http_response_field_type type;
    struct entry *children[];
};

static struct entry http_rsp_age = {
    .str = "ge",
    .type = HTTP_RESP_FIELD_AGE,
    .children = { NULL }
};

static struct entry http_rsp_accept_ranges = {
    .str = "ccept-ranges",
    .type = HTTP_RESP_FIELD_ACCEPT_RANGES,
    .children = { NULL }
};

static struct entry http_rsp_allow = {
    .str = "llow",
    .type = HTTP_RESP_FIELD_ALLOW,
    .children = { NULL }
};

static struct entry http_rsp_a = {
    .str = "a",
    .type = HTTP_RESP_FIELD_INVALID,
    .children = { &http_rsp_accept_ranges, 
                  &http_rsp_age, 
                  &http_rsp_allow, 
                  NULL }
};

static struct entry http_rsp_cache_control = {
    .str = "ache-control",
    .type = HTTP_RESP_FIELD_CACHE_CONTROL,
    .children = { NULL }
};

static struct entry http_rsp_connection = {
    .str = "nection",
    .type = HTTP_RESP_FIELD_CONNECTION,
    .children = { &http_rsp_connection,
                  NULL }
};

static struct entry http_rsp_content_encoding = {
    .str = "encoding",
    .type = HTTP_RESP_FIELD_CONTENT_ENCODING,
    .children = { NULL }
};

static struct entry http_rsp_content_language = {
    .str = "anguage",
    .type = HTTP_RESP_FIELD_CONTENT_LANGUAGE,
    .children = { NULL }
};

static struct entry http_rsp_content_length = {
    .str = "ength",
    .type = HTTP_RESP_FIELD_CONTENT_LENGTH,
    .children = { NULL }
};

static struct entry http_rsp_content_location = {
    .str = "ocation",
    .type = HTTP_RESP_FIELD_CONTENT_LOCATION,
    .children = { NULL }
};

static struct entry http_rsp_content_l = {
    .str = "l",
    .type = HTTP_RESP_FIELD_INVALID,
    .children = { &http_rsp_content_language,
                  &http_rsp_content_length,
                  &http_rsp_content_location,
                  NULL }
};

static struct entry http_rsp_content_md5 = {
    .str = "md5",
    .type = HTTP_RESP_FIELD_CONTENT_MD5,
    .children = { NULL }
};

static struct entry http_rsp_content_range = {
    .str = "range",
    .type = HTTP_RESP_FIELD_CONTENT_RANGE,
    .children = { NULL }
};
static struct entry http_rsp_content_type = {
    .str = "type",
    .type = HTTP_RESP_FIELD_CONTENT_TYPE,
    .children = { NULL }
};

static struct entry http_rsp_content = {
    .str = "tent-",
    .type = HTTP_RESP_FIELD_INVALID,
    .children = { &http_rsp_content_encoding,
                  &http_rsp_content_l,
                  &http_rsp_content_md5,
                  &http_rsp_content_range,
                  &http_rsp_content_type,
                  NULL
    }
};

static struct entry http_rsp_con = {
    .str = "on",
    .type = HTTP_RESP_FIELD_INVALID,
    .children = { &http_rsp_connection,
                  &http_rsp_content,
                  NULL
    }
};

static struct entry http_rsp_c = {
    .str = "c",
    .type = HTTP_RESP_FIELD_INVALID,
    .children = { &http_rsp_cache_control, 
                  &http_rsp_con, 
                  NULL }
};

static struct entry http_rsp_date = {
    .str = "date",
    .type = HTTP_RESP_FIELD_DATE,
    .children = { NULL }
};

static struct entry http_rsp_last_modified = {
    .str = "last-modified",
    .type = HTTP_RESP_FIELD_LAST_MODIFIED,
    .children = { NULL }
};

static struct entry http_rsp_expires = {
    .str = "expires",
    .type = HTTP_RESP_FIELD_EXPIRES,
    .children = { NULL }
};

static struct entry http_rsp_pragma = {
    .str = "pragma",
    .type = HTTP_RESP_FIELD_PRAGMA,
    .children = { NULL }
};

static struct entry http_rsp_server = {
    .str = "rver",
    .type = HTTP_RESP_FIELD_SERVER,
    .children = { NULL }
};

static struct entry http_rsp_set_cookie = {
    .str = "t-cookie",
    .type = HTTP_RESP_FIELD_SET_COOKIE,
    .children = { NULL }
};

static struct entry http_rsp_se = {
    .str = "se",
    .type = HTTP_RESP_FIELD_INVALID,
    .children = { &http_rsp_server,
                  &http_rsp_set_cookie,
                  NULL }
};

static struct entry http_rsp_transfer_encoding = {
    .str = "transfer-encoding",
    .type = HTTP_RESP_FIELD_TRANSFER_ENCODING,
    .children = { NULL }
};

static struct entry http_rsp_vary = {
    .str = "vary",
    .type = HTTP_RESP_FIELD_VARY,
    .children = { NULL }
};

static struct entry http_rsp_warning = {
    .str = "warning",
    .type = HTTP_RESP_FIELD_WARNING,
    .children = { NULL }
};

static struct entry http_rsp_root = {
    .str = "",
    .type = HTTP_RESP_FIELD_INVALID,
    .children = { &http_rsp_a,
                  &http_rsp_date,
                  &http_rsp_c,
                  &http_rsp_expires, 
                  &http_rsp_last_modified, 
                  &http_rsp_pragma,
                  &http_rsp_se,
                  &http_rsp_transfer_encoding,
                  &http_rsp_vary,
                  &http_rsp_warning,
                  NULL }
};

static unsigned int match_rsp_string(const char *str, 
                                     enum http_response_field_type *type)
{
    struct entry *e = &http_rsp_root;
    const char *epos = e->str;
    unsigned int n = 0;

    for (n = 0; str[n] != '\0'; n++) {
        char ch = LOWER(str[n]);
        
        if (*epos == '\0') {
            struct entry *c;
            unsigned int i = 0;
            /* descend down a child */
            c = e->children[i];
            
            while (c) {
                if (*c->str == ch)
                    break;
                c = e->children[++i];
            }

            if (!c)
                break;
            e = c;
            epos = e->str;
        }

        if (*epos++ != ch)
            break;
    }

    if (e && type)
        *type = e->type;

    return n;
}

int http_response_parse(const char *buf, size_t buflen, 
                        struct http_response **rsp,
                        int (*header_field_cb)(enum http_response_field_type type, 
                                               const char *content,
                                               size_t content_len))
{
    const char *pos = buf;
    const char *rsp_field_start = NULL;
    const char *body_start = NULL;
    enum http_response_field_type field_type = HTTP_RESP_FIELD_INVALID;
    enum {
        ST_START,
        ST_RSP_MAJOR_START,
        ST_RSP_MAJOR,
        ST_RSP_MINOR_START,
        ST_RSP_MINOR,
        ST_RSP_STATUS_CODE_START,
        ST_RSP_STATUS_CODE,
        ST_RSP_STATUS_REASON,
        ST_RSP_STATUS_REASON_END,
        ST_RSP_HEADER_FIELD_START,
        ST_RSP_HEADER_FIELD,
        ST_RSP_HEADER_FIELD_END,
        ST_RSP_BODY_START,
        ST_RSP_BODY,
        ST_RSP_BODY_END,
    } state = ST_START;

    if (!rsp)
        return -1;
    
    *rsp = http_response_alloc();

    do {
        char c = *pos;
        
        switch (state) {
        case ST_START:
        { 
            const char *http = "http/";
            (*rsp)->msg.header = pos;

            while (*http != '\0') {
                c = HTTP_OCTET(*pos);
                if (c != *http)
                    return -1;
                pos++;
                http++;
            }
            pos--;
            state = ST_RSP_MAJOR_START;
            break;
        }
        case ST_RSP_MAJOR_START:
            if (!NUMERIC(c)) {
                LOG_ERR("Non-numeric version major %c\n", c);
                return -1;
            }
            (*rsp)->version_major = c - '0';
            state = ST_RSP_MAJOR;
            break;
        case ST_RSP_MAJOR:
            if (c == '.') {
                state = ST_RSP_MINOR_START;
            } else if (NUMERIC(c)) {
                (*rsp)->version_major *= 10;
                (*rsp)->version_major += c - '0';
            } else 
                return -1;
            break;
        case ST_RSP_MINOR_START:
            if (!NUMERIC(c))
                    return -1;
            (*rsp)->version_minor = c - '0';
            state = ST_RSP_MINOR;
            break;
        case ST_RSP_MINOR:
            if (c == ' ') {
                state = ST_RSP_STATUS_CODE;
            } else if (!NUMERIC(c)) {
                return -1;
            } else {
                (*rsp)->version_minor *= 10;
                (*rsp)->version_minor += c - '0';
            }
            break;
        case ST_RSP_STATUS_CODE_START:
            if (c == ' ')
                /* Skip */
                break;
            else if (NUMERIC(c)) {
                (*rsp)->status_code = c - '0';
                state = ST_RSP_STATUS_CODE;
                break;
            }
            return -1;
        case ST_RSP_STATUS_CODE:
            if (NUMERIC(c)) {
                (*rsp)->status_code *= 10;
                (*rsp)->status_code += c - '0';
            } else if (c == ' ') {
                /* skip */
                state = ST_RSP_STATUS_REASON;
            } else 
                return -1;
            break;
        case ST_RSP_STATUS_REASON:
            if (ALPHA(c)) {
                (*rsp)->status_reason = pos;
                state = ST_RSP_STATUS_REASON_END;
                break;
            } 
            return -1;
        case ST_RSP_STATUS_REASON_END:
            if (ALPHA(c) || c == ' ' || c == '-') {
                break;
            } else if (c == '\r' && pos[1] == '\n') {
                state = ST_RSP_HEADER_FIELD_START;
                pos++;
                break;
            }
            return -1;
        case ST_RSP_HEADER_FIELD_START:
        {
            unsigned int n;
            
            if (c == '\r') {
                state = ST_RSP_BODY_START;
                break;
            }
            n = match_rsp_string(pos, &field_type);
            
            if (pos[n] != ':' || 
                field_type == HTTP_RESP_FIELD_INVALID) {
                LOG_ERR("Unknown field, skipping\n");
                rsp_field_start = NULL;
                state = ST_RSP_HEADER_FIELD;
                break;
            }
            
            /* skip past the field we just checked, along with the
             * ':' and SPC */
            pos += n + 1;
            if (*pos == ' ')
                pos++;

            rsp_field_start = pos;
            state = ST_RSP_HEADER_FIELD;
            break;
        }
        case ST_RSP_HEADER_FIELD:
            if (c == '\r') {
                state = ST_RSP_HEADER_FIELD_END;
                
                if (rsp_field_start) {
                    /* Add this field to the response */
                    http_response_add_field(*rsp, field_type, 
                                            rsp_field_start, 
                                            pos - rsp_field_start);
                    
                    /* Tell the user */
                    if (header_field_cb &&
                        header_field_cb(field_type, 
                                        rsp_field_start, 
                                        pos - rsp_field_start) != 0) {
                        LOG_ERR("callback header field error on '%s'\n", 
                                rsp_field_start);
                        return -1;
                    }
                }
            }
            break;
        case ST_RSP_HEADER_FIELD_END:
            if (c == '\n') {
                state = ST_RSP_HEADER_FIELD_START;
                break;
            }
            LOG_ERR("Bad header field\n");
            return -1;
        case ST_RSP_BODY_START:
            if (c != '\n') {
                LOG_ERR("Unexpected body start\n");
                return -1;
            }
            state = ST_RSP_BODY;
            body_start = pos + 1;
            (*rsp)->msg.header_len = (pos + 1) - (*rsp)->msg.header;
            (*rsp)->msg.body = pos + 1;
            break;
        case ST_RSP_BODY:
            if (c == '\0') {
                state = ST_RSP_BODY_END;
                (*rsp)->msg.body_len = pos - (*rsp)->msg.body;
            }
            break;
        case ST_RSP_BODY_END:
            break;
        default:
            return -1;
        }
    }  while (*pos++ != '\0');
   
    //printf("HTTP version=%u.%u\n", (*rsp)->version_major, (*rsp)->version_minor);
    //printf("HTTP status code=%u\n", (*rsp)->status_code);
    //printf("HTTP status reason=%s\n", (*rsp)->status_reason);
    return pos - buf;
}

static int http_response_field_callback(enum http_response_field_type type,
                                        const char *content,
                                        size_t content_len)
{
    char buf[content_len+1];

    strncpy(buf, content, content_len);
    buf[content_len] = '\0';
    LOG_DBG("callback: '%s' '%s'\n", http_response_field_strings[type], buf);

    return 0;
}

int http_response_recv(struct socket *sock, 
                       struct http_response **rsp, int timeout)
{
    short events = SOCKET_EV_READ;
    static char backlog[HTTP_BUFSIZE];
    static size_t backlog_len = 0;
    static size_t backlog_index = 0;
    size_t recv_len = 0;
    char *buf;
    int ret;

    if (backlog_len) {
        ret = http_response_parse(backlog + backlog_index, backlog_len, 
                                  rsp, http_response_field_callback);
        
        if (ret > 0) {
            backlog_len -= ret;

            if (backlog_len)
                backlog_index += ret;
            else
                backlog_index = 0;
            return ret;
        }        
    }

    if (timeout > 0) {
        ret = socket_poll(sock, &events, timeout);
        
        if (ret == -1) {
            LOG_ERR("poll error %s\n", socket_strerror(sock));
            return -1;
        } else if (ret == 0) {
            LOG_DBG("poll timeout\n");
            return ret;
        }
    }

    buf = malloc(HTTP_BUFSIZE);

    if (!buf)
        return -1;
    
    if (backlog_len)
        memcpy(buf, backlog + backlog_index, backlog_len);

    ret = socket_recv(sock, buf + backlog_len, 
                      HTTP_BUFSIZE - backlog_len, 0);

    if (ret == -1) {
        LOG_ERR("recv error: %s\n", socket_strerror(sock));
        return -1;
    }
    
    LOG_DBG("received %d bytes backlog_len=%zu\n", ret, backlog_len);
    
    LOG_DBG("\nbuf=%s\n\n", buf + backlog_len);

    if (ret == 0)
        return 0;

    recv_len = ret;

    ret = http_response_parse(buf + backlog_len, recv_len, 
                              rsp, http_response_field_callback);

    if (ret <= 0) {
        /* Save whatever we've received so far in the backlog */
        memcpy(backlog, buf, recv_len + backlog_len);
        backlog_len += recv_len;
        backlog_index = 0;
        return 0;
    }
    
    if (ret < (int)(backlog_len + recv_len)) {
        backlog_len = backlog_len + recv_len - ret;
        backlog_index = 0;
        memcpy(backlog, buf + ret, backlog_len); 
    }

    return 1;
}


#if defined(ENABLE_TEST)
#define TEST_RESPONSE "HTTP/1.1 200 OK\r\n"                             \
    "Server: nginx\r\n"                                                 \
    "Date: Wed, 29 Aug 2012 17:35:44 GMT\r\n"                           \
    "Content-Type: text/plain\r\n"                                      \
    "Connection: close\r\n"                                             \
    "Vary: Accept-Encoding\r\n"                                         \
    "\r\n"                                                              \
    "serval.anydns.com|128.112.139.195|http://freedns.afraid.org/dynamic/update.php?VURmSVFxMzFVMVVBQUFUU0pSVUFBQUFkOjgyMDU2MTU=\r\n" \
    "\r\n"

int main(int argc, char **argv)
{
    int ret;
    struct http_response *rsp;

    LOG_DBG("Parsing:\n%s\n", TEST_RESPONSE);

    ret = http_response_parse(TEST_RESPONSE, strlen(TEST_RESPONSE), 
                              &rsp, http_response_field_callback);

    if (ret > 0) {
        LOG_DBG("Message OK, body is %s\n", rsp->msg.body);
    }
    http_response_free(rsp);

    return 0;
}
#endif
