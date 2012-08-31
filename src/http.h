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
#ifndef __HTTP_H__
#define __HTTP_H__

enum http_request_method {
    HTTP_REQ_HEAD,
    HTTP_REQ_GET,
    HTTP_REQ_POST,
    HTTP_REQ_PUT,
    HTTP_REQ_DELETE,
    HTTP_REQ_TRACE,
    HTTP_REQ_OPTIONS,
    HTTP_REQ_CONNECT,
    HTTP_REQ_PATCH,
};

enum http_status_code {
    /* 1xx Informal */
    HTTP_STATUS_CONTINUE = 100,
    HTTP_STATUS_SWITCHING_PROTOCOLS = 101,
    HTTP_STATUS_PROCESSING = 102,
    /* 2xx Success */
    HTTP_STATUS_OK = 200,
    HTTP_STATUS_CREATED = 201,
    HTTP_STATUS_ACCEPTED = 202,
    HTTP_STATUS_NON_AUTHORITATIVE_INFORMATION = 203,
    HTTP_STATUS_NO_CONTENT = 204,
    HTTP_STATUS_RESET_CONTENT = 205,
    HTTP_STATUS_PARTIAL_CONTENT = 206,
    HTTP_STATUS_MULTI_STATUS = 207,
    HTTP_STATUS_ALREADY_REPORTED = 208,
    HTTP_STATUS_IM_USED = 226,
    /* 3xx Redirection */
    HTTP_STATUS_MULTIPLE_CHOICES = 300,
    HTTP_STATUS_TEMPORARY_REDIRECT = 307,
    /* 4xx Client errors */
    HTTP_STATUS_BAD_REQUEST = 400,
    HTTP_STATUS_UNAUTHORIZED = 401,
    HTTP_STATUS_PAYMENT_REQUIRED = 402,
    HTTP_STATUS_FORBIDDEN = 403,
    HTTP_STATUS_NOT_FOUND = 404,
    HTTP_STATUS_METHOD_NOT_ALLOWED = 405,
    HTTP_STATUS_NOT_ACCEPTABLE = 406,
    HTTP_STATUS_PROXY_AUTHENTICATION_REQUIRED = 407,
    HTTP_STATUS_REQUEST_TIMEOUT = 408,
    HTTP_STATUS_CONFLICT = 409,
    HTTP_STATUS_GONE = 410,
    HTTP_STATUS_LENGTH_REQUIRED = 411,
    /* 5xx Server errors */
    HTTP_STATUS_INTERNAL_SERVER_ERROR = 500,
    HTTP_STATUS_NOT_IMPLEMENTED = 501,
    HTTP_STATUS_BAD_GATEWAY = 502,
    HTTP_STATUS_SERVICE_UNAVAILABLE = 503,
    HTTP_STATUS_GATEWAY_TIMEOUT = 504,
    HTTP_STATUS_HTTP_VERSION_NOT_SUPPORTED = 505,
    HTTP_STATUS_NETWORK_AUTHENTICATION_REQUIRED = 511,
};

enum http_request_field_type {
    HTTP_REQ_FIELD_ACCEPT,
    HTTP_REQ_FIELD_ACCEPT_CHARSET,
    HTTP_REQ_FIELD_ACCEPT_ENCODING,
    HTTP_REQ_FIELD_ACCEPT_LANGUAGE,
    HTTP_REQ_FIELD_ACCEPT_DATETIME,
    HTTP_REQ_FIELD_AUTHORIZATION,
    HTTP_REQ_FIELD_CONNECTION,
    HTTP_REQ_FIELD_CONTENT_LENGTH,
    HTTP_REQ_FIELD_CONTENT_MD5,
    HTTP_REQ_FIELD_CONTENT_TYPE,
    HTTP_REQ_FIELD_DATE,
    HTTP_REQ_FIELD_EXPECT,
    HTTP_REQ_FIELD_FROM,
    HTTP_REQ_FIELD_HOST,
    HTTP_REQ_FIELD_PRAGMA,
    HTTP_REQ_FIELD_USER_AGENT,
    HTTP_REQ_FIELD_RANGE,
    HTTP_REQ_FIELD_WARNING,
};

enum http_response_field_type {
    HTTP_RESP_FIELD_ACCEPT_RANGES,
    HTTP_RESP_FIELD_AGE,
    HTTP_RESP_FIELD_ALLOW,
    HTTP_RESP_FIELD_CACHE_CONTROL,
    HTTP_RESP_FIELD_CONNECTION,
    HTTP_RESP_FIELD_CONTENT_ENCODING,
    HTTP_RESP_FIELD_CONTENT_LANGUAGE,
    HTTP_RESP_FIELD_CONTENT_LENGTH,
    HTTP_RESP_FIELD_CONTENT_LOCATION,
    HTTP_RESP_FIELD_CONTENT_MD5,
    HTTP_RESP_FIELD_CONTENT_RANGE,
    HTTP_RESP_FIELD_CONTENT_TYPE,
    HTTP_RESP_FIELD_DATE,
    HTTP_RESP_FIELD_EXPIRES,
    HTTP_RESP_FIELD_LAST_MODIFIED,
    HTTP_RESP_FIELD_PRAGMA,
    HTTP_RESP_FIELD_SERVER,
    HTTP_RESP_FIELD_SET_COOKIE,
    HTTP_RESP_FIELD_TRANSFER_ENCODING,
    HTTP_RESP_FIELD_VARY,
    HTTP_RESP_FIELD_WARNING,
    _MAX_HTTP_RESP_FIELD,
};

#define HTTP_RESP_FIELD_INVALID _MAX_HTTP_RESP_FIELD

struct http_request_field;
struct http_response_field;
struct http_request;
struct http_response;

struct http_request *http_request_alloc(enum http_request_method method,
                                        const char *uri);
struct http_response *http_response_alloc(void);
void http_request_free(struct http_request *req);
void http_response_free(struct http_response *rsp);
int http_request_send(struct socket *sock, struct http_request *req);
int http_response_recv(struct socket *sock, 
                       struct http_response **resp, int timeout);
int http_request_fprintf(FILE *fp, struct http_request *req);
const char *http_response_body(struct http_response *rsp);
size_t http_response_body_len(struct http_response *rsp);
//int http_response_parse(const char *buf, struct http_response **resp);
struct http_request_field *http_request_add_field(struct http_request *req, 
                                                  enum http_request_field_type type, 
                                                  const char *content,
                                                  size_t content_len);
struct http_request_field *http_request_get_field(struct http_request *req,
                                                  enum http_request_field_type type);
const char *http_request_field_content(struct http_request_field *field);

#endif /* __HTTP_H__ */
