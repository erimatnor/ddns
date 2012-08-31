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
#include <stdio.h>
#include <ddns/ddns.h>
#include <config.h>
#include "http.h"
#include "config.h"
#include "base64.h"
#include "debug.h"
#include <openssl/sha.h>

#define GET_INFO_ASCII_URL \
    "/api/?action=getdyndns&sha=%s"

#define GET_INFO_XML_URL \
    "/api/?action=getdyndns&sha=%s&style=xml"

/* sha1 [username|password], ip */
#define UPDATE_URL \
    "/dynamic/update.php?%s&address=%s"

/* sha1 */
#define QUERY_URL \
    "/api/?action=getdyndns&sha=%s"

static const char *service = "freedns.afraid.org";

static inline char *ntohex(const void *src,
			   size_t src_len,
			   char *dst,
			   size_t dst_len)
{
        static const char hex[] = "0123456789abcdef";
        char *dst_ptr = (char *)dst;
        const unsigned char *src_ptr = (const unsigned char *)src;

        while (src_len && dst_len > 1) {
                *dst_ptr++ = hex[*src_ptr >> 4];

                if (--dst_len > 1) {
                        *dst_ptr++ = hex[*src_ptr++ & 0xf];
                        dst_len--;
                }
                src_len--;
        }
        
        if (dst_len)
                *dst_ptr = '\0';

        return dst;
}

int freedns_init(struct ddns *dd)
{
    dd->service = service;

    return 0;
}

void freedns_destroy(struct ddns *dd)
{
    
}

static int freedns_get_update_url(const char *info, const char *name, 
                                  const char **url, size_t *len)
{
    unsigned int i = 0;
    const char *line = info;

    *url = NULL;

    while (*info != '\0') {
        if (*info == '|') {
            i = (i + 1) % 3;
            
            switch (i) {
            case 1:
                /* IP */
                break;
            case 2:
                if (strncmp(name, line, strlen(name)) == 0)
                    *url = info + 1;
                break;
            default:
                break;
            }
        } else if (*info == '\n') {
            line = info + 1;
            i = 0;
            
            if (*url) {
                *len = info - *url;
                return 1;
            }
        }
        info++;
    }

    return 0;
}

static int freedns_get_info(struct ddns *dd, const char *name, 
                            const char *addr, struct http_response **rsp)
{
    struct http_request *req;
    SHA_CTX ctx;
    char buf[512];
    unsigned char md[SHA_DIGEST_LENGTH];
    char sha1[SHA_DIGEST_LENGTH*2+1];
    int ret;
    
    snprintf(buf, sizeof(buf), "%s|%s", dd->username, dd->password);
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, buf, strlen(buf));
    SHA1_Final(md, &ctx);

    ntohex(md, sizeof(md), sha1, sizeof(sha1));
    
    sprintf(buf, GET_INFO_ASCII_URL, sha1);
    
    req = http_request_alloc(HTTP_REQ_GET, buf);
    
    if (!req)
        return -1;

    http_request_add_field(req, HTTP_REQ_FIELD_HOST, dd->service, strlen(dd->service));
    /* http_request_add_field(req, HTTP_REQ_FIELD_AUTHORIZATION, 
                           "Basic base-64-authorization", 
                           strlen("Basic base-64-authorization")); */
    http_request_add_field(req, HTTP_REQ_FIELD_USER_AGENT, 
                           PACKAGE_NAME " - " PACKAGE_VERSION,
                           strlen(PACKAGE_NAME " - " PACKAGE_VERSION));
    http_request_add_field(req, HTTP_REQ_FIELD_CONTENT_LENGTH,
                           "0", 1);

    http_request_fprintf(stdout, req);

    http_request_send(dd->sock, req);
    
    ret = http_response_recv(dd->sock, rsp, 2000);
    
    http_request_free(req);

    if (ret == -1)
        return -1;

    return 0;
}

int freedns_update(struct ddns *dd, const char *name, const char *addr)
{
    struct http_request *req;
    struct http_response *rsp;
    char buf[512];
    const char *url;
    size_t url_len = 0;
    int ret;
    
    ret = freedns_get_info(dd, name, addr, &rsp);

    if (ret == -1) {
        LOG_ERR("Could not get FreeDNS info\n");
        return -1;
    }
    
    ret = freedns_get_update_url(http_response_body(rsp), name, &url, &url_len);

    if (ret == 0) {
        http_response_free(rsp);
        LOG_ERR("Could not get update URL\n");
        return -1;
    }

    ret = 0;

    /* Find the beginning of the local path URI */
    while (*url != '\0') {
        if (*url == '/')
            ret++;

        if (ret == 3)
            break;
        url++;
        url_len--;
    }

    if (ret != 3) {
        LOG_ERR("could not find local path URI\n");
        http_response_free(rsp);
        return -1;
    }

    ret = snprintf(buf, url_len, "%s", url);

    if (ret < url_len) {
        LOG_ERR("Could not create HTTP request URI\n");
        http_response_free(rsp);
    }

    ret = sprintf(buf + url_len - 1, "&address=%s", addr);

    LOG_DBG("\nbuf=%s\n\n", buf);

    req = http_request_alloc(HTTP_REQ_GET, buf);

    http_response_free(rsp);
    rsp = NULL;

    if (!req)
        return -1;

    http_request_add_field(req, HTTP_REQ_FIELD_HOST, dd->service, strlen(dd->service));
    /*http_request_add_field(req, HTTP_REQ_FIELD_AUTHORIZATION, 
                           "Basic base-64-authorization", 
                           strlen("Basic base-64-authorization")); */
    http_request_add_field(req, HTTP_REQ_FIELD_USER_AGENT, 
                           PACKAGE_NAME " - " PACKAGE_VERSION,
                           strlen(PACKAGE_NAME " - " PACKAGE_VERSION));
    http_request_add_field(req, HTTP_REQ_FIELD_ACCEPT, 
                           "text/plain",
                           strlen("text/plain"));

    http_request_fprintf(stdout, req);

    http_request_send(dd->sock, req);

    ret = http_response_recv(dd->sock, &rsp, 5000);
    
    http_request_free(req);

    if (ret == -1) {
        LOG_ERR("response receive error\n");
        return -1;
    }

    if (rsp)
        http_response_free(rsp);
    
    return 0;
}

struct ddns_proto_ops freedns_proto_ops = {
    .init = freedns_init,
    .destroy = freedns_destroy,
    .update = freedns_update,
};
