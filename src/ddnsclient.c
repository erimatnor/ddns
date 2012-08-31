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
#include <string.h>
#include <ddns/ddns.h>
#include "debug.h"

enum option {
    OPT_USERNAME,
    OPT_PASSWORD,
    OPT_HOSTNAME,
    OPT_ADDRESS,
    OPT_SERVICE,
    _OPT_MAX,
};

enum option_type {
    OPT_TYPE_STRING,
    OPT_TYPE_UINT,
    OPT_TYPE_INT,
    OPT_TYPE_NONE,
};

struct options {
    enum option_type type;
    const char *strings[2];
    unsigned int num_args;
} options[] = {
    [OPT_USERNAME] = { OPT_TYPE_STRING, { "-u", "--username" }, 1 },
    [OPT_PASSWORD] = { OPT_TYPE_STRING, { "-p", "--password" }, 1 },
    [OPT_SERVICE] = { OPT_TYPE_STRING, { "-s", "--service" }, 1 },
    [OPT_HOSTNAME] = { OPT_TYPE_STRING, { "-h", "--hostname" }, 1 },
    [OPT_ADDRESS] = { OPT_TYPE_STRING, { "-a", "--address" }, 1 },
    [_OPT_MAX] = { OPT_TYPE_INT, { NULL, NULL }, 0 }
};

struct option_value {
    void *val;
};

static int parse_opt(int argc, char **argv, struct option_value *vals)
{
    unsigned int i;
    int num_args = 0;
    
    for (i = 0; i < _OPT_MAX; i++) {
        if (strcmp(options[i].strings[0], argv[0]) == 0 ||
            strcmp(options[i].strings[1], argv[0]) == 0) {
            
            if (options[i].num_args > 0) {
                switch (options[i].type) {
                case OPT_TYPE_STRING:
                    *((char **)vals[i].val) = argv[1];
                    break;
                case OPT_TYPE_INT:
                    *((int *)vals[i].val) = atoi(argv[1]);
                    break;
                case OPT_TYPE_UINT:
                    break;
                case OPT_TYPE_NONE:
                    break;
                }
                num_args++;
            }
            return num_args;
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    struct ddns dd;
    char *username = NULL;
    char *password = NULL;
    char *hostname = NULL;
    char *address = NULL;
    char *service = NULL;
    struct option_value op_val[] = {
        [OPT_USERNAME] = { &username },
        [OPT_PASSWORD] = { &password },
        [OPT_HOSTNAME] = { &hostname },
        [OPT_ADDRESS] = { &address },
        [OPT_SERVICE] = { &service }
    };
    int ret;

    ret = ddns_init(&dd, DDNS_INET, DDNS_PROTO_FREEDNS);

    if (ret == -1) {
        LOG_ERR("ddns_init failed\n");
        return ret;
    }
    
    argv++;
    argc--;
       
    while (argc) {
        ret = parse_opt(argc, argv, op_val);
        argc -= (ret + 1);
        argv += (ret + 1);
    }
    
    if (!username) {
        fprintf(stderr, "No username given\n");
        return -1;
    }

    if (!password) {
        fprintf(stderr, "No password given\n");
        return -1;
    }

    if (!hostname) {
        fprintf(stderr, "No hostname given\n");
        return -1;
    }
    
    if (!address) {
        fprintf(stderr, "No address given\n");
        return -1;
    }
    
    ret = ddns_connect(&dd, dd.service, username, password);
    
    if (ret == 0) {
        LOG_DBG("Successfully connected to %s\n", dd.service);
    }

    ret = ddns_update(&dd, hostname, address);

    ddns_destroy(&dd);

    return 0;
}
