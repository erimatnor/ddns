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
#ifndef __DEBUG_H__
#define __DEBUG_H__

#include <stdio.h>

#if defined(OS_ANDROID)
#include <android/log.h>
#if defined(ENABLE_DEBUG)
#define LOG_DBG(format, ...) __android_log_print(ANDROID_LOG_DEBUG, "Serval", \
                                                 "%s: "format, __func__, ## __VA_ARGS__)
#else
#define LOG_DBG(format, ...)
#endif /* ENABLE_DEBUG */
#define LOG_ERR(format, ...) __android_log_print(ANDROID_LOG_ERROR, "Serval", "%s: ERROR "format, \
                                                 __func__, ## __VA_ARGS__)
#else
#if defined(ENABLE_DEBUG)
#define LOG_DBG(format, ...) printf("%s: "format, __func__, ## __VA_ARGS__)
#else
#error "no debug"
#define LOG_DBG(format, ...)
#endif
#define LOG_ERR(format, ...) fprintf(stderr, "%s: ERROR "format,    \
                                     __func__, ## __VA_ARGS__)
#endif /* OS_ANDROID */

#endif /* __DEBUG_H__ */
