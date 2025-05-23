/* Based on:
 * https://github.com/espressif/esp-idf/blob/179ea878c747519138b40f387b80f30dd72097f0/components/log/include/esp_log.h
 * Under the following license:
 *
 * SPDX-FileCopyrightText: 2015-2022 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define XLOG_COLOR_BLACK  "30"
#define XLOG_COLOR_RED    "31"
#define XLOG_COLOR_GREEN  "32"
#define XLOG_COLOR_BROWN  "33"
#define XLOG_COLOR_BLUE   "34"
#define XLOG_COLOR_PURPLE "35"
#define XLOG_COLOR_CYAN   "36"
#define XLOG_COLOR(COLOR) "\033[0;" COLOR "m"
#define XLOG_BOLD(COLOR)  "\033[1;" COLOR "m"
#define XLOG_RESET_COLOR  "\033[0m"
#define XLOG_COLOR_T      ""
#define XLOG_COLOR_D      ""
#define XLOG_COLOR_E      XLOG_COLOR(XLOG_COLOR_RED)
#define XLOG_COLOR_F      XLOG_COLOR(XLOG_COLOR_RED)
#define XLOG_COLOR_W      XLOG_COLOR(XLOG_COLOR_BROWN)
#define XLOG_COLOR_I      XLOG_COLOR(XLOG_COLOR_GREEN)
