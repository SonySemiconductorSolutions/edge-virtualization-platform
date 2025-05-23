/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "log.h"
#include "timer.h"

#define CLOCK_SRC CLOCK_REALTIME

typedef struct {
	bool started;
	unsigned int period_ms;
	long time_next_event_ms;
	TIMER_CALLBACK cb;
	void *userData;
} virtual_timer_t;

typedef struct {
	virtual_timer_t *timers;
	const char *module_name;
	unsigned int num_timers;
	unsigned int pevent_max_timeout;
} handle_t;

static long
get_time_ms(void)
{
	struct timespec t;
	int ret;

	ret = clock_gettime(CLOCK_SRC, &t);
	assert(ret != -1);
	long tms = t.tv_sec * 1000 + t.tv_nsec / 1000000;
	return tms;
}

TIMER_handle_t
TIMER_init_timers(const char *mod_name, unsigned int num_timers,
		  unsigned int pevent_max_timeout)
{
	handle_t *h;

	h = malloc(sizeof(handle_t));
	assert(h != NULL);
	h->module_name = mod_name;
	h->num_timers = num_timers;
	h->pevent_max_timeout = pevent_max_timeout;
	h->timers = malloc(sizeof(virtual_timer_t) * num_timers);
	assert(h->timers != NULL);
	for (int i = 0; i < num_timers; i++) {
		TIMER_stop_timer((TIMER_handle_t *)h, i);
	}
	return h;
}

void
TIMER_start_timer(TIMER_handle_t *ext_h, unsigned int timer_id,
		  unsigned int period_ms, TIMER_CALLBACK cb, void *userData)
{
	assert(ext_h != NULL && cb != NULL);
	handle_t *h = (handle_t *)ext_h;
	assert(timer_id < h->num_timers);

	h->timers[timer_id].period_ms = period_ms;
	h->timers[timer_id].time_next_event_ms = get_time_ms() + period_ms;
	h->timers[timer_id].cb = cb;
	h->timers[timer_id].userData = userData;
	h->timers[timer_id].started = true;
	log_module(h->module_name, "Timer %d started with period %d ms.\n",
		   timer_id, period_ms);
}

void
TIMER_stop_timer(TIMER_handle_t *ext_h, unsigned int timer_id)
{
	assert(ext_h != NULL);
	handle_t *h = (handle_t *)ext_h;
	assert(timer_id < h->num_timers);

	h->timers[timer_id].started = false;
	h->timers[timer_id].time_next_event_ms = 0;
	h->timers[timer_id].period_ms = 0;
	h->timers[timer_id].cb = NULL;
	h->timers[timer_id].userData = NULL;
	log_module(h->module_name, "Timer %d stopped.\n", timer_id);
}

int
TIMER_get_max_sleep_time(TIMER_handle_t *ext_h)
{
	assert(ext_h != NULL);
	handle_t *h = (handle_t *)ext_h;
	long remaining_time_ms;
	long curr_time_ms = get_time_ms();
	int pevent_time_out = h->pevent_max_timeout;

	for (int i = 0; i < h->num_timers; i++) {
		if (h->timers[i].started) {
			if (h->timers[i].time_next_event_ms <= curr_time_ms) {
				pevent_time_out = 0;
			} else {
				remaining_time_ms =
					h->timers[i].time_next_event_ms -
					curr_time_ms;
				if (remaining_time_ms < pevent_time_out) {
					pevent_time_out = remaining_time_ms;
				}
			}
		}
	}
	return pevent_time_out;
}

void
TIMER_execute_expired_timers(TIMER_handle_t *ext_h)
{
	assert(ext_h != NULL);
	handle_t *h = (handle_t *)ext_h;
	long curr_time_ms = get_time_ms();

	for (int i = 0; i < h->num_timers; i++) {
		if (h->timers[i].started) {
			if (h->timers[i].time_next_event_ms <= curr_time_ms) {
				h->timers[i].cb(h->timers[i].userData);
				log_module(h->module_name,
					   "Set_time_next_timer_%d - before "
					   "(time_next=%ld, curr_time=%ld)\n",
					   i, h->timers[i].time_next_event_ms,
					   curr_time_ms);
				h->timers[i].time_next_event_ms +=
					h->timers[i].period_ms;
				log_module(h->module_name,
					   "Set_time_next_timer_%d - after "
					   "(time_next=%ld, curr_time=%ld)\n",
					   i, h->timers[i].time_next_event_ms,
					   curr_time_ms);
			}
		}
	}
}

void
TIMER_deinit_timers(TIMER_handle_t ext_h)
{
	assert(ext_h != NULL);
	handle_t *h = ext_h;

	free(h->timers);
	free(h);
}
