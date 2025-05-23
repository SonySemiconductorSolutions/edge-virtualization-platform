/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <parson.h>

#include <internal/util.h>

#include "module_log_queue.h"
#include "timeutil.h"
#include "xlog.h"
#include "xpthread.h"

// Log max - length of '{"device/log":[]}'
#define MODULE_LOG_CAPACITY                                                   \
	(CONFIG_EVP_AGENT_MODULE_LOG_REPORT_LEN -                             \
	 sizeof("{\"device/log\":[]}"))

#define lock(ctxt)   xpthread_mutex_lock(&ctxt->lock)
#define unlock(ctxt) xpthread_mutex_unlock(&ctxt->lock)

struct rbuf {
	size_t head;
	size_t tail;
	size_t capacity;
	bool is_full;
	char buf[];
};

struct queue {
	struct evp_lock lock;
	struct rbuf *ring_buffer;
};

static struct queue g_context = {
	.lock = EVP_LOCK_INITIALIZER,
	.ring_buffer = NULL,
};

static bool
advance_index(struct rbuf *self, size_t *index)
{
	if (++(*index) == MODULE_LOG_CAPACITY) {
		*index = 0;
	}
	return self->tail == self->head;
}

static size_t
get_len(struct rbuf *self)
{
	if (self->is_full) {
		return self->capacity;
	} else if (self->head >= self->tail) {
		return self->head - self->tail;
	} else {
		return self->capacity - self->tail + self->head;
	}
}

static bool
is_full(struct rbuf *self)
{
	return self->is_full;
}

static int
enqueue(struct rbuf *self, const char *data)
{
	self->buf[self->head] = *data;

	if (self->is_full) {
		advance_index(self, &self->tail);
	}

	if (advance_index(self, &self->head)) {
		self->is_full = true;
	}

	return 0;
}

static int
dequeue(struct rbuf *self, char *data)
{
	if (0 == get_len(self)) {
		return -1;
	}
	*data = self->buf[self->tail];
	self->is_full = false;
	advance_index(self, &self->tail);

	return 0;
}

static struct rbuf *
create(size_t capacity)
{
	struct rbuf *self = xmalloc(offsetof(struct rbuf, buf) + capacity);
	*self = (struct rbuf){.capacity = capacity};

	return self;
}

void
module_log_queue_free(void)
{
	struct queue *self = &g_context;

	lock(self);
	free(self->ring_buffer);
	self->ring_buffer = NULL;
	unlock(self);
}

void
module_log_queue_init(void)
{
	struct queue *self = &g_context;
	lock(self);
	self->ring_buffer = create(MODULE_LOG_CAPACITY);
	unlock(self);
}

int
module_log_queue_put(const char *instance_id, const char *stream,
		     const char *log)
{
	int ret = -1;
	struct timespec ts;
	char tstring[ISO8601_SIZ];

	getrealtime(&ts);
	JSON_Value *v = json_value_init_object();
	JSON_Object *o = json_value_get_object(v);
	json_object_set_string(o, "log", log);
	json_object_set_string(o, "app", instance_id);
	json_object_set_string(o, "stream", stream);
	json_object_set_string(o, "time", iso8601time_r(&ts, tstring));

	size_t sz = json_serialization_size(v);
	char *buf = xmalloc(sz);
	if (JSONSuccess == json_serialize_to_buffer(v, buf, sz)) {
		ret = module_log_queue_write(",\n", 2);
		ret += module_log_queue_write(buf, sz - 1);
	}
	free(buf);
	json_value_free(v);
	return ret;
}

size_t
module_log_queue_write(void *data, size_t len)
{
	struct queue *self = &g_context;
	size_t ret = 0;

	// TODO: Replace assert (programming error)
	assert(self->ring_buffer != NULL);

	lock(self);
	while (len && !enqueue(self->ring_buffer, data++)) {
		ret++;
		len--;
	}
	unlock(self);

	return ret;
}

size_t
module_log_queue_read(void *data, size_t len)
{
	struct queue *self = &g_context;
	size_t ret = 0;

	// TODO: Replace assert (programming error)
	assert(self->ring_buffer != NULL);

	lock(self);
	while (len && !dequeue(self->ring_buffer, data++)) {
		ret++;
		len--;
	}
	unlock(self);

	return ret;
}

size_t
module_log_queue_get_len(void)
{
	struct queue *self = &g_context;

	// TODO: Replace assert (programming error)
	assert(self->ring_buffer != NULL);

	lock(self);
	size_t value = get_len(self->ring_buffer);
	unlock(self);

	return value;
}

bool
module_log_queue_is_full(void)
{
	struct queue *self = &g_context;

	// TODO: Replace assert (programming error)
	assert(self->ring_buffer != NULL);

	lock(self);
	bool value = is_full(self->ring_buffer);
	unlock(self);

	return value;
}
