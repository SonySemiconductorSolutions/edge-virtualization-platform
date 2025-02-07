/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if !defined(__TIMER_H_)

/** @file */

/**
 * @brief The type (opaque structure ) to represent
 * an instance of this library.
 */
typedef void *TIMER_handle_t;

/**
 *  Function prototype for the callback passed to the function
 *  @ref TIMER_start_timer.
 *
 *  @param userData		An arbitrary blob of data to pass to the
 * 						callback.
 */
typedef void (*TIMER_CALLBACK)(void *userData);

/** @brief Initialize the timer library.
 *
 * Performs the required initialization operations for the module instance.
 *
 * This should be called by the main thread of the module instance.
 * Otherwise, the behavior is undefined.
 *
 * This should not be called more than once for a module instance.
 * Otherwise, the behavior is undefined.
 *
 * @param mod_name				Name of the module instance.
 * @param num_timers 			Number of timers that will be
 *								allocated.
 * @param pevent_max_timeout	Maximum timeout returned by @ref
 *								TIMER_get_max_sleep_time
 *
 * @returns `TIMER_handle_t *` for the calling module instance.
 */
TIMER_handle_t TIMER_init_timers(const char *mod_name, unsigned int num_timers,
				 unsigned int pevent_max_timeout);

/** @brief Starts a periodic timer.
 *
 * This function can be called more than once over the same timer_id.
 * In this case the timer is set with the new information.
 *
 * @param ext_h 	TIMER_handle_t *.
 * @param timer_id	The identifier of the timer (0-N).
 * @param period_ms	The period in which the cb will be called.
 * @param cb		The callback function.
 */
void TIMER_start_timer(TIMER_handle_t *ext_h, unsigned int timer_id,
		       unsigned int period_ms, TIMER_CALLBACK cb,
		       void *userData);

/** @brief Stops a periodic timer.
 *
 * This function can be called more than once over the same timer_id.
 *
 * @param ext_h 	TIMER_handle_t *.
 * @param timer_id	The identifier of the timer (0-N).
 */
void TIMER_stop_timer(TIMER_handle_t *ext_h, unsigned int timer_id);

/** @brief Gets the maximum sleep time for EVP_processEvent.
 *
 * It takes into consideration the maximum timeout set, and when
 * the new timer will expire.
 *
 * @param ext_h 	TIMER_handle_t *.
 *
 * @returns The maximum timeout.
 */
int TIMER_get_max_sleep_time(TIMER_handle_t *ext_h);

/** @brief Executes the callbacks of the timers that have expired.
 *
 * If one of more timers is expired, more than one callback can be called.
 *
 * @param ext_h 	TIMER_handle_t *.
 */
void TIMER_execute_expired_timers(TIMER_handle_t *ext_h);

/** @brief Deinit a timer.
 *
 * The memory used in @ref TIMER_init_timers is freed.
 *
 * @param ext_h 	TIMER_handle_t *.
 */
void TIMER_deinit_timers(TIMER_handle_t ext_h);

#endif /* __TIMER_H_ */
