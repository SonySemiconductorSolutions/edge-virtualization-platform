/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if !defined(__DOCKER_H__)
#define __DOCKER_H__

#include <stdbool.h>

#include <mbedtls/ssl.h>
#include <parson.h>

struct docker;
struct docker_container;
struct config;

struct docker *docker_create(const char *api,
			     struct mbedtls_ssl_config *ssl_config,
			     const char *unix_socket);
void docker_free(struct docker *docker);

int image_create(struct docker *docker, const char *fromImage);
int image_inspect(struct docker *docker, const char *image);
int image_prune(struct docker *docker);

struct docker_bind {
	const char *host_src;
	const char *container_dest;
};

int container_list(struct docker *docker, int (*cb)(const char *, void *),
		   void *user, bool all);
int container_killall(struct docker *docker);
int container_deleteall(struct docker *docker);
int container_prune(struct docker *docker);
int container_create_raw(struct docker *docker, const char *name,
			 JSON_Value *v, struct docker_container **contp);
int container_create(struct docker *docker, const char *image,
		     unsigned int nbinds, const struct docker_bind *binds,
		     struct docker_container **contp, JSON_Value *cmd_v);
int container_start(struct docker_container *cont);
int container_state(struct docker_container *cont, int *state_status,
		    int *state_health_status);
int container_logs(struct docker_container *cont);
int container_stop(struct docker_container *cont, unsigned int timeout_sec);
int container_wait(struct docker_container *cont);
int container_delete(struct docker_container *cont);
void container_free(struct docker_container *cont);
const char *container_id(struct docker_container *cont);
int docker_parse_image_ref(const char *fromImage, const char **domainp,
			   size_t *domain_lenp, const char **tagp,
			   size_t *tag_lenp, const char **digestp,
			   size_t *digest_lenp);

const char *docker_get_registry_auth_var_name(const char *fromImage);
char *docker_get_registry_auth_header(const char *fromImage);

/*
 * DOCKER_CONTAINER_STATE_STATUS: The container status in docker.
 *
 * Note: DOCKER_CONTAINER_STATE_STATUS_NONE is not a docker status.
 * It means that we haven't successfully queried the status yet.
 * It's what module_instance->state_status is when the structure is
 * initialized with calloc().
 */

enum DOCKER_CONTAINER_STATE_STATUS {
	DOCKER_CONTAINER_STATE_STATUS_UNKNOWN = -1,
	DOCKER_CONTAINER_STATE_STATUS_NONE = 0,
	DOCKER_CONTAINER_STATE_STATUS_CREATED = 1,
	DOCKER_CONTAINER_STATE_STATUS_RUNNING = 2,
	DOCKER_CONTAINER_STATE_STATUS_PAUSED = 3,
	DOCKER_CONTAINER_STATE_STATUS_RESTARTING = 4,
	DOCKER_CONTAINER_STATE_STATUS_REMOVING = 5,
	DOCKER_CONTAINER_STATE_STATUS_EXITED = 6,
	DOCKER_CONTAINER_STATE_STATUS_DEAD = 7,
};

enum DOCKER_CONTAINER_STATE_STATUS
docker_container_state_status(const char *name);

enum DOCKER_CONTAINER_STATE_HEALTH_STATUS {
	DOCKER_CONTAINER_STATE_HEALTH_STATUS_UNKNOWN = -1,
	DOCKER_CONTAINER_STATE_HEALTH_STATUS_NONE = 1,
	DOCKER_CONTAINER_STATE_HEALTH_STATUS_STARTING = 2,
	DOCKER_CONTAINER_STATE_HEALTH_STATUS_HEALTHY = 3,
	DOCKER_CONTAINER_STATE_HEALTH_STATUS_UNHEALTHY = 4,
};

enum DOCKER_CONTAINER_STATE_HEALTH_STATUS
docker_container_state_health_status(const char *name);

#endif /* !defined(__DOCKER_H__) */
