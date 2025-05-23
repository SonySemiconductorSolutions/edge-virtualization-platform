/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * This file is intended to implement the minimum necessary subset
 * of the Docker API 1.40
 *
 * Reference: https://docs.docker.com/engine/api/v1.40/
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <parson.h>

#include <internal/evp_config.h>
#include <internal/util.h>

#include "webclient/webclient.h"

#include "cdefs.h"
#include "connections.h"
#include "docker.h"
#include "webclient_mbedtls.h"
#include "xlog.h"

/*
 * The buffer used to make the http request (not including the body) 1024 is
 * enough for the "common" requests, keep in mind to add extra size for big
 * headers
 */
#define DOCKER_WEBCLIENT_BUFF_MIN_SIZE (1024)

/*
 * Labels for docker containers.
 */
#define EVP_LABEL_MANAGED "com.sss.evp.managed-by-evp-agent"

/*
 *
 * >>> d={'label':['com.sss.evp.managed-by-evp-agent']}
 * >>> urllib.parse.quote(json.dumps(d))
 * '%7B%22label%22%3A%20%5B%22com.sss.evp.managed-by-evp-agent%22%5D%7D'
 */
static const char *evp_label_managed_filters =
	"%7B%22label%22%3A%20%5B%22" EVP_LABEL_MANAGED "%22%"
	"5D%7D";

struct docker {
	const char *api;
	struct mbedtls_ssl_config *ssl_config;
	const char *unix_socket;
};

struct docker_container {
	struct docker *docker;
	const char *id;
};

static int
_noop_write_func(unsigned http_status, char **bufp, int offset, int datend,
		 int *buflen, void *vp)
{
	xlog_trace("response body: %.*s", (int)(datend - offset),
		   (*bufp) + offset);
	return 0;
}

static int
write_to_file_func(unsigned http_status, char **bufp, int offset, int datend,
		   int *buflen, void *vp)
{
	xlog_trace("response body: %.*s", (int)(datend - offset),
		   (*bufp) + offset);
	FILE *fp = vp;
	size_t written = fwrite((*bufp) + offset, datend - offset, 1, fp);
	if (written != 1) {
		return -EIO;
	}
	return 0;
}

static int
write_to_xlog_fn(unsigned http_status, char **bufp, int offset, int datend,
		 int *buflen, void *vp)
{
	xlog_info("response body: %.*s", (int)(datend - offset),
		  (*bufp) + offset);
	return 0;
}

/*
 * The stream format is documented in:
 * https://docs.docker.com/engine/api/v1.40/#operation/ContainerAttach
 */

struct docker_stream_hdr {
	uint8_t type;
	uint8_t zero1;
	uint8_t zero2;
	uint8_t zero3;
	uint8_t size1;
	uint8_t size2;
	uint8_t size3;
	uint8_t size4;
};

struct docker_stream_state {
	size_t bytes_received;
	struct docker_stream_hdr hdr;
	FILE *out;
};

static int
docker_stream_fn(unsigned http_status, char **bufp, int offset, int datend,
		 int *buflen, void *vp)
{
	const void *p = (*bufp) + offset;
	size_t n = datend - offset;
	struct docker_stream_state *state = vp;

	while (n > 0) {
		if (state->bytes_received < sizeof(state->hdr)) {
			size_t sz = sizeof(state->hdr) - state->bytes_received;
			if (sz > n) {
				sz = n;
			}
			memcpy((char *)&state->hdr + state->bytes_received, p,
			       sz);
			p += sz;
			n -= sz;
			state->bytes_received += sz;
			if (state->bytes_received == sizeof(state->hdr)) {
				if (state->hdr.type == 0) {
					fprintf(state->out,
						"STDIN :"); /* XXX can this
							       happen? */
				}
				if (state->hdr.type == 1) {
					fprintf(state->out, "STDOUT:");
				}
				if (state->hdr.type == 2) {
					fprintf(state->out, "STDERR:");
				}
			}
		}
		if (state->bytes_received >= sizeof(state->hdr)) {
			size_t datasz = ((uint32_t)state->hdr.size1 << 24) +
					((uint32_t)state->hdr.size2 << 16) +
					((uint32_t)state->hdr.size3 << 8) +
					((uint32_t)state->hdr.size4);
			size_t sz = datasz - (state->bytes_received -
					      sizeof(state->hdr));
			if (sz > n) {
				sz = n;
			}
			fwrite(p, sz, 1, state->out);
			p += sz;
			n -= sz;
			state->bytes_received += sz;
			assert(state->bytes_received <=
			       sizeof(state->hdr) + datasz);
			if (state->bytes_received ==
			    sizeof(state->hdr) + datasz) {
				state->bytes_received = 0;
			}
		}
	}
	return 0;
}

#define MAX_EXTRA_HEADERS 1

static int
do_http(struct docker *docker, const char *method, const char *url,
	const char **extra_headers, unsigned int n_extra_headers,
	const char *body, unsigned int timeout_sec,
	webclient_sink_callback_t sink_cb, void *sink_cb_data,
	unsigned int *statusp, char **reasonp, bool verbose)
{
	// TODO: Replace assert (programming error)
	assert(n_extra_headers <= MAX_EXTRA_HEADERS);

	struct webclient_context ctx;
	int ret;

	if (verbose) {
		xlog_info("request method: %s url: %s", method, url);
		if (strlen(body)) {
			xlog_info("request body: %s", body);
		}
	} else {
		xlog_trace("request method: %s url: %s", method, url);
		if (strlen(body)) {
			xlog_trace("request body: %s", body);
		}
	}

	webclient_set_defaults(&ctx);
	ctx.protocol_version = WEBCLIENT_PROTOCOL_VERSION_HTTP_1_1;

	/* request */
	const char *headers[1 + MAX_EXTRA_HEADERS] = {
		"Content-Type: application/json"};
	unsigned int nheaders = 1;
	unsigned int i;
	unsigned int buffer_len_total = DOCKER_WEBCLIENT_BUFF_MIN_SIZE;

	for (i = 0; i < n_extra_headers; i++) {
		headers[nheaders + i] = extra_headers[i];
		buffer_len_total += strlen(extra_headers[i]);
		xlog_trace("ctx buffer: header[%d] add %zu total %d", i,
			   strlen(extra_headers[i]), buffer_len_total);
	}

	ctx.buffer = xmalloc(buffer_len_total);
	ctx.buflen = buffer_len_total;

	nheaders += n_extra_headers;
	ctx.method = method;
	ctx.url = url;
	ctx.headers = headers;
	ctx.nheaders = nheaders;

	/* i/o */
	webclient_set_static_body(&ctx, body, strlen(body));
	if (sink_cb != NULL) {
		ctx.sink_callback = sink_cb;
		ctx.sink_callback_arg = sink_cb_data;
	} else {
		ctx.sink_callback = _noop_write_func;
		ctx.sink_callback_arg = NULL;
	}

	/* tls */
	struct webclient_mbedtls_param tls_param = {
		.insecure = false,
		.nonblocking = true,
		.ssl_config = docker->ssl_config,
	};
	if (docker->ssl_config) {
		ctx.tls_ops = &mbedtls_tls_ops;
		ctx.tls_ctx = &tls_param;
	}

	/* unix domain socket */
	ctx.unix_socket_path = docker->unix_socket;

	/* results */
	char reason[256];
	ctx.http_reason = reason;
	ctx.http_reason_len = sizeof(reason);

	/* timeout */
	if (timeout_sec > 0) { /* 0 means "use the default" */
		ctx.timeout_sec = timeout_sec;
	}

	ret = connections_webclient_perform(&ctx);
	free(ctx.buffer);
	if (ret < 0) {
		xlog_warning("webclient_perform failed with %d", ret);
		/*
		 * Connect with unix domain socket can fail with ENOENT
		 * if the server is not ready. Treat it as ECONNREFUSED,
		 * which would happen for similar cases with TCP, to make
		 * it easiser for the caller to deal with.
		 *
		 * Note: Right now, missing certs/key files for TLS causes EIO
		 * here, not ENOENT.
		 * (MBEDTLS_ERR_X509_FILE_IO_ERROR and
		 * MBEDTLS_ERR_PK_FILE_IO_ERROR)
		 */
		if (ret == -ENOENT && docker->unix_socket != NULL) {
			xlog_warning("Treating ENOENT for unix socket as "
				     "ECONNREFUSED");
			ret = -ECONNREFUSED;
		}
		return -ret;
	}

	if (verbose) {
		xlog_info("http status=%u reason=%s", ctx.http_status, reason);
	} else {
		/* log at info only on an error */
		if ((ctx.http_status / 100) >= 4) {
			xlog_info("(it was sent before) request method: %s "
				  "url: %s",
				  method, url);
			xlog_info("http status=%u reason=%s", ctx.http_status,
				  reason);
		} else {
			xlog_trace("http status=%u reason=%s", ctx.http_status,
				   reason);
		}
	}

	if (statusp != NULL) {
		*statusp = ctx.http_status;
	} else {
		if ((ctx.http_status / 100) >= 4) {
			return EIO; /* XXX */
		}
	}
	if (reasonp != NULL) {
		*reasonp = xstrdup(ctx.http_reason);
	}
	return 0;
}

struct docker *
docker_create(const char *api, struct mbedtls_ssl_config *ssl_config,
	      const char *unix_socket)
{
	struct docker *docker = xcalloc(1, sizeof(*docker));
	docker->api = api;
	docker->ssl_config = ssl_config;
	docker->unix_socket = unix_socket;
	return docker;
}

void
docker_free(struct docker *docker)
{
	free(docker);
}

int
docker_parse_image_ref(const char *fromImage, const char **domainp,
		       size_t *domain_lenp, const char **tagp,
		       size_t *tag_lenp, const char **digestp,
		       size_t *digest_lenp)
{
	/*
	 * References:
	 * https://github.com/docker/distribution/blob/35b26def43c1f0bff65f349a058644cf45181338/reference/reference.go#L1-L24
	 * https://github.com/docker/distribution/blob/35b26def43c1f0bff65f349a058644cf45181338/reference/regexp.go#L58-L63
	 * https://github.com/docker/distribution/blob/35b26def43c1f0bff65f349a058644cf45181338/reference/normalize.go#L88-L105
	 */

	const char *sep = strchr(fromImage, '/');
	const char *last_component;
	if (sep == NULL) {
		last_component = fromImage;
		goto use_default;
	}
	const char *domain = fromImage;
	size_t domain_len = sep - fromImage;
	last_component = sep + 1;
	if (strcspn(domain, ".:") > domain_len &&
	    strncmp(domain, "localhost", domain_len)) {
	use_default:
		domain = "docker.io";
		domain_len = strlen(domain);
	}
	const char *tag;
	size_t tag_len;
	const char *tag_sep = strchr(last_component, ':');
	const char *digest;
	size_t digest_len;
	const char *digest_sep = strchr(last_component, '@');
	/*
	 * Note: While unusual, it's valid for an image reference to have
	 * both of tag and digest.
	 *
	 * Note: A digest usually contains ":". Don't misunderstand it as a
	 * tag. eg. sha256:b0729a3b....
	 */
	if (digest_sep != NULL && tag_sep != NULL && tag_sep > digest_sep) {
		tag_sep = NULL;
	}
	if (tag_sep != NULL) {
		tag = tag_sep + 1;
		if (digest_sep != NULL) {
			tag_len = digest_sep - tag;
		} else {
			tag_len = strlen(tag);
		}
	} else {
		tag = NULL;
		tag_len = 0;
	}
	if (digest_sep != NULL) {
		digest = digest_sep + 1;
		digest_len = strlen(digest);
	} else {
		digest = NULL;
		digest_len = 0;
	}
	if (domainp != NULL) {
		*domainp = domain;
		*domain_lenp = domain_len;
	}
	if (tagp != NULL) {
		*tagp = tag;
		*tag_lenp = tag_len;
	}
	if (digestp != NULL) {
		*digestp = digest;
		*digest_lenp = digest_len;
	}
	return 0;
}

const char *
docker_get_registry_auth_var_name(const char *fromImage)
{
	/*
	 * for the image "xxx/yyy:zzz",
	 * look at the "EVP_REGISTRY_AUTH_xxx" environment variable.
	 *
	 * e.g. for the image "ghcr.io/aaa/bbb:latest",
	 * use "EVP_REGISTRY_AUTH_ghcr.io".
	 *
	 * REVISIT: maybe it's simpler to reject non-fully-qualified names.
	 *
	 * REVISIT: these environment variables are not convenient
	 * as their names are not valid for shell variables.
	 */

	xlog_trace("looking for auth setting for image %s", fromImage);
	const char *domain;
	size_t domain_len;
	int error = docker_parse_image_ref(fromImage, &domain, &domain_len,
					   NULL, NULL, NULL, NULL);
	if (error != 0) {
		return NULL;
	}
	xlog_trace("looking for auth setting for domain %.*s", (int)domain_len,
		   domain);
	char *var_name;
	xasprintf(&var_name, "EVP_REGISTRY_AUTH_%.*s", (int)domain_len,
		  domain);
	return var_name;
}

static const char *
get_registry_auth_header_old(const char *fromImage)
{
	const char *var_name = docker_get_registry_auth_var_name(fromImage);
	const char *token = getenv(var_name);

	if (token == NULL) {
		xlog_info("%s: neither EVP_REGISTRY_AUTH or %s defined",
			  __func__, var_name);
		goto end;
	}

	xlog_warning("%s: using %s is deprecated, please define "
		     "EVP_REGISTRY_AUTH as a JSON database instead",
		     __func__, var_name);

end:
	free(__UNCONST(var_name));
	return token;
}

char *
docker_get_registry_auth_header(const char *fromImage)
{
	char *h = NULL;
	const char *auth = NULL;
	char *domain = NULL;
	JSON_Value *v = NULL;
	char *db = config_get_string(EVP_CONFIG_REGISTRY_AUTH);

	if (db == NULL) {
		auth = get_registry_auth_header_old(fromImage);

		if (auth == NULL) {
			goto end;
		}
	} else {
		const char *domain_ref;
		size_t domain_len;
		int error = docker_parse_image_ref(fromImage, &domain_ref,
						   &domain_len, NULL, NULL,
						   NULL, NULL);

		if (error) {
			xlog_error("%s: docker_parse_image_ref(%s) failed",
				   __func__, fromImage);
			goto end;
		}

		xasprintf(&domain, "%.*s", (int)domain_len, domain_ref);

		v = json_parse_string(db);

		if (v == NULL) {
			xlog_error("%s: failed to parse: %s", __func__, db);
			goto end;
		}

		const JSON_Object *o = json_value_get_object(v);

		if (o == NULL) {
			xlog_error("%s: Not a JSON object: %s", __func__, db);
			goto end;
		}

		auth = json_object_get_string(o, domain);

		if (auth == NULL) {
			xlog_info("%s: registry %s not found on "
				  "EVP_REGISTRY_AUTH",
				  __func__, domain);
			goto end;
		}
		xlog_info("%s: registry %s was found in EVP_REGISTRY_AUTH",
			  __func__, domain);
	}

	xasprintf(&h, "X-Registry-Auth: %s", auth);
	xlog_trace("built an auth header: %s", h);
end:
	json_value_free(v);
	free(domain);
	free(db);
	return h;
}

int
image_create(struct docker *docker, const char *fromImage)
{
	char *url;
	int ret;

	const char *tag;
	size_t tag_len;
	const char *digest;
	size_t digest_len;
	ret = docker_parse_image_ref(fromImage, NULL, NULL, &tag, &tag_len,
				     &digest, &digest_len);
	if (ret != 0) {
		return ret;
	}
	if (tag == NULL && digest == NULL) {
		xlog_warning("%s: Image references without tag or digest are "
			     "not supported: %s",
			     __func__, fromImage);
		/*
		 * It seems that the Docker API tries to pull all available
		 * tags in this case. It isn't likely what the user wants.
		 */
		return ENOTSUP;
	}
	xasprintf(&url, "%s/images/create?fromImage=%s", docker->api,
		  fromImage);
	const char *extra_header = docker_get_registry_auth_header(fromImage);
	unsigned int n_extra_headers;
	if (extra_header != NULL) {
		n_extra_headers = 1;
	} else {
		n_extra_headers = 0;
	}

	/*
	 * image create is a time consuming operation.
	 * docker streams us its progress via response body.
	 * log them so that we can investigate what's taking long.
	 *
	 * Some data points about the timeout value below:
	 * - Docker sends us their download progress for every 512KB.
	 *   https://github.com/moby/moby/blob/5e62ca1a05f2aab49066d91c9070cb7dc7ad2461/pkg/progress/progressreader.go#L37-L47
	 * - A customer said 120 seconds was enough to eliminate the
	 *   timeout issues he was observing with >1GB image on
	 *   his arm64 board. It might have been disk I/O related as it was
	 *   often in the "Extracting" phase. (ES-103)
	 * - kubelet dockersim has a timeout with a similar purpose and
	 *   semantics, ImagePullProgressDeadline/image-pull-progress-deadline.
	 *   Thier default is 60 seconds.
	 *   https://github.com/kubernetes/kubernetes/blob/b766721332da82f8a3eaa7dd3f131713d291f288/cmd/kubelet/app/options/container_runtime.go#L52
	 * - Mirantis cri-dockerd seems keeping it as it is.
	 *   https://github.com/Mirantis/cri-dockerd/blob/288a7a69b60bbef920eb5e6c6e5d66fb9b7cc3ed/pkg/app/options/container_runtime.go#L51
	 */

	unsigned int timeout_sec = 120;
	ret = do_http(docker, "POST", url, &extra_header, n_extra_headers, "",
		      timeout_sec, write_to_xlog_fn, NULL, NULL, NULL, true);
	free(url);
	free(__UNCONST(extra_header));
	return ret;
}

int
image_inspect(struct docker *docker, const char *image)
{
	char *url;
	int ret;

	/*
	 * Note: We don't have a use case which actually needs
	 * the message body.
	 * Just send it to xlog for now.
	 */

	unsigned int status;
#if defined(__clang_analyzer__)
	status = 9999;
#endif
	xasprintf(&url, "%s/images/%s/json", docker->api, image);
	ret = do_http(docker, "GET", url, NULL, 0, "", 0, write_to_xlog_fn,
		      NULL, &status, NULL, true);
	free(url);
	if (ret != 0) {
		return ret;
	}
	if (status / 100 >= 4) {
		if (status == 404) {
			return ENOENT;
		}
		return EIO;
	}
	return 0;
}

int
image_prune(struct docker *docker)
{
	char *url;
	int ret;

	/*
	 * XXX the filters is hardcoded because I don't want to implement
	 * url quoting.
	 *
	 * >>> d={'dangling':['false']}
	 * >>> urllib.parse.quote(json.dumps(d))
	 * '%7B%22dangling%22%3A%20%5B%22false%22%5D%7D'
	 */
	const char *filters = "%7B%22dangling%22%3A%20%5B%22false%22%5D%7D";
	xasprintf(&url, "%s/images/prune?filters=%s", docker->api, filters);
	ret = do_http(docker, "POST", url, NULL, 0, "", 0, NULL, NULL, NULL,
		      NULL, false);
	free(url);
	return ret;
}

int
container_list(struct docker *docker, int (*cb)(const char *, void *),
	       void *user, bool all)
{
	char *url;
	int ret;

	xasprintf(&url, "%s/containers/json?all=%d&filters=%s", docker->api,
		  all, evp_label_managed_filters);
	char *buf;
	size_t buflen;
	FILE *fp = open_memstream(&buf, &buflen);
	if (fp == NULL) {
		return EIO;
	}
	unsigned int status;
#if defined(__clang_analyzer__)
	status = 9999;
#endif
	ret = do_http(docker, "GET", url, NULL, 0, "", 0, write_to_file_func,
		      fp, &status, NULL, false);
	free(url);
	fclose(fp);
	if (ret != 0) {
		xlog_warning("do_http failed with %d", ret);
		free(buf);
		return ret;
	}
	if (status / 100 >= 4) {
		free(buf);
		if (status == 404) {
			/*
			 * Docker API returns 404 when it has no containers to
			 * show.
			 */
			return 0;
		}
		xlog_warning("do_http failed with http status %u", status);
		return EIO;
	}
	/*
	 * Ensure NUL termination.
	 */
	buf = xrealloc(buf, buflen + 1);
	buf[buflen] = 0;
	/*
	 * The response body (in buf) looks like:
	 *
	 */
	JSON_Value *result_v = json_parse_string(buf);
	free(buf);
	if (result_v == NULL) {
		return EINVAL;
	}

	JSON_Array *a = json_value_get_array(result_v);
	size_t sz = json_array_get_count(a);
	size_t i;
	ret = 0;
	for (i = 0; i < sz; i++) {
		JSON_Object *c = json_array_get_object(a, i);
		if (c == NULL) {
			ret = EINVAL;
			goto free_result;
		}
		const char *id = json_object_get_string(c, "Id");
		ret = cb(id, user);
		if (ret != 0) {
			break;
		}
	}
free_result:
	json_value_free(result_v);
	return ret;
}

static int
_container_kill(const char *id, void *user)
{
	struct docker *docker = user;
	char *url;
	int ret;

	xasprintf(&url, "%s/containers/%s/kill", docker->api, id);
	ret = do_http(docker, "POST", url, NULL, 0, "", 0, NULL, NULL, NULL,
		      NULL, true);
	free(url);
	return ret;
}

int
container_killall(struct docker *docker)
{
	return container_list(docker, _container_kill, docker, false);
}

int
container_prune(struct docker *docker)
{
	char *url;
	int ret;

	xasprintf(&url, "%s/containers/prune?filters=%s", docker->api,
		  evp_label_managed_filters);
	ret = do_http(docker, "POST", url, NULL, 0, "", 0, NULL, NULL, NULL,
		      NULL, true);
	free(url);
	return ret;
}

static int
_container_delete(const char *id, void *user)
{
	struct docker_container cont;
	int ret;

	cont.docker = user;
	cont.id = id;

	ret = container_delete(&cont);

	return ret;
}

int
container_deleteall(struct docker *docker)
{
	return container_list(docker, _container_delete, docker, true);
}

int
container_create_raw(struct docker *docker, const char *name, JSON_Value *v,
		     struct docker_container **contp)
{
	struct docker_container *cont;
	char *url;
	int ret;

	char *body = json_serialize_to_string_pretty(v);
	if (name != NULL) {
		/*
		 * No need to url quoting here because a name should be
		 * [a-zA-Z0-9][a-zA-Z0-9_.-]
		 */
		xasprintf(&url, "%s/containers/create?name=%s", docker->api,
			  name);
	} else {
		xasprintf(&url, "%s/containers/create", docker->api);
	}
	char *buf;
	size_t buflen;
	FILE *fp = open_memstream(&buf, &buflen);
	if (fp == NULL) {
		free(body);
		return EIO;
	}
	unsigned int status;
#if defined(__clang_analyzer__)
	status = 9999;
#endif
	ret = do_http(docker, "POST", url, NULL, 0, body, 0,
		      write_to_file_func, fp, &status, NULL, true);
	free(url);
	json_free_serialized_string(body);
	fclose(fp);
	if (ret != 0) {
		xlog_warning("do_http failed with %d", ret);
		free(buf);
		return ret;
	}
	if (status / 100 >= 4) {
		switch (status) {
		case 404:
			/*
			 * when the specified image is not found, docker
			 * returns:
			 *
			 *    http status: 404
			 *    reason: Not Found
			 *    response body:
			 *    '{"message":"No such image: alpine:latest"}'
			 *
			 * XXX do we want to check the message in the response
			 * body to be sure?
			 */
			ret = ENOENT;
			break;
		default:
			ret = EIO;
			break;
		}
		free(buf);
		return ret;
	}

	/*
	 * Ensure NUL termination.
	 */
	buf = xrealloc(buf, buflen + 1);
	buf[buflen] = 0;
	/*
	 * The response body (in buf) looks like:
	 * {"Id":"8df9bf48c9f91518026cd3b121644a7c69647c1c0d0eec1fbc95c0dc2db58f52","Warnings":[]}
	 */
	JSON_Value *result_v = json_parse_string(buf);
	free(buf);
	if (result_v == NULL) {
		return EINVAL;
	}
	JSON_Object *result = json_value_get_object(result_v);
	cont = xcalloc(1, sizeof(*cont));
	cont->docker = docker;
	cont->id = xstrdup(json_object_get_string(result, "Id"));
	json_value_free(result_v);
	*contp = cont;
	return 0;
}

int
container_create(struct docker *docker, const char *image, unsigned int nbinds,
		 const struct docker_bind *binds,
		 struct docker_container **contp, JSON_Value *cmd_v)
{
	int ret = EINVAL;

	/*
	 * Build JSON like the following:
	 *
	 *    {"Image":"<image>",
	 *     "Tty":true,
	 *     "HostConfig":{"NetworkMode":"none"}}
	 *
	 * XXX we might want to specify:
	 *   the console/tty stuff
	 *   Cmd
	 *   EntryPoint
	 *   Env
	 *   HealthCheck
	 *   HostName
	 *   HostConfig.RestartPolicy
	 *   HostConfig.AutoRemove
	 *   HostConfig.Privileged
	 */
	JSON_Status jstatus;
	JSON_Value *v = json_value_init_object();
	if (v == NULL) {
		return ENOMEM;
	}

	JSON_Object *o = json_value_get_object(v);

	jstatus = json_object_dotset_string(o, "Image", image);
	if (jstatus != JSONSuccess) {
		goto out;
	}
	jstatus =
		json_object_dotset_string(o, "HostConfig.NetworkMode", "none");
	if (jstatus != JSONSuccess) {
		goto out;
	}
	jstatus = json_object_dotset_boolean(o, "Tty", true);
	if (jstatus != JSONSuccess) {
		goto out;
	}
	JSON_Value *labels_v = json_value_init_object();
	if (labels_v == NULL) {
		goto out;
	}
	JSON_Object *labels_obj = json_value_get_object(labels_v);
	jstatus = json_object_set_string(labels_obj, EVP_LABEL_MANAGED, "");
	if (jstatus != JSONSuccess) {
		goto out;
	}
	jstatus = json_object_dotset_value(o, "Labels", labels_v);
	if (jstatus != JSONSuccess) {
		goto out;
	}
	JSON_Value *binds_v = json_value_init_array();
	if (binds_v == NULL) {
		ret = ENOMEM;
		goto out;
	}
	JSON_Array *binds_array = json_value_get_array(binds_v);
	unsigned int i;
	for (i = 0; i < nbinds; i++) {
		const struct docker_bind *b = &binds[i];
		char bind_string[PATH_MAX * 2];

		ret = snprintf(bind_string, sizeof(bind_string), "%s:%s",
			       b->host_src, b->container_dest);
		if (ret < 0 || (unsigned)ret >= sizeof(bind_string)) {
			goto out;
		}
		jstatus = json_array_append_string(binds_array, bind_string);
		if (jstatus != JSONSuccess) {
			goto out;
		}
	}
	jstatus = json_object_dotset_value(o, "HostConfig.Binds", binds_v);
	if (jstatus != JSONSuccess) {
		goto out;
	}

	if (cmd_v) {
		json_object_dotset_value(o, "Cmd", cmd_v);
	}

	ret = container_create_raw(docker, NULL, v, contp);
out:
	json_value_free(v);
	return ret;
}

int
container_start(struct docker_container *cont)
{
	struct docker *docker = cont->docker;
	char *url;
	int ret;

	xasprintf(&url, "%s/containers/%s/start", docker->api, cont->id);
	ret = do_http(docker, "POST", url, NULL, 0, "", 0, NULL, NULL, NULL,
		      NULL, true);
	free(url);
	return ret;
}

int
container_state(struct docker_container *cont, int *state_status,
		int *state_health_status)
{
	if (cont == NULL) {
		return EINVAL;
	}

	struct docker *docker = cont->docker;
	char *url;
	int ret;

	xasprintf(&url, "%s/containers/%s/json", docker->api, cont->id);
	char *buf;
	size_t buflen;
	FILE *fp = open_memstream(&buf, &buflen);
	if (fp == NULL) {
		free(url);
		return EIO;
	}
	ret = do_http(docker, "GET", url, NULL, 0, "", 0, write_to_file_func,
		      fp, NULL, NULL, false);
	free(url);
	fclose(fp);
	if (ret != 0) {
		printf("do_http failed with %d\n", ret);
		free(buf);
		return ret;
	}

	/*
	 * Ensure NUL termination.
	 */
	buf = xrealloc(buf, buflen + 1);
	buf[buflen] = 0;
	JSON_Value *result_v = json_parse_string(buf);
	free(buf);
	if (result_v == NULL) {
		return ENOMEM;
	}
	JSON_Object *result = json_value_get_object(result_v);

	const char *state_status_string = NULL;
	state_status_string =
		json_object_dotget_string(result, "State.Status");
	if (state_status_string == NULL) {
		ret = EINVAL;
		goto out;
	}
	*state_status = docker_container_state_status(state_status_string);

	const char *state_health_status_string = NULL;
	state_health_status_string =
		json_object_dotget_string(result, "State.Health.Status");
	if (state_health_status_string == NULL) {
		*state_health_status =
			DOCKER_CONTAINER_STATE_HEALTH_STATUS_NONE;
	} else {
		*state_health_status = docker_container_state_health_status(
			state_health_status_string);
	}
out:
	json_value_free(result_v);
	return 0;
}

int
container_logs(struct docker_container *cont)
{
	struct docker *docker = cont->docker;
	char *url;
	int ret;

	xasprintf(&url,
		  "%s/containers/%s/"
		  "logs?stdout=true&stderr=true&timestamps=true",
		  docker->api, cont->id);
	struct docker_stream_state state;
	memset(&state, 0, sizeof(state));
	state.out = stdout;
	ret = do_http(docker, "GET", url, NULL, 0, "", 0, docker_stream_fn,
		      &state, NULL, NULL, true);
	free(url);
	return ret;
}

int
container_stop(struct docker_container *cont, unsigned int timeout_sec)
{
	struct docker *docker = cont->docker;
	char *url;
	int ret;
	unsigned int status;

	xasprintf(&url, "%s/containers/%s/stop?t=%u", docker->api, cont->id,
		  timeout_sec);
#if defined(__clang_analyzer__)
	status = 9999;
#endif
	ret = do_http(docker, "POST", url, NULL, 0, "", 0, NULL, NULL, &status,
		      NULL, true);
	free(url);

	if (ret != 0) {
		return ret;
	}
	if (status / 100 >= 4) {
		/*
		 * when the specified container is not found, docker
		 * returns:
		 *
		 *    http status: 404
		 *    reason: Not Found
		 *
		 * It shouldn't happen for ordinary EVP module instances.
		 * But it's normal for RAW_CONTAINER_SPEC containers with
		 * AutoRemove.
		 */
		if (status == 404) {
			return ENOENT;
		}
		return EIO; /* XXX */
	}
	return ret;
}

int
container_wait(struct docker_container *cont)
{
	struct docker *docker = cont->docker;
	char *url;
	int ret;

	xasprintf(&url, "%s/containers/%s/wait", docker->api, cont->id);
	ret = do_http(docker, "POST", url, NULL, 0, "", 0, NULL, NULL, NULL,
		      NULL, true);
	free(url);
	return ret;
}

int
container_delete(struct docker_container *cont)
{
	struct docker *docker = cont->docker;
	char *url;
	int ret;
	unsigned int status;

	xasprintf(&url, "%s/containers/%s?v=1", docker->api, cont->id);
#if defined(__clang_analyzer__)
	status = 9999;
#endif
	ret = do_http(docker, "DELETE", url, NULL, 0, "", 0, NULL, NULL,
		      &status, NULL, true);
	free(url);

	if (ret != 0) {
		return ret;
	}
	if (status / 100 >= 4) {
		switch (status) {
		case 404:
			/*
			 * when the specified container is not found, docker
			 * returns:
			 *
			 *    http status: 404
			 *    reason: Not Found
			 *
			 * For our current usage, it's ok to ignore.
			 *
			 * It shouldn't happen for ordinary EVP module
			 * instances. But it's normal for RAW_CONTAINER_SPEC
			 * containers with AutoRemove.
			 */
			ret = 0;
			break;
		case 409:
			/*
			 * when container is being removed, docker
			 * returns:
			 *
			 *    http status: 409
			 *    reason: Conflict
			 *
			 * In later stage, check container is really removed or
			 * not again.
			 *
			 * It shouldn't happen for ordinary EVP module
			 * instances. But it's normal for RAW_CONTAINER_SPEC
			 * containers with AutoRemove.
			 */
			ret = EALREADY;
			break;
		default:
			ret = EIO;
			break;
		}
	}
	return ret;
}

enum DOCKER_CONTAINER_STATE_STATUS
docker_container_state_status(const char *name)
{
	// TODO: Replace assert (programming error)
	assert(name != NULL);

	enum DOCKER_CONTAINER_STATE_STATUS result =
		DOCKER_CONTAINER_STATE_STATUS_UNKNOWN;

	if (strcmp(name, "created") == 0)
		result = DOCKER_CONTAINER_STATE_STATUS_CREATED;
	if (strcmp(name, "running") == 0)
		result = DOCKER_CONTAINER_STATE_STATUS_RUNNING;
	if (strcmp(name, "paused") == 0)
		result = DOCKER_CONTAINER_STATE_STATUS_PAUSED;
	if (strcmp(name, "restarting") == 0)
		result = DOCKER_CONTAINER_STATE_STATUS_RESTARTING;
	if (strcmp(name, "removing") == 0)
		result = DOCKER_CONTAINER_STATE_STATUS_REMOVING;
	if (strcmp(name, "exited") == 0)
		result = DOCKER_CONTAINER_STATE_STATUS_EXITED;
	if (strcmp(name, "dead") == 0)
		result = DOCKER_CONTAINER_STATE_STATUS_DEAD;

	return result;
}

enum DOCKER_CONTAINER_STATE_HEALTH_STATUS
docker_container_state_health_status(const char *name)
{
	// TODO: Replace assert (programming error)
	assert(name != NULL);

	enum DOCKER_CONTAINER_STATE_HEALTH_STATUS result =
		DOCKER_CONTAINER_STATE_HEALTH_STATUS_UNKNOWN;
	if (strcmp(name, "none") == 0)
		result = DOCKER_CONTAINER_STATE_HEALTH_STATUS_NONE;
	if (strcmp(name, "starting") == 0)
		result = DOCKER_CONTAINER_STATE_HEALTH_STATUS_STARTING;
	if (strcmp(name, "healthy") == 0)
		result = DOCKER_CONTAINER_STATE_HEALTH_STATUS_HEALTHY;
	if (strcmp(name, "unhealthy") == 0)
		result = DOCKER_CONTAINER_STATE_HEALTH_STATUS_UNHEALTHY;

	return result;
}

void
container_free(struct docker_container *cont)
{
	free(__UNCONST(cont->id));
	free(cont);
}

const char *
container_id(struct docker_container *cont)
{
	return cont->id;
}
