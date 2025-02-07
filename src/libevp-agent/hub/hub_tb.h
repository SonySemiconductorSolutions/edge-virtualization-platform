/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

struct transport_ctxt;
struct evp_agent_context;
struct telemetry_entries;
struct direct_command_response;
struct request;

void hub_evp1_tb_on_message(struct evp_agent_context *ctxt, const char *topic,
			    int packet_id, int qos_level, const char *payload);
void hub_evp2_tb_on_message(struct evp_agent_context *ctxt, const char *topic,
			    int packet_id, int qos_level, const char *payload);
void hub_evp1_tb_on_connected(struct evp_agent_context *ctxt,
			      struct transport_ctxt *transport,
			      const char *device_id, const char *client_id);
void hub_evp2_tb_on_connected(struct evp_agent_context *ctxt,
			      struct transport_ctxt *transport,
			      const char *device_id, const char *client_id);
bool hub_tb_is_ready_to_report(void);
int hub_tb_send_telemetry(struct transport_ctxt *ctxt,
			  const struct telemetry_entries *telemetry_entries);
int hub_tb_evp1_send_direct_command_response(
	struct transport_ctxt *ctxt, struct direct_command_response *response);
int hub_tb_evp2_send_direct_command_response(
	struct transport_ctxt *ctxt, struct direct_command_response *response);
int hub_tb_send_periodic_report(struct request *req);

int hub_tb_send_rpc_request(struct evp_agent_context *agent,
			    struct request *req, JSON_Value *v);
