/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if !defined(__MODULES_COMMON_BLOB_CONFIG_H_)
#define __MODULES_COMMON_BLOB_CONFIG_H_

/* Module topic subscription */
#define TOPIC_INSTANCE_NAME    ("instance_name")
#define TOPIC_DOWNLOAD         ("download")
#define TOPIC_UPLOAD           ("upload")
#define TOPIC_LOCAL_FILE       ("local_file")
#define TOPIC_STORAGE_NAME_DEF ("storage_name_def")

/* Only used for upload blobs via mSTP */
#define TOPIC_UPLOAD_A       ("upload_a")
#define TOPIC_UPLOAD_B       ("upload_b")
#define TOPIC_STORAGE_NAME_A ("storage_name_a")
#define TOPIC_STORAGE_NAME_B ("storage_name_b")

#define BLOB_MEMORY_MAX_SIZE (4096)

#endif /* __MODULES_COMMON_BLOB_CONFIG_H_ */
