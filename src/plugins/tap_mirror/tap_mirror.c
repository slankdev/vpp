/*
 * Copyright (c) 2019 Hiroki Shirokura
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vnet/osi/osi.h>
#include <vnet/fib/fib_types.h>
#include <vnet/ethernet/arp_packet.h>
#include <vnet/mfib/mfib_types.h>
#include <vnet/mfib/mfib_table.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/dpo/dpo.h>
#include <vnet/dpo/replicate_dpo.h>

#include <tap_mirror/tap_mirror.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <vppinfra/vec.h>
#include <vnet/unix/tuntap.h>
#include <vlib/unix/unix.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <netinet/in.h>

#include <tap_mirror/tap_mirror_msg_enum.h>
#define vl_typedefs
#include <tap_mirror/tap_mirror_all_api_h.h>
#undef vl_typedefs
#define vl_endianfun
#include <tap_mirror/tap_mirror_all_api_h.h>
#undef vl_endianfun
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <tap_mirror/tap_mirror_all_api_h.h>
#undef vl_printfun
#define vl_api_version(n,v) static uint32_t api_version=(v);
#include <tap_mirror/tap_mirror_all_api_h.h>
#undef vl_api_version
#define REPLY_MSG_ID_BASE mmp->msg_id_base
#include <vlibapi/api_helper_macros.h>
#define vl_msg_name_crc_list
#include <tap_mirror/tap_mirror_all_api_h.h>
#undef vl_msg_name_crc_list

#include <tap_mirror/tap_mirror_cli.h>

vlib_node_registration_t tap_mirror_node;

static tap_mirror_main_t *
tap_mirror_get_main(void)
{
  static tap_mirror_main_t tap_mirror_main;
  return &tap_mirror_main;
}

int
tap_inject_is_enabled (void)
{
  printf("SLANKDEV: %s\n", __func__);
  tap_mirror_main_t * im = tap_mirror_get_main ();
  return !!(im->flags & TAP_MIRROR_F_ENABLED);
}

int
tap_inject_is_config_disabled (void)
{
  printf("SLANKDEV: %s\n", __func__);
  tap_mirror_main_t * im = tap_mirror_get_main ();
  return !!(im->flags & TAP_MIRROR_F_CONFIG_DISABLE);
}

static clib_error_t *
tap_mirror_init (vlib_main_t *vm)
{
  printf("SLANKDEV: %s\n", __func__);
  tap_mirror_main_t * mmp = tap_mirror_get_main();
  mmp->vlib_main = vm;
  mmp->vnet_main = vnet_get_main();
  mmp->mirror_node_index = tap_mirror_node.index;

  uint8_t * name = format (0, "tap_mirror_%08x%c", api_version, 0);
  mmp->msg_id_base = vl_msg_api_get_msg_ids
      ((char *) name, VL_MSG_FIRST_AVAILABLE);
  vec_free(name);
  return NULL;
}

static uint64_t
tap_mirror_input_fn (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * f)
{
  printf("SLANKDEV: %s\n", __func__);
  uint32_t* pkts = vlib_frame_vector_args (f);
  vlib_buffer_free (vm, pkts, f->n_vectors);
  return f->n_vectors;
}

VLIB_INIT_FUNCTION (tap_mirror_init);

VNET_FEATURE_INIT (tap_mirror, static) =
{
  .arc_name = "device-input",
  .node_name = "tap_mirror",
  .runs_after = VNET_FEATURES ("ethernet-input"),
};

VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "tap_mirror plugin for operational debug",
};

VLIB_REGISTER_NODE (tap_mirror_node) = {
  .function = tap_mirror_input_fn,
  .name = "tap-mirror-input",
  .vector_size = sizeof (uint32_t),
  .type = VLIB_NODE_TYPE_INTERNAL,
};

VLIB_CLI_COMMAND (set_node_tap_mirror, static) = {
  .path = "set node tap-mirror",
  .short_help = "set node tap-mirror <node-name> <tap-name> [reset]",
  .function = set_node_tap_mirror_fn,
};

VLIB_CLI_COMMAND (show_tap_inject_cmd, static) = {
  .path = "show tap-mirror",
  .short_help = "show tap-mirror",
  .function = show_tap_mirror_fn,
};

