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

#define foreach_tap_mirror_plugin_api_msg \
_(TAP_INJECT_ENABLE_DISABLE, tap_inject_enable_disable) \
_(TAP_INJECT_DUMP, tap_inject_dump) \
_(TAP_INJECT_DETAILS, tap_inject_details) \
_(GET_NODE_INFO, get_node_info) \
_(GET_NODE_INFO_REPLY, get_node_info_reply) \
_(GET_PROC_INFO, get_proc_info) \
_(GET_PROC_INFO_REPLY, get_proc_info_reply) \

#define MTU 1500
#define MTU_BUFFERS ((MTU + VLIB_BUFFER_DATA_SIZE - 1) / VLIB_BUFFER_DATA_SIZE)
#define NUM_BUFFERS_TO_ALLOC 32
#define VLIB_BUFFER_DATA_SIZE (2048)

vlib_node_registration_t tap_mirror_node;

static tap_mirror_main_t *
tap_mirror_get_main(void)
{
  static tap_mirror_main_t tap_mirror_main;
  return &tap_mirror_main;
}

static int
tap_inject_is_enabled (void)
{
  printf("SLANKDEV: %s\n", __func__);
  tap_mirror_main_t * im = tap_mirror_get_main ();
  return !!(im->flags & TAP_INJECT_F_ENABLED);
}

static int
tap_inject_is_config_disabled (void)
{
  printf("SLANKDEV: %s\n", __func__);
  tap_mirror_main_t * im = tap_mirror_get_main ();
  return !!(im->flags & TAP_INJECT_F_CONFIG_DISABLE);
}

static clib_error_t *
tap_mirror_init (vlib_main_t *vm)
{
  printf("SLANKDEV: %s\n", __func__);
  tap_mirror_main_t * mmp = tap_mirror_get_main();
  mmp->vlib_main = vm;
  mmp->vnet_main = vnet_get_main();
  mmp->tx_node_index = tap_mirror_node.index;

  uint8_t * name = format (0, "tap_mirror_%08x%c", api_version, 0);
  mmp->msg_id_base = vl_msg_api_get_msg_ids
      ((char *) name, VL_MSG_FIRST_AVAILABLE);
  vec_free(name);
  return NULL;
}

static clib_error_t *
set_node_tap_mirror_fn (vlib_main_t * vm,
    unformat_input_t * input, vlib_cli_command_t * cmd)
{
  printf("SLANKDEV: %s\n", __func__);
  clib_error_t *err = NULL;
  return err;
}

static clib_error_t *
enable_disable_tap_inject_cmd_fn (vlib_main_t * vm, unformat_input_t * input,
                 vlib_cli_command_t * cmd)
{
  return 0;
}

static uint8_t *
format_tap_inject_tap_name (uint8_t * s, va_list * args)
{
  int fd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
  if (fd < 0)
    return 0;

  struct ifreq ifr;
  memset (&ifr, 0, sizeof (ifr));
  ifr.ifr_ifindex = va_arg (*args, uint32_t);
  if (ioctl (fd, SIOCGIFNAME, &ifr) < 0) {
    close (fd);
    return 0;
  }

  close (fd);
  return format (s, "%s", ifr.ifr_name);
}

static clib_error_t *
show_tap_inject (vlib_main_t * vm, unformat_input_t * input,
                 vlib_cli_command_t * cmd)
{
  if (tap_inject_is_config_disabled ()) {
    vlib_cli_output (vm, "tap-inject is disabled in config.\n");
    return 0;
  }

  if (!tap_inject_is_enabled ()) {
    vlib_cli_output (vm, "tap-inject is not enabled.\n");
    return 0;
  }

  vlib_cli_output (vm, "tap-inject is enabled.\n");
  uint32_t k, v;
  vnet_main_t * vnet_main = vnet_get_main ();
  tap_mirror_main_t * im = tap_mirror_get_main ();
  hash_foreach (k, v, im->tap_if_index_to_sw_if_index,
    /* routine */ {
      vnet_sw_interface_t *iface = vnet_get_sw_interface(vnet_main, v);
      vlib_cli_output (vm, "%U -> %U",
              format_vnet_sw_interface_name, vnet_main, iface,
              format_tap_inject_tap_name, k);
      vlib_cli_output(vm, "  vpp%u %U \n", v, format_vnet_sw_interface_name, vnet_main, iface);
      vlib_cli_output(vm, "  kern%u %U \n", k, format_tap_inject_tap_name, k);
    }
  );
  return 0;
}

static uint64_t
tap_inject_tx (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * f)
{
  printf("SLANKDEV: %s\n", __func__);
  uint32_t* pkts = vlib_frame_vector_args (f);
  vlib_buffer_free (vm, pkts, f->n_vectors);
  return f->n_vectors;
}

static uint32_t
tap_inject_lookup_sw_if_index_from_tap_fd (uint32_t tap_fd)
{
  tap_mirror_main_t * im = tap_mirror_get_main ();
  vec_validate_init_empty (im->tap_fd_to_sw_if_index, tap_fd, ~0);
  return im->tap_fd_to_sw_if_index[tap_fd];
}

static inline uint64_t
tap_rx (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * f, int fd)
{
  tap_mirror_main_t * im = tap_mirror_get_main ();
  uint32_t sw_if_index = tap_inject_lookup_sw_if_index_from_tap_fd (fd);
  if (sw_if_index == ~0)
    return 0;

  /* Allocate buffers in bulk when there are less than enough to rx an MTU. */
  if (vec_len (im->rx_buffers) < MTU_BUFFERS) {
    uint32_t len = vec_len (im->rx_buffers);
    uint8_t buffer_pool_index = vlib_buffer_pool_get_default_for_numa(vm, 0);
    len = vlib_buffer_alloc_from_pool (vm,
                  &im->rx_buffers[len], NUM_BUFFERS_TO_ALLOC,
                  buffer_pool_index);

    _vec_len (im->rx_buffers) += len;
    if (vec_len (im->rx_buffers) < MTU_BUFFERS) {
      clib_warning ("failed to allocate buffers");
      return 0;
    }
  }

  /* Fill buffers from the end of the list to make it easier to resize. */
  struct iovec iov[MTU_BUFFERS];
  uint32_t bi[MTU_BUFFERS];
  for (uint32_t i = 0, j = vec_len (im->rx_buffers) - 1; i < MTU_BUFFERS; ++i, --j) {
    vlib_buffer_t * b;
    bi[i] = im->rx_buffers[j];
    b = vlib_get_buffer (vm, bi[i]);
    iov[i].iov_base = b->data;
    iov[i].iov_len = VLIB_BUFFER_DATA_SIZE;
  }

  ssize_t n_bytes = readv (fd, iov, MTU_BUFFERS);
  if (n_bytes < 0) {
    clib_warning ("readv failed");
    return 0;
  }

  vlib_buffer_t * b = vlib_get_buffer (vm, bi[0]);
  vnet_buffer (b)->sw_if_index[VLIB_RX] = sw_if_index;
  vnet_buffer (b)->sw_if_index[VLIB_TX] = sw_if_index;
  ssize_t n_bytes_left = n_bytes - VLIB_BUFFER_DATA_SIZE;
  if (n_bytes_left > 0) {
    b->total_length_not_including_first_buffer = n_bytes_left;
    b->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
  }

  uint32_t i;
  b->current_length = n_bytes;
  for (i = 1; n_bytes_left > 0; ++i, n_bytes_left -= VLIB_BUFFER_DATA_SIZE) {
    vlib_buffer_t * b = vlib_get_buffer (vm, bi[i - 1]);
    b->current_length = VLIB_BUFFER_DATA_SIZE;
    b->flags |= VLIB_BUFFER_NEXT_PRESENT;
    b->next_buffer = bi[i];
    b = vlib_get_buffer (vm, bi[i]);
    b->current_length = n_bytes_left;
  }

  _vec_len (im->rx_buffers) -= i;
  /* Get the packet to the output node. */
  {
    vnet_hw_interface_t * hw;
    vlib_frame_t * new_frame;
    uint32_t * to_next;

    hw = vnet_get_hw_interface (vnet_get_main (), sw_if_index);
    new_frame = vlib_get_frame_to_node (vm, hw->output_node_index);
    to_next = vlib_frame_vector_args (new_frame);
    to_next[0] = bi[0];
    new_frame->n_vectors = 1;
    vlib_put_frame_to_node (vm, hw->output_node_index, new_frame);
  }

  return 1;
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

VLIB_CLI_COMMAND (set_node_tap_mirror, static) = {
  .path = "set node <node-name> tap-mirror <tap-name> [del]",
  .short_help ="setting up tap-mirror for  cplane-netdev {id <if-id>} [name <name>]",
  .function = set_node_tap_mirror_fn,
};

VLIB_CLI_COMMAND (enable_tap_inject_cmd, static) = {
  .path = "enable tap-inject",
  .short_help ="enable tap-inject",
  .function = enable_disable_tap_inject_cmd_fn,
  .function_arg = 1,
};

VLIB_CLI_COMMAND (disable_tap_inject_cmd, static) = {
  .path = "disable tap-inject",
  .short_help ="disable tap-inject",
  .function = enable_disable_tap_inject_cmd_fn,
  .function_arg = 0,
};

VLIB_CLI_COMMAND (show_tap_inject_cmd, static) = {
  .path = "show tap-inject",
  .short_help = "show tap-inject",
  .function = show_tap_inject,
};

VLIB_REGISTER_NODE (tap_mirror_node) = {
  .function = tap_inject_tx,
  .name = "tap_mirror-tap-inject-tx",
  .vector_size = sizeof (uint32_t),
  .type = VLIB_NODE_TYPE_INTERNAL,
};

