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

tap_mirror_main_t *
tap_mirror_get_main(void)
{
  static tap_mirror_main_t tap_mirror_main;
  return &tap_mirror_main;
}

int
tap_mirror_is_enabled (void)
{
  tap_mirror_main_t *xm = tap_mirror_get_main();
  return !!(xm->flags & TAP_MIRROR_F_ENABLED);
}

void
disable_tap_mirror(vlib_main_t *vm,
  const char *node_name, const char *tap_name)
{
  tap_mirror_main_t *xm = tap_mirror_get_main();
  if (xm->tap_fd > 0) {
    close(xm->tap_fd);
    xm->tap_fd = -1;
  }
  xm->node_name[0] = '\0';
  xm->tap_name[0] = '\0';
  xm->flags &= ~TAP_MIRROR_F_ENABLED;
  xm->target_rt->function = xm->target_fn;
}

static int
open_tap_fd(const char *name)
{
  int fd = open("/dev/net/tun", O_RDWR|O_NONBLOCK);
  if (fd < 0) {
    //"%s: failed. open tap-fd\n"
    return -1;
  }

  struct ifreq ifr;
  memset (&ifr, 0, sizeof (ifr));
  ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
  snprintf (ifr.ifr_name, IFNAMSIZ, "%s", name);
  int ret = ioctl (fd, TUNSETIFF, (void *) &ifr);
  if (ret < 0) {
    //"%s: ioctl(TUNSETIFF) failed.\n"
    close (fd);
    return -2;
  }

  return fd;
}

static int
set_link_up_down(const char *name, bool is_up)
{
  int fd = socket (AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    //"%s: socket failed.\n"
    return -1;
  }

  struct ifreq ifr;
  memset (&ifr, 0, sizeof (ifr));
  strncpy (ifr.ifr_name, name, IFNAMSIZ - 1);
  int ret = ioctl (fd, SIOCGIFFLAGS, &ifr);
  if (ret < 0) {
    //"%s: ioctl(SIOCGIFFLAGS) failed.\n"
    close (fd);
    return -2;
  }

  if (is_up) ifr.ifr_flags |= IFF_UP;
  else ifr.ifr_flags &= ~IFF_UP;
  ret = ioctl (fd, SIOCSIFFLAGS, &ifr);
  if (ret < 0) {
    //"%s: ioctl(SIOCSIFFLAGS) failed.\n"
    close (fd);
    return -3;
  }

  close (fd);
  return 0;
}

static clib_error_t *
tap_mirror_init (vlib_main_t *vm)
{
  printf("SLANKDEV: %s\n", __func__);
  tap_mirror_main_t * mmp = tap_mirror_get_main();
  mmp->vlib_main = vm;
  mmp->vnet_main = vnet_get_main();
  mmp->tap_fd = -1;
  vec_validate(mmp->clones, vlib_num_workers());

  uint8_t * name = format (0, "tap_mirror_%08x%c", api_version, 0);
  mmp->msg_id_base = vl_msg_api_get_msg_ids
      ((char *) name, VL_MSG_FIRST_AVAILABLE);
  vec_free(name);
  return NULL;
}

static uint64_t
tap_mirror_input_fn (vlib_main_t * vm,
    vlib_node_runtime_t * node, vlib_frame_t * f)
{
  tap_mirror_main_t *xm = tap_mirror_get_main();
  uint32_t *pkts = vlib_frame_vector_args (f);
  for (uint32_t i = 0; i < f->n_vectors; ++i) {
    uint32_t thread_index = vlib_get_thread_index();
    vec_validate (xm->clones[thread_index], 1);
    uint32_t n_cloned = vlib_buffer_clone (vm, pkts[i],
		 xm->clones[thread_index], 2,
                 VLIB_BUFFER_CLONE_HEAD_SIZE);
    assert(n_cloned == 2);

    vlib_buffer_t *b = vlib_get_buffer (vm, xm->clones[thread_index][1]);
    vlib_buffer_advance (b, -b->current_data);
    if (true /* debug*/) {
      uint8_t *ptr = vlib_buffer_get_current(b);
      size_t len = vlib_buffer_length_in_chain(vm, b);
      int ret = write(xm->tap_fd, ptr, len);
      if (ret < 0)
        printf("%s: tapmirror write failed (ret=%d)\n", __func__, ret);
    }

    vlib_buffer_free (vm, &xm->clones[thread_index][1], 1);
  }
  return xm->target_fn(vm, node, f);
}

int
enable_tap_mirror(vlib_main_t *vm,
  const char *node_name, const char *tap_name)
{
  if (tap_mirror_is_enabled()) {
    vlib_cli_output (vm, "%s: failed. already enabled\n", __func__);
    return -1;
  }

  tap_mirror_main_t *xm = tap_mirror_get_main();
  snprintf(xm->node_name, sizeof(xm->node_name), "%s", node_name);
  snprintf(xm->tap_name, sizeof(xm->tap_name), "%s", tap_name);

  uint8_t *str_ptr = format(0, "%s", node_name);
  vlib_node_t *node = vlib_get_node_by_name(vlib_get_main(), str_ptr);
  vlib_node_runtime_t *runtime = node ?
       vlib_node_get_runtime(vm, node->index) : NULL;
  if (!runtime) {
    vlib_cli_output (vm,
      "%s: failed. no such node or runtime (%s)\n",
      __func__, node_name);
    return -2;
  }

  assert(xm->tap_fd <= 0);
  xm->tap_fd = open_tap_fd(tap_name);
  set_link_up_down(tap_name, true);

  xm->flags |= TAP_MIRROR_F_ENABLED;
  xm->target_rt = runtime;
  xm->target_fn = runtime->function;
  runtime->function = tap_mirror_input_fn;
  return 0;
}

VLIB_INIT_FUNCTION (tap_mirror_init);

VNET_FEATURE_INIT (tap_mirror, static) =
{
  .arc_name = "device-input",
  .node_name = "tap-mirror",
  .runs_after = VNET_FEATURES ("ethernet-input"),
};

static uint64_t
test_proc_fn (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  for (int i=0;; i++) {
    //vlib_process_wait_for_event (vm);
    //data = vlib_process_get_event_data (vm, &type);
    //vlib_process_put_event_data (vm, data);
    vlib_cli_output (vm, "slank: %d", i);
    vlib_process_suspend (vm, 1e0 /* secs */ );
  }
  return 0;
}

VLIB_REGISTER_NODE (test_proc, static) = {
  .function = test_proc_fn,
  .name = "my-proc",
  .type = VLIB_NODE_TYPE_PROCESS,
};

VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "tap_mirror plugin for operational debug",
};

VLIB_CLI_COMMAND (set_node_tap_mirror, static) = {
  .path = "set tap-mirror",
  .short_help = "set tap-mirror {node <node-name>} {tap <tap-name>} [reset]",
  .function = set_tap_mirror_fn,
};

VLIB_CLI_COMMAND (show_tap_inject_cmd, static) = {
  .path = "show tap-mirror",
  .short_help = "show tap-mirror",
  .function = show_tap_mirror_fn,
};

