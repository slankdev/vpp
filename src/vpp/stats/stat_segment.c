/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vppinfra/mem.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include "stat_segment.h"
#include <vnet/vnet.h>
#include <vnet/devices/devices.h>	/* vnet_get_aggregate_rx_packets */
#undef HAVE_MEMFD_CREATE
#include <vppinfra/linux/syscall.h>
#include <vpp-api/client/stat_client.h>
#include <vppinfra/mheap.h>

stat_segment_main_t stat_segment_main;

/*
 *  Used only by VPP writers
 */
void
vlib_stat_segment_lock (void)
{
  stat_segment_main_t *sm = &stat_segment_main;
  clib_spinlock_lock (sm->stat_segment_lockp);
  sm->shared_header->in_progress = 1;
}

void
vlib_stat_segment_unlock (void)
{
  stat_segment_main_t *sm = &stat_segment_main;
  sm->shared_header->epoch++;
  sm->shared_header->in_progress = 0;
  clib_spinlock_unlock (sm->stat_segment_lockp);
}

/*
 * Change heap to the stats shared memory segment
 */
void *
vlib_stats_push_heap (void *old)
{
  stat_segment_main_t *sm = &stat_segment_main;

  sm->last = old;
  ASSERT (sm && sm->shared_header);
  return clib_mem_set_heap (sm->heap);
}

static u32
lookup_or_create_hash_index (u8 * name, u32 next_vector_index)
{
  stat_segment_main_t *sm = &stat_segment_main;
  u32 index;
  hash_pair_t *hp;

  /* Must be called in the context of the main heap */
  ASSERT (clib_mem_get_heap () != sm->heap);

  hp = hash_get_pair (sm->directory_vector_by_name, name);
  if (!hp)
    {
      /* we allocate our private copy of 'name' */
      hash_set (sm->directory_vector_by_name, format (0, "%s%c", name, 0),
		next_vector_index);
      index = next_vector_index;
    }
  else
    {
      index = hp->value[0];
    }

  return index;
}

void
vlib_stats_pop_heap (void *cm_arg, void *oldheap, u32 cindex,
		     stat_directory_type_t type)
{
  vlib_simple_counter_main_t *cm = (vlib_simple_counter_main_t *) cm_arg;
  stat_segment_main_t *sm = &stat_segment_main;
  stat_segment_shared_header_t *shared_header = sm->shared_header;
  char *stat_segment_name;
  stat_segment_directory_entry_t e = { 0 };

  /* Not all counters have names / hash-table entries */
  if (!cm->name && !cm->stat_segment_name)
    {
      clib_mem_set_heap (oldheap);
      return;
    }

  ASSERT (shared_header);

  vlib_stat_segment_lock ();

  /* Lookup hash-table is on the main heap */
  stat_segment_name =
    cm->stat_segment_name ? cm->stat_segment_name : cm->name;
  u32 next_vector_index = vec_len (sm->directory_vector);
  clib_mem_set_heap (oldheap);	/* Exit stats segment */
  u32 vector_index = lookup_or_create_hash_index ((u8 *) stat_segment_name,
						  next_vector_index);
  /* Back to stats segment */
  clib_mem_set_heap (sm->heap);	/* Re-enter stat segment */


  /* Update the vector */
  if (vector_index == next_vector_index)
    {				/* New */
      strncpy (e.name, stat_segment_name, 128 - 1);
      e.type = type;
      vec_add1 (sm->directory_vector, e);
    }

  stat_segment_directory_entry_t *ep = &sm->directory_vector[vector_index];
  ep->offset = stat_segment_offset (shared_header, cm->counters);	/* Vector of threads of vectors of counters */
  u64 *offset_vector =
    ep->offset_vector ? stat_segment_pointer (shared_header,
					      ep->offset_vector) : 0;

  /* Update the 2nd dimension offset vector */
  int i;
  vec_validate (offset_vector, vec_len (cm->counters) - 1);

  if (sm->last != offset_vector)
    {
      for (i = 0; i < vec_len (cm->counters); i++)
	offset_vector[i] =
	  stat_segment_offset (shared_header, cm->counters[i]);
    }
  else
    offset_vector[cindex] =
      stat_segment_offset (shared_header, cm->counters[cindex]);

  ep->offset_vector = stat_segment_offset (shared_header, offset_vector);
  sm->directory_vector[vector_index].offset =
    stat_segment_offset (shared_header, cm->counters);

  /* Reset the client hash table pointer, since it WILL change! */
  shared_header->directory_offset =
    stat_segment_offset (shared_header, sm->directory_vector);

  vlib_stat_segment_unlock ();
  clib_mem_set_heap (oldheap);
}

void
vlib_stats_register_error_index (void *oldheap, u8 * name, u64 * em_vec,
				 u64 index)
{
  stat_segment_main_t *sm = &stat_segment_main;
  stat_segment_shared_header_t *shared_header = sm->shared_header;
  stat_segment_directory_entry_t e;

  ASSERT (shared_header);

  vlib_stat_segment_lock ();
  u32 next_vector_index = vec_len (sm->directory_vector);
  clib_mem_set_heap (oldheap);	/* Exit stats segment */

  u32 vector_index = lookup_or_create_hash_index (name,
						  next_vector_index);

  /* Back to stats segment */
  clib_mem_set_heap (sm->heap);	/* Re-enter stat segment */

  if (next_vector_index == vector_index)
    {
      memcpy (e.name, name, vec_len (name));
      e.name[vec_len (name)] = '\0';
      e.type = STAT_DIR_TYPE_ERROR_INDEX;
      e.offset = index;
      e.offset_vector = 0;
      vec_add1 (sm->directory_vector, e);

      /* Warn clients to refresh any pointers they might be holding */
      shared_header->directory_offset =
	stat_segment_offset (shared_header, sm->directory_vector);
    }

  vlib_stat_segment_unlock ();
}

static void
stat_validate_counter_vector (stat_segment_directory_entry_t * ep, u32 max)
{
  stat_segment_main_t *sm = &stat_segment_main;
  stat_segment_shared_header_t *shared_header = sm->shared_header;
  counter_t **counters = 0;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  int i;
  u64 *offset_vector = 0;

  vec_validate_aligned (counters, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);
  for (i = 0; i < tm->n_vlib_mains; i++)
    {
      vec_validate_aligned (counters[i], max, CLIB_CACHE_LINE_BYTES);
      vec_add1 (offset_vector,
		stat_segment_offset (shared_header, counters[i]));
    }
  ep->offset = stat_segment_offset (shared_header, counters);
  ep->offset_vector = stat_segment_offset (shared_header, offset_vector);
}

void
vlib_stats_pop_heap2 (u64 * error_vector, u32 thread_index, void *oldheap,
		      int lock)
{
  stat_segment_main_t *sm = &stat_segment_main;
  stat_segment_shared_header_t *shared_header = sm->shared_header;

  ASSERT (shared_header);

  if (lock)
    vlib_stat_segment_lock ();

  /* Reset the client hash table pointer, since it WILL change! */
  vec_validate (sm->error_vector, thread_index);
  sm->error_vector[thread_index] =
    stat_segment_offset (shared_header, error_vector);

  shared_header->error_offset =
    stat_segment_offset (shared_header, sm->error_vector);
  shared_header->directory_offset =
    stat_segment_offset (shared_header, sm->directory_vector);

  if (lock)
    vlib_stat_segment_unlock ();
  clib_mem_set_heap (oldheap);
}

clib_error_t *
vlib_map_stat_segment_init (void)
{
  stat_segment_main_t *sm = &stat_segment_main;
  stat_segment_shared_header_t *shared_header;
  void *oldheap;
  ssize_t memory_size;
  int mfd;
  char *mem_name = "stat_segment_test";
  void *memaddr;

  memory_size = sm->memory_size;
  if (memory_size == 0)
    memory_size = STAT_SEGMENT_DEFAULT_SIZE;

  /* Create shared memory segment */
  if ((mfd = memfd_create (mem_name, 0)) < 0)
    return clib_error_return (0, "stat segment memfd_create failure");

  /* Set size */
  if ((ftruncate (mfd, memory_size)) == -1)
    return clib_error_return (0, "stat segment ftruncate failure");

  if ((memaddr =
       mmap (NULL, memory_size, PROT_READ | PROT_WRITE, MAP_SHARED, mfd,
	     0)) == MAP_FAILED)
    return clib_error_return (0, "stat segment mmap failure");

  void *heap;
#if USE_DLMALLOC == 0
  heap = mheap_alloc_with_flags (((u8 *) memaddr) + getpagesize (),
				 memory_size - getpagesize (),
				 MHEAP_FLAG_DISABLE_VM |
				 MHEAP_FLAG_THREAD_SAFE);
#else
  heap =
    create_mspace_with_base (((u8 *) memaddr) + getpagesize (),
			     memory_size - getpagesize (), 1 /* locked */ );
  mspace_disable_expand (heap);
#endif

  sm->heap = heap;
  sm->memfd = mfd;

  sm->directory_vector_by_name = hash_create_string (0, sizeof (uword));
  sm->shared_header = shared_header = memaddr;

  shared_header->version = STAT_SEGMENT_VERSION;

  sm->stat_segment_lockp = clib_mem_alloc (sizeof (clib_spinlock_t));
  clib_spinlock_init (sm->stat_segment_lockp);

  oldheap = clib_mem_set_heap (sm->heap);

  /* Set up the name to counter-vector hash table */
  sm->directory_vector = 0;

  shared_header->epoch = 1;

  /* Scalar stats and node counters */
  vec_validate (sm->directory_vector, STAT_COUNTERS - 1);
#define _(E,t,n,p)							\
  strcpy(sm->directory_vector[STAT_COUNTER_##E].name,  #p "/" #n); \
  sm->directory_vector[STAT_COUNTER_##E].type = STAT_DIR_TYPE_##t;
  foreach_stat_segment_counter_name
#undef _
    /* Save the vector offset in the shared segment, for clients */
    shared_header->directory_offset =
    stat_segment_offset (shared_header, sm->directory_vector);

  clib_mem_set_heap (oldheap);

  /* Total shared memory size */
  clib_mem_usage_t usage;
  mheap_usage (sm->heap, &usage);
  sm->directory_vector[STAT_COUNTER_MEM_STATSEG_TOTAL].value =
    usage.bytes_total;

  return 0;
}

static int
name_sort_cmp (void *a1, void *a2)
{
  stat_segment_directory_entry_t *n1 = a1;
  stat_segment_directory_entry_t *n2 = a2;

  return strcmp ((char *) n1->name, (char *) n2->name);
}

static u8 *
format_stat_dir_entry (u8 * s, va_list * args)
{
  stat_segment_directory_entry_t *ep =
    va_arg (*args, stat_segment_directory_entry_t *);
  char *type_name;
  char *format_string;

  format_string = "%-74s %-10s %10lld";

  switch (ep->type)
    {
    case STAT_DIR_TYPE_SCALAR_INDEX:
      type_name = "ScalarPtr";
      break;

    case STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE:
    case STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED:
      type_name = "CMainPtr";
      break;

    case STAT_DIR_TYPE_ERROR_INDEX:
      type_name = "ErrIndex";
      break;

    default:
      type_name = "illegal!";
      break;
    }

  return format (s, format_string, ep->name, type_name, ep->offset);
}

static clib_error_t *
show_stat_segment_command_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  stat_segment_main_t *sm = &stat_segment_main;
  stat_segment_directory_entry_t *show_data;
  int i;

  int verbose = 0;

  if (unformat (input, "verbose"))
    verbose = 1;

  /* Lock even as reader, as this command doesn't handle epoch changes */
  vlib_stat_segment_lock ();
  show_data = vec_dup (sm->directory_vector);
  vlib_stat_segment_unlock ();

  vec_sort_with_function (show_data, name_sort_cmp);

  vlib_cli_output (vm, "%-74s %10s %10s", "Name", "Type", "Value");

  for (i = 0; i < vec_len (show_data); i++)
    {
      vlib_cli_output (vm, "%-100U", format_stat_dir_entry,
		       vec_elt_at_index (show_data, i));
    }

  if (verbose)
    {
      ASSERT (sm->heap);
      vlib_cli_output (vm, "%U", format_mheap, sm->heap, 0 /* verbose */ );
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_stat_segment_command, static) =
{
  .path = "show statistics segment",
  .short_help = "show statistics segment [verbose]",
  .function = show_stat_segment_command_fn,
};
/* *INDENT-ON* */

/*
 * Node performance counters:
 * total_calls [threads][node-index]
 * total_vectors
 * total_calls
 * total suspends
 */

static inline void
update_node_counters (stat_segment_main_t * sm)
{
  vlib_main_t **stat_vms = 0;
  vlib_node_t ***node_dups = 0;
  int i, j;
  stat_segment_shared_header_t *shared_header = sm->shared_header;
  static u32 no_max_nodes = 0;

  vlib_node_get_nodes (0 /* vm, for barrier sync */ ,
		       (u32) ~ 0 /* all threads */ ,
		       1 /* include stats */ ,
		       0 /* barrier sync */ ,
		       &node_dups, &stat_vms);

  u32 l = vec_len (node_dups[0]);

  /*
   * Extend performance nodes if necessary
   */
  if (l > no_max_nodes)
    {
      void *oldheap = clib_mem_set_heap (sm->heap);
      vlib_stat_segment_lock ();

      stat_validate_counter_vector (&sm->directory_vector
				    [STAT_COUNTER_NODE_CLOCKS], l - 1);
      stat_validate_counter_vector (&sm->directory_vector
				    [STAT_COUNTER_NODE_VECTORS], l - 1);
      stat_validate_counter_vector (&sm->directory_vector
				    [STAT_COUNTER_NODE_CALLS], l - 1);
      stat_validate_counter_vector (&sm->directory_vector
				    [STAT_COUNTER_NODE_SUSPENDS], l - 1);

      vec_validate (sm->nodes, l - 1);
      stat_segment_directory_entry_t *ep;
      ep = &sm->directory_vector[STAT_COUNTER_NODE_NAMES];
      ep->offset = stat_segment_offset (shared_header, sm->nodes);

      int i;
      u64 *offset_vector =
	ep->offset_vector ? stat_segment_pointer (shared_header,
						  ep->offset_vector) : 0;
      /* Update names dictionary */
      vec_validate (offset_vector, l - 1);
      vlib_node_t **nodes = node_dups[0];

      for (i = 0; i < vec_len (nodes); i++)
	{
	  vlib_node_t *n = nodes[i];
	  u8 *s = 0;
	  s = format (s, "%v%c", n->name, 0);
	  if (sm->nodes[n->index])
	    vec_free (sm->nodes[n->index]);
	  sm->nodes[n->index] = s;
	  offset_vector[i] =
	    sm->nodes[i] ? stat_segment_offset (shared_header,
						sm->nodes[i]) : 0;

	}
      ep->offset_vector = stat_segment_offset (shared_header, offset_vector);

      vlib_stat_segment_unlock ();
      clib_mem_set_heap (oldheap);
      no_max_nodes = l;
    }

  for (j = 0; j < vec_len (node_dups); j++)
    {
      vlib_node_t **nodes = node_dups[j];

      for (i = 0; i < vec_len (nodes); i++)
	{
	  counter_t **counters;
	  counter_t *c;
	  vlib_node_t *n = nodes[i];

	  counters =
	    stat_segment_pointer (shared_header,
				  sm->directory_vector
				  [STAT_COUNTER_NODE_CLOCKS].offset);
	  c = counters[j];
	  c[n->index] = n->stats_total.clocks - n->stats_last_clear.clocks;

	  counters =
	    stat_segment_pointer (shared_header,
				  sm->directory_vector
				  [STAT_COUNTER_NODE_VECTORS].offset);
	  c = counters[j];
	  c[n->index] = n->stats_total.vectors - n->stats_last_clear.vectors;

	  counters =
	    stat_segment_pointer (shared_header,
				  sm->directory_vector
				  [STAT_COUNTER_NODE_CALLS].offset);
	  c = counters[j];
	  c[n->index] = n->stats_total.calls - n->stats_last_clear.calls;

	  counters =
	    stat_segment_pointer (shared_header,
				  sm->directory_vector
				  [STAT_COUNTER_NODE_SUSPENDS].offset);
	  c = counters[j];
	  c[n->index] =
	    n->stats_total.suspends - n->stats_last_clear.suspends;
	}
    }
}

static void
do_stat_segment_updates (stat_segment_main_t * sm)
{
  stat_segment_shared_header_t *shared_header = sm->shared_header;
  vlib_main_t *vm = vlib_mains[0];
  f64 vector_rate;
  u64 input_packets;
  f64 dt, now;
  vlib_main_t *this_vlib_main;
  int i, start;
  counter_t **counters;
  static int num_worker_threads_set;

  /*
   * Set once at the beginning of time.
   * Can't do this from the init routine, which happens before
   * start_workers sets up vlib_mains...
   */
  if (PREDICT_FALSE (num_worker_threads_set == 0))
    {
      sm->directory_vector[STAT_COUNTER_NUM_WORKER_THREADS].value =
	vec_len (vlib_mains) > 1 ? vec_len (vlib_mains) - 1 : 1;

      stat_validate_counter_vector (&sm->directory_vector
				    [STAT_COUNTER_VECTOR_RATE_PER_WORKER],
				    vec_len (vlib_mains));
      num_worker_threads_set = 1;
    }

  /*
   * Compute per-worker vector rates, and the average vector rate
   * across all workers
   */
  vector_rate = 0.0;

  counters =
    stat_segment_pointer (shared_header,
			  sm->directory_vector
			  [STAT_COUNTER_VECTOR_RATE_PER_WORKER].offset);

  start = vec_len (vlib_mains) > 1 ? 1 : 0;

  for (i = start; i < vec_len (vlib_mains); i++)
    {

      f64 this_vector_rate;

      this_vlib_main = vlib_mains[i];

      this_vector_rate = vlib_last_vector_length_per_node (this_vlib_main);
      vector_rate += this_vector_rate;

      /* Set the per-worker rate */
      counters[i - start][0] = this_vector_rate;
    }

  /* And set the system average rate */
  vector_rate /= (f64) (i - start);

  sm->directory_vector[STAT_COUNTER_VECTOR_RATE].value = vector_rate;

  /*
   * Compute the aggregate input rate
   */
  now = vlib_time_now (vm);
  dt = now - sm->directory_vector[STAT_COUNTER_LAST_UPDATE].value;
  input_packets = vnet_get_aggregate_rx_packets ();
  sm->directory_vector[STAT_COUNTER_INPUT_RATE].value =
    (f64) (input_packets - sm->last_input_packets) / dt;
  sm->directory_vector[STAT_COUNTER_LAST_UPDATE].value = now;
  sm->last_input_packets = input_packets;
  sm->directory_vector[STAT_COUNTER_LAST_STATS_CLEAR].value =
    vm->node_main.time_last_runtime_stats_clear;

  /* Stats segment memory heap counter */
  clib_mem_usage_t usage;
  mheap_usage (sm->heap, &usage);
  sm->directory_vector[STAT_COUNTER_MEM_STATSEG_USED].value =
    usage.bytes_used;

  if (sm->node_counters_enabled)
    update_node_counters (sm);

  /* *INDENT-OFF* */
  stat_segment_gauges_pool_t *g;
  pool_foreach(g, sm->gauges,
  ({
    g->fn(&sm->directory_vector[g->directory_index], g->caller_index);
  }));
  /* *INDENT-ON* */

  /* Heartbeat, so clients detect we're still here */
  sm->directory_vector[STAT_COUNTER_HEARTBEAT].value++;
}

/*
 * Accept connection on the socket and exchange the fd for the shared
 * memory segment.
 */
static clib_error_t *
stats_socket_accept_ready (clib_file_t * uf)
{
  stat_segment_main_t *sm = &stat_segment_main;
  clib_error_t *err;
  clib_socket_t client = { 0 };

  err = clib_socket_accept (sm->socket, &client);
  if (err)
    {
      clib_error_report (err);
      return err;
    }

  /* Send the fd across and close */
  err = clib_socket_sendmsg (&client, 0, 0, &sm->memfd, 1);
  if (err)
    clib_error_report (err);
  clib_socket_close (&client);

  return 0;
}

static clib_error_t *
stats_segment_socket_init (void)
{
  stat_segment_main_t *sm = &stat_segment_main;
  clib_error_t *error;
  clib_socket_t *s = clib_mem_alloc (sizeof (clib_socket_t));

  memset (s, 0, sizeof (clib_socket_t));
  s->config = (char *) sm->socket_name;
  s->flags = CLIB_SOCKET_F_IS_SERVER | CLIB_SOCKET_F_SEQPACKET |
    CLIB_SOCKET_F_ALLOW_GROUP_WRITE | CLIB_SOCKET_F_PASSCRED;

  if ((error = clib_socket_init (s)))
    return error;

  clib_file_t template = { 0 };
  template.read_function = stats_socket_accept_ready;
  template.file_descriptor = s->fd;
  template.description = format (0, "stats segment listener %s", s->config);
  clib_file_add (&file_main, &template);

  sm->socket = s;

  return 0;
}

static clib_error_t *
stats_segment_socket_exit (vlib_main_t * vm)
{
  /*
   * cleanup the listener socket on exit.
   */
  stat_segment_main_t *sm = &stat_segment_main;
  unlink ((char *) sm->socket_name);
  return 0;
}

VLIB_MAIN_LOOP_EXIT_FUNCTION (stats_segment_socket_exit);

static uword
stat_segment_collector_process (vlib_main_t * vm, vlib_node_runtime_t * rt,
				vlib_frame_t * f)
{
  stat_segment_main_t *sm = &stat_segment_main;

  /* Wait for Godot... */
  f64 sleep_duration = 10;

  while (1)
    {
      do_stat_segment_updates (sm);
      vlib_process_suspend (vm, sleep_duration);
    }
  return 0;			/* or not */
}

clib_error_t *
stat_segment_register_gauge (u8 * name, stat_segment_update_fn update_fn,
			     u32 caller_index)
{
  stat_segment_main_t *sm = &stat_segment_main;
  stat_segment_shared_header_t *shared_header = sm->shared_header;
  void *oldheap;
  stat_segment_directory_entry_t e;
  stat_segment_gauges_pool_t *gauge;

  ASSERT (shared_header);

  u32 next_vector_index = vec_len (sm->directory_vector);
  u32 vector_index = lookup_or_create_hash_index (name,
						  next_vector_index);

  if (vector_index < next_vector_index)	/* Already registered */
    return clib_error_return (0, "%v is alreadty registered", name);

  oldheap = vlib_stats_push_heap (NULL);
  vlib_stat_segment_lock ();

  memset (&e, 0, sizeof (e));
  e.type = STAT_DIR_TYPE_SCALAR_INDEX;

  memcpy (e.name, name, vec_len (name));
  vec_add1 (sm->directory_vector, e);

  shared_header->directory_offset =
    stat_segment_offset (shared_header, sm->directory_vector);

  vlib_stat_segment_unlock ();
  clib_mem_set_heap (oldheap);

  /* Back on our own heap */
  pool_get (sm->gauges, gauge);
  gauge->fn = update_fn;
  gauge->caller_index = caller_index;
  gauge->directory_index = next_vector_index;

  return NULL;
}

static clib_error_t *
statseg_config (vlib_main_t * vm, unformat_input_t * input)
{
  stat_segment_main_t *sm = &stat_segment_main;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "socket-name %s", &sm->socket_name))
	;
      /* DEPRECATE: default (does nothing) */
      else if (unformat (input, "default"))
	;
      else if (unformat (input, "size %U",
			 unformat_memory_size, &sm->memory_size))
	;
      else if (unformat (input, "per-node-counters on"))
	sm->node_counters_enabled = 1;
      else if (unformat (input, "per-node-counters off"))
	sm->node_counters_enabled = 0;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  /* set default socket file name when statseg config stanza is empty. */
  if (!vec_len (sm->socket_name))
    sm->socket_name = format (0, "%s/%s", vlib_unix_get_runtime_dir (),
			      STAT_SEGMENT_SOCKET_FILENAME);

  /*
   * NULL-terminate socket name string
   * clib_socket_init()->socket_config() use C str*
   */
  vec_terminate_c_string (sm->socket_name);

  return stats_segment_socket_init ();
}

static clib_error_t *
statseg_sw_interface_add_del (vnet_main_t * vnm, u32 sw_if_index, u32 is_add)
{
  stat_segment_main_t *sm = &stat_segment_main;
  stat_segment_shared_header_t *shared_header = sm->shared_header;

  void *oldheap = vlib_stats_push_heap (sm->interfaces);
  vlib_stat_segment_lock ();

  vec_validate (sm->interfaces, sw_if_index);
  if (is_add)
    {
      vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, sw_if_index);
      vnet_sw_interface_t *si_sup =
	vnet_get_sup_sw_interface (vnm, si->sw_if_index);
      vnet_hw_interface_t *hi_sup;

      ASSERT (si_sup->type == VNET_SW_INTERFACE_TYPE_HARDWARE);
      hi_sup = vnet_get_hw_interface (vnm, si_sup->hw_if_index);

      u8 *s = 0;
      s = format (s, "%v", hi_sup->name);
      if (si->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
	s = format (s, ".%d", si->sub.id);
      s = format (s, "%c", 0);
      sm->interfaces[sw_if_index] = s;
    }
  else
    {
      vec_free (sm->interfaces[sw_if_index]);
      sm->interfaces[sw_if_index] = 0;
    }

  stat_segment_directory_entry_t *ep;
  ep = &sm->directory_vector[STAT_COUNTER_INTERFACE_NAMES];
  ep->offset = stat_segment_offset (shared_header, sm->interfaces);

  int i;
  u64 *offset_vector =
    ep->offset_vector ? stat_segment_pointer (shared_header,
					      ep->offset_vector) : 0;

  vec_validate (offset_vector, vec_len (sm->interfaces) - 1);

  if (sm->last != sm->interfaces)
    {
      /* the interface vector moved, so need to recalulate the offset array */
      for (i = 0; i < vec_len (sm->interfaces); i++)
	{
	  offset_vector[i] =
	    sm->interfaces[i] ? stat_segment_offset (shared_header,
						     sm->interfaces[i]) : 0;
	}
    }
  else
    {
      offset_vector[sw_if_index] =
	sm->interfaces[sw_if_index] ?
	stat_segment_offset (shared_header, sm->interfaces[sw_if_index]) : 0;
    }
  ep->offset_vector = stat_segment_offset (shared_header, offset_vector);

  vlib_stat_segment_unlock ();
  clib_mem_set_heap (oldheap);

  return 0;
}

VLIB_CONFIG_FUNCTION (statseg_config, "statseg");
VNET_SW_INTERFACE_ADD_DEL_FUNCTION (statseg_sw_interface_add_del);

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (stat_segment_collector, static) =
{
.function = stat_segment_collector_process,
.name = "statseg-collector-process",
.type = VLIB_NODE_TYPE_PROCESS,
};

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
