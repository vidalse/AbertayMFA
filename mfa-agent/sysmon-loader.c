#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define PIN_BASE "/sys/fs/bpf/sysmon"

// Tracepoint attachment info: program name to category/event
struct tp_attach {
    const char *prog_name;
    const char *tp_category;
    const char *tp_name;
};

static const struct tp_attach tracepoints[] = {
    { "sysmon_execve",  "syscalls", "sys_enter_execve"  },
    { "sysmon_ptrace",  "syscalls", "sys_enter_ptrace"  },
    { "sysmon_mount",   "syscalls", "sys_enter_mount"   },
    { "sysmon_socket",  "syscalls", "sys_enter_socket"  },
    { "sysmon_openat",  "syscalls", "sys_enter_openat"  },
    { "sysmon_connect", "syscalls", "sys_enter_connect" },
};

#define NUM_TRACEPOINTS (sizeof(tracepoints) / sizeof(tracepoints[0]))

// Map names to pin
static const char *map_names[] = {
    "sysmon_stats",
    "sysmon_events",
    "sysmon_event_idx",
};

#define NUM_MAPS (sizeof(map_names) / sizeof(map_names[0]))

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <bpf-sysmon.o>\n", argv[0]);
        return 1;
    }
    const char *obj_path = argv[1];
    struct bpf_object *obj = NULL;
    struct bpf_program *prog;
    struct bpf_link *link;
    int err;
    // Create pin directory
    mkdir(PIN_BASE, 0700);
    // Suppress libbpf debug output
    //libbpf_set_print(NULL);
    // Open BPF object
    obj = bpf_object__open(obj_path);
    if (!obj) {
        fprintf(stderr, "Failed to open %s: %s\n", obj_path, strerror(errno));
        return 1;
    }
    // Load into kernel
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %s\n", strerror(-err));
        bpf_object__close(obj);
        return 1;
    }

    fprintf(stderr, "Loaded %s\n", obj_path);
    // Attach each tracepoint program
    int attached = 0;
    for (int i = 0; i < (int)NUM_TRACEPOINTS; i++) {
        prog = bpf_object__find_program_by_name(obj, tracepoints[i].prog_name);
        if (!prog) {
            fprintf(stderr, "  Program '%s' not found, skipping\n",
                tracepoints[i].prog_name);
            continue;
        }
        link = bpf_program__attach_tracepoint(prog,
            tracepoints[i].tp_category, tracepoints[i].tp_name);
        if (!link) {
            fprintf(stderr, "  Failed to attach %s to %s/%s: %s\n",
                tracepoints[i].prog_name,
                tracepoints[i].tp_category,
                tracepoints[i].tp_name,
                strerror(errno));
            continue;
        }
        // Pin the link so it persists after this process exits
        char link_path[256];
        snprintf(link_path, sizeof(link_path), "%s/link_%s",
            PIN_BASE, tracepoints[i].prog_name);
        err = bpf_link__pin(link, link_path);
        if (err) {
            fprintf(stderr, "  Failed to pin link %s: %s\n",
                link_path, strerror(-err));
            bpf_link__destroy(link);
            continue;
        }
        fprintf(stderr, "  Attached %s → %s/%s (pinned)\n",
            tracepoints[i].prog_name,
            tracepoints[i].tp_category,
            tracepoints[i].tp_name);
        attached++;
    }
    if (attached == 0) {
        fprintf(stderr, "No tracepoints attached, aborting\n");
        bpf_object__close(obj);
        return 1;
    }
    // Pin maps so agent can read them
    int maps_pinned = 0;
    for (int i = 0; i < (int)NUM_MAPS; i++) {
        struct bpf_map *map = bpf_object__find_map_by_name(obj, map_names[i]);
        if (!map) {
            fprintf(stderr, "  Map '%s' not found\n", map_names[i]);
            continue;
        }
        char map_path[256];
        snprintf(map_path, sizeof(map_path), "%s/%s", PIN_BASE, map_names[i]);
        // Remove stale pin if exists (from previous run)
        unlink(map_path);
        err = bpf_map__pin(map, map_path);
        if (err) {
            fprintf(stderr, "  Failed to pin map %s: %s\n",
                map_path, strerror(-err));
            continue;
        }
        fprintf(stderr, "  Pinned %s → %s\n", map_names[i], map_path);
        maps_pinned++;
    }
    fprintf(stderr, "\nSysmon active: %d/%d hooks, %d/%d maps pinned\n",
        attached, (int)NUM_TRACEPOINTS, maps_pinned, (int)NUM_MAPS);
    // Close object, programs and maps persist via pins
    bpf_object__close(obj);
    return (attached > 0 && maps_pinned == (int)NUM_MAPS) ? 0 : 1;
}

