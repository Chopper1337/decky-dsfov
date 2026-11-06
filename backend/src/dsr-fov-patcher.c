#define _GNU_SOURCE

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static const uint8_t k_fov_signature[] = {
    0x8b, 0x42, 0x50, 0x4c, 0x8b, 0xc2, 0x89, 0x41, 0x50,
    0x48, 0x8b, 0xd9, 0x8b, 0x42, 0x54, 0x89, 0x41, 0x54,
};
static const uint8_t k_original_patch_bytes[] = {
    0x8b, 0x42, 0x50, 0x4c, 0x8b, 0xc2,
};

static const uintptr_t IMAGE_BASE = (uintptr_t)0x140000000ULL;

enum {
    PATCH_RVA = 0x235f06,
    PATCH_FILE_OFFSET = 0x235306,
    PATCH_LEN = 6,
    STUB_LEN  = 13, /* mov eax,imm32 + mov r8,rdx + jmp rel32 */
    HEADER_SIZE = 0x400,  /* SizeOfHeaders; the rest of the header page is zero padding */
    PAGE_SIZE_BYTES = 0x1000,
    WAIT_POLL_SECONDS = 1,
    WAIT_TIMEOUT_SECONDS = 300,
    /*
     * The game's protection layer rewrites its code during startup, and a
     * patch applied in the first second crashes the game. Patching after
     * the game process has run this long is known to work.
     */
    MIN_GAME_AGE_SECONDS = 45,
};

struct map_range {
    uintptr_t start;
    uintptr_t end;
    uint64_t offset;
    char perms[5];
    char path[512];
};

static void die(const char *msg) {
    perror(msg);
    exit(1);
}

static bool parse_pid(const char *s, pid_t *pid) {
    char *end = NULL;
    long v = strtol(s, &end, 10);
    if (!s[0] || *end || v <= 0)
        return false;
    *pid = (pid_t)v;
    return true;
}

static bool is_number(const char *s) {
    for (; *s; s++)
        if (!isdigit((unsigned char)*s))
            return false;
    return true;
}

/* The kernel truncates comm to 15 characters: "DarkSoulsRemastered.exe" becomes "DarkSoulsRemast". */
static const char k_game_comm[] = "DarkSoulsRemast";
static const char k_game_exe[] = "DarkSoulsRemastered.exe";

static bool comm_equals(const char *pid_dir, const char *expected) {
    char path[512];
    snprintf(path, sizeof(path), "/proc/%s/comm", pid_dir);
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return false;
    char buf[64];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0)
        return false;
    buf[n] = 0;
    buf[strcspn(buf, "\n")] = 0;
    return strcmp(buf, expected) == 0;
}

/* True if the process maps a file whose basename is exactly `exe`.
 * Launcher, Proton and Wine helper processes only mention the EXE in their
 * command line; only the game process itself maps it. */
static bool maps_module(const char *pid_dir, const char *exe) {
    char path[512];
    snprintf(path, sizeof(path), "/proc/%s/maps", pid_dir);
    FILE *fp = fopen(path, "r");
    if (!fp)
        return false;

    bool found = false;
    char line[4096 + 256];
    while (!found && fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = 0;
        const char *slash = strrchr(line, '/');
        found = slash && strcmp(slash + 1, exe) == 0;
    }
    fclose(fp);
    return found;
}

/* Returns the game's PID, or 0 if it is not running. Exits if several match. */
static pid_t find_process(void) {
    DIR *dir = opendir("/proc");
    if (!dir)
        die("opendir /proc");

    pid_t found = 0;
    struct dirent *ent;
    while ((ent = readdir(dir))) {
        if (!is_number(ent->d_name))
            continue;

        if (!comm_equals(ent->d_name, k_game_comm) ||
            !maps_module(ent->d_name, k_game_exe))
            continue;

        pid_t pid = (pid_t)strtol(ent->d_name, NULL, 10);
        if (found && found != pid) {
            fprintf(stderr, "Multiple matching processes found; pass --pid explicitly.\n");
            closedir(dir);
            exit(1);
        }
        found = pid;
    }

    closedir(dir);
    return found;
}

static int read_maps(pid_t pid, struct map_range **out_maps) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *fp = fopen(path, "r");
    if (!fp)
        return -1;

    int count = 0;
    int cap = 32;
    struct map_range *maps = calloc((size_t)cap, sizeof(*maps));
    if (!maps)
        die("calloc maps");

    char line[2048];
    while (fgets(line, sizeof(line), fp)) {
        if (count == cap) {
            cap *= 2;
            maps = realloc(maps, (size_t)cap * sizeof(*maps));
            if (!maps)
                die("realloc maps");
        }

        struct map_range *m = &maps[count];
        unsigned long long start = 0, end = 0, offset = 0;
        char dev[32] = {0};
        unsigned long inode = 0;
        int consumed = 0;
        int n = sscanf(line, "%llx-%llx %4s %llx %31s %lu %n",
                       &start, &end, m->perms, &offset, dev, &inode, &consumed);
        if (n < 6)
            continue;
        m->start = (uintptr_t)start;
        m->end   = (uintptr_t)end;
        m->offset = offset;
        m->path[0] = 0;
        if (line[consumed]) {
            char *p = line + consumed;
            while (*p == ' ') p++;
            p[strcspn(p, "\n")] = 0;
            snprintf(m->path, sizeof(m->path), "%s", p);
        }
        count++;
    }

    fclose(fp);
    *out_maps = maps;
    return count;
}

static bool read_mem(int memfd, uintptr_t addr, void *buf, size_t len) {
    return pread(memfd, buf, len, (off_t)addr) == (ssize_t)len;
}

static bool write_mem(int memfd, uintptr_t addr, const void *buf, size_t len) {
    return pwrite(memfd, buf, len, (off_t)addr) == (ssize_t)len;
}

static bool rel32(uintptr_t from_next, uintptr_t to, int32_t *out) {
    int64_t d = (int64_t)to - (int64_t)from_next;
    if (d < INT32_MIN || d > INT32_MAX)
        return false;
    *out = (int32_t)d;
    return true;
}

static uint32_t float_bits(float v) {
    uint32_t bits;
    memcpy(&bits, &v, sizeof(bits));
    return bits;
}

static bool read_stub_target(int memfd, uintptr_t patch_addr, uintptr_t *out_cave) {
    uint8_t current[PATCH_LEN];
    if (!read_mem(memfd, patch_addr, current, PATCH_LEN))
        return false;
    if (current[0] != 0xe9)
        return false;

    int32_t rel;
    memcpy(&rel, current + 1, 4);
    *out_cave = (uintptr_t)((int64_t)(patch_addr + 5) + rel);
    return true;
}

static bool validate_stub(int memfd, uintptr_t cave_addr, uintptr_t patch_addr) {
    uint8_t stub[STUB_LEN];
    if (!read_mem(memfd, cave_addr, stub, sizeof(stub)))
        return false;
    if (stub[0] != 0xb8 ||
        stub[5] != 0x4c || stub[6] != 0x8b || stub[7] != 0xc2 ||
        stub[8] != 0xe9)
        return false;

    int32_t back;
    memcpy(&back, stub + 9, 4);
    return (uintptr_t)((int64_t)(cave_addr + STUB_LEN) + back) ==
           patch_addr + PATCH_LEN;
}

/*
 * Scan all r-x mappings for the 18-byte FOV signature. Exits if more than
 * one unique match is found (ambiguous patch site).
 */
static uintptr_t find_signature(int memfd, const struct map_range *maps, int count) {
    uintptr_t found = 0;
    uint8_t *buf = NULL;
    size_t buf_cap = 0;

    for (int i = 0; i < count; i++) {
        const struct map_range *m = &maps[i];
        if (m->perms[0] != 'r' || m->perms[2] != 'x')
            continue;

        size_t size = (size_t)(m->end - m->start);
        if (size > 256 * 1024 * 1024)
            continue;
        if (size > buf_cap) {
            free(buf);
            buf = malloc(size);
            if (!buf)
                die("malloc map buffer");
            buf_cap = size;
        }
        if (!read_mem(memfd, m->start, buf, size))
            continue;

        const uint8_t *hit = buf;
        size_t left = size;
        while ((hit = memmem(hit, left, k_fov_signature, sizeof(k_fov_signature)))) {
            uintptr_t addr = m->start + (uintptr_t)(hit - buf);
            if (found && found != addr) {
                fprintf(stderr, "FOV signature is not unique; refusing to patch.\n");
                free(buf);
                exit(1);
            }
            found = addr;
            hit++;
            left = size - (size_t)(hit - buf);
        }
    }

    free(buf);
    return found;
}

static bool map_contains(const struct map_range *m, uintptr_t addr) {
    return addr >= m->start && addr < m->end;
}

static uintptr_t find_static_patch_addr(const struct map_range *maps, int count) {
    uintptr_t fixed = (uintptr_t)IMAGE_BASE + PATCH_RVA;

    for (int i = 0; i < count; i++) {
        if (map_contains(&maps[i], fixed))
            return fixed;
    }

    for (int i = 0; i < count; i++) {
        const struct map_range *m = &maps[i];
        if (!strstr(m->path, "DarkSoulsRemastered.exe"))
            continue;
        uint64_t size = (uint64_t)(m->end - m->start);
        if (m->offset <= PATCH_FILE_OFFSET &&
            PATCH_FILE_OFFSET < m->offset + size) {
            return m->start + (uintptr_t)(PATCH_FILE_OFFSET - m->offset);
        }
        if (m->offset <= PATCH_RVA &&
            PATCH_RVA < m->offset + size) {
            return m->start + (uintptr_t)(PATCH_RVA - m->offset);
        }
    }

    return 0;
}

static uintptr_t find_patch_addr(int memfd, const struct map_range *maps, int count) {
    uintptr_t patch_addr = find_signature(memfd, maps, count);
    if (patch_addr)
        return patch_addr;
    return find_static_patch_addr(maps, count);
}

/*
 * Scan r-x mappings for STUB_LEN consecutive zero bytes that are reachable
 * from patch_addr via a pair of rel32 jumps (±2 GB). The first qualifying
 * address is returned; 0 means no cave found.
 */
/*
 * Look for the stub location in the zero padding after the PE headers. The
 * game keeps rewriting .text at runtime, so zero runs there are not safe.
 */
static uintptr_t find_header_cave(int memfd, const struct map_range *maps, int count,
                                  uintptr_t patch_addr) {
    uintptr_t base = patch_addr - PATCH_RVA;
    uintptr_t start = base + HEADER_SIZE;
    uintptr_t end = base + PAGE_SIZE_BYTES;

    bool executable = false;
    for (int i = 0; i < count; i++) {
        if (maps[i].start <= start && end <= maps[i].end) {
            executable = maps[i].perms[0] == 'r' && maps[i].perms[2] == 'x';
            break;
        }
    }
    if (!executable)
        return 0;

    uint8_t buf[PAGE_SIZE_BYTES - HEADER_SIZE];
    if (!read_mem(memfd, start, buf, sizeof(buf)))
        return 0;

    static const uint8_t zeros[STUB_LEN] = {0};
    const uint8_t *hit = memmem(buf, sizeof(buf), zeros, sizeof(zeros));
    return hit ? start + (uintptr_t)(hit - buf) : 0;
}

static uintptr_t find_cave(int memfd, const struct map_range *maps, int count,
                           uintptr_t patch_addr) {
    uintptr_t header_cave = find_header_cave(memfd, maps, count, patch_addr);
    if (header_cave)
        return header_cave;

    uint8_t *buf = NULL;
    size_t buf_cap = 0;
    uintptr_t found = 0;

    for (int i = 0; i < count && !found; i++) {
        const struct map_range *m = &maps[i];
        if (m->perms[0] != 'r' || m->perms[2] != 'x')
            continue;

        size_t size = (size_t)(m->end - m->start);
        if (size > 256 * 1024 * 1024)
            continue;
        if (size > buf_cap) {
            free(buf);
            buf = malloc(size);
            if (!buf)
                die("malloc cave buffer");
            buf_cap = size;
        }
        if (!read_mem(memfd, m->start, buf, size))
            continue;

        for (size_t off = 0; off + STUB_LEN <= size && !found; off++) {
            /* Quick rejection: last byte must be zero before checking the rest. */
            if (buf[off + STUB_LEN - 1] != 0)
                continue;
            bool zeroed = true;
            for (int j = 0; j < STUB_LEN - 1; j++) {
                if (buf[off + j]) { zeroed = false; break; }
            }
            if (!zeroed)
                continue;

            uintptr_t addr = m->start + off;
            int32_t dummy;
            if (!rel32(patch_addr + 5, addr, &dummy))
                continue;
            if (!rel32(addr + STUB_LEN, patch_addr + PATCH_LEN, &dummy))
                continue;

            found = addr;
        }
    }

    free(buf);
    return found;
}

/*
 * True once the patch site holds either the original code or our jump.
 * Reads memory without attaching, so polling does not stop the game.
 */
static bool patch_site_ready(pid_t pid) {
    struct map_range *maps = NULL;
    int count = read_maps(pid, &maps);
    if (count < 0)
        return false;

    char mempath[64];
    snprintf(mempath, sizeof(mempath), "/proc/%d/mem", pid);
    int memfd = open(mempath, O_RDONLY);
    if (memfd < 0) {
        free(maps);
        return false;
    }

    bool ready = false;
    uintptr_t patch_addr = find_patch_addr(memfd, maps, count);
    uint8_t current[PATCH_LEN];
    if (patch_addr && read_mem(memfd, patch_addr, current, PATCH_LEN))
        ready = memcmp(current, k_original_patch_bytes, PATCH_LEN) == 0 ||
                current[0] == 0xe9;

    close(memfd);
    free(maps);
    return ready;
}

/* Seconds since the process started, or -1 if it is gone. */
static long process_age_seconds(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    FILE *fp = fopen(path, "r");
    if (!fp)
        return -1;
    char buf[1024];
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    buf[n] = 0;

    /* comm may contain spaces; fields after it start at the last ')'. */
    char *p = strrchr(buf, ')');
    if (!p)
        return -1;
    unsigned long long start_ticks = 0;
    if (sscanf(p + 2, "%*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %*u %*u %*d %*d %*d %*d %*d %*d %llu",
               &start_ticks) != 1)
        return -1;

    double uptime = 0;
    fp = fopen("/proc/uptime", "r");
    if (!fp)
        return -1;
    int ok = fscanf(fp, "%lf", &uptime);
    fclose(fp);
    if (ok != 1)
        return -1;

    long ticks = sysconf(_SC_CLK_TCK);
    long age = (long)(uptime - (double)start_ticks / (double)ticks);
    return age < 0 ? 0 : age;
}

static bool process_exists(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d", pid);
    return access(path, F_OK) == 0;
}

/*
 * Wait until the game is running, has run for MIN_GAME_AGE_SECONDS, and its
 * patch site is loaded. With pid 0 the game process is searched for;
 * otherwise that PID must stay alive. Time spent waiting for the game to age
 * does not count towards WAIT_TIMEOUT_SECONDS.
 */
static pid_t wait_for_patch_site(pid_t pid) {
    bool announced = false;
    pid_t announced_age = 0;
    int waited = 0;
    for (;;) {
        if (pid && !process_exists(pid)) {
            fprintf(stderr, "Process %d not found.\n", pid);
            exit(1);
        }
        pid_t target = pid ? pid : find_process();

        if (target) {
            long age = process_age_seconds(target);
            if (age >= 0 && age < MIN_GAME_AGE_SECONDS) {
                if (announced_age != target) {
                    printf("Found game (pid %d); patching in %ld s.\n",
                           target, MIN_GAME_AGE_SECONDS - age);
                    fflush(stdout);
                    announced_age = target;
                    announced = true;
                }
                sleep(WAIT_POLL_SECONDS);
                continue;
            }
            if (age >= 0 && patch_site_ready(target))
                return target;
        }

        if (waited >= WAIT_TIMEOUT_SECONDS) {
            if (target)
                fprintf(stderr, "Could not locate the FOV patch site in process memory.\n");
            else
                fprintf(stderr, "%s process not found.\n", k_game_exe);
            exit(1);
        }
        if (!announced) {
            printf("Waiting for Dark Souls Remastered... (Ctrl+C to cancel)\n");
            fflush(stdout);
            announced = true;
        }
        sleep(WAIT_POLL_SECONDS);
        waited += WAIT_POLL_SECONDS;
    }
}

static void attach_process(pid_t pid) {
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0)
        die("ptrace attach");
    int status = 0;
    if (waitpid(pid, &status, 0) < 0)
        die("waitpid");
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "Process did not stop after attach.\n");
        exit(1);
    }
}

static void detach_process(pid_t pid) {
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0)
        die("ptrace detach");
}

int main(int argc, char **argv) {
    float fov = 1.08f;
    pid_t pid = 0;
    bool restore = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--pid") == 0 && i + 1 < argc) {
            if (!parse_pid(argv[++i], &pid)) {
                fprintf(stderr, "Invalid pid.\n");
                return 2;
            }
        } else if (strcmp(argv[i], "--restore") == 0) {
            restore = true;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("usage: %s [--pid PID] [--restore] [fov]\n", argv[0]);
            printf("example: %s 1.13\n", argv[0]);
            printf("\nWaits up to %d s for the game to start, then patches it once the\n"
                   "game has run for %d s.\n", WAIT_TIMEOUT_SECONDS, MIN_GAME_AGE_SECONDS);
            printf("--restore does not wait.\n");
            return 0;
        } else {
            char *end = NULL;
            fov = strtof(argv[i], &end);
            if (!argv[i][0] || *end) {
                fprintf(stderr, "Invalid argument: %s\n", argv[i]);
                return 2;
            }
        }
    }

    if (restore) {
        if (!pid)
            pid = find_process();
        if (!pid) {
            fprintf(stderr, "%s process not found.\n", k_game_exe);
            return 1;
        }
    } else {
        pid = wait_for_patch_site(pid);
    }

    attach_process(pid);

    char mempath[64];
    snprintf(mempath, sizeof(mempath), "/proc/%d/mem", pid);
    int memfd = open(mempath, O_RDWR);
    if (memfd < 0) {
        int saved = errno;
        detach_process(pid);
        errno = saved;
        die("open mem");
    }

    struct map_range *maps = NULL;
    int map_count = read_maps(pid, &maps);
    if (map_count < 0) {
        close(memfd);
        detach_process(pid);
        die("read maps");
    }

    uintptr_t patch_addr = find_patch_addr(memfd, maps, map_count);
    if (!patch_addr) {
        fprintf(stderr, "Could not locate the FOV patch site in process memory.\n");
        close(memfd);
        free(maps);
        detach_process(pid);
        return 1;
    }

    if (restore) {
        /* Follow the jmp at the patch site to locate the stub dynamically. */
        uint8_t current[PATCH_LEN];
        if (!read_mem(memfd, patch_addr, current, PATCH_LEN)) {
            close(memfd);
            free(maps);
            detach_process(pid);
            die("read patch site");
        }

        if (memcmp(current, k_original_patch_bytes, PATCH_LEN) == 0) {
            printf("Patch is not applied; nothing to restore.\n");
            close(memfd);
            free(maps);
            detach_process(pid);
            return 0;
        }

        if (current[0] != 0xe9) {
            fprintf(stderr, "Unexpected bytes at patch site 0x%" PRIxPTR "; refusing to restore.\n",
                    patch_addr);
            close(memfd);
            free(maps);
            detach_process(pid);
            return 1;
        }

        uintptr_t cave_addr = 0;
        if (!read_stub_target(memfd, patch_addr, &cave_addr) ||
            !validate_stub(memfd, cave_addr, patch_addr)) {
            fprintf(stderr, "Stub at 0x%" PRIxPTR " looks invalid; refusing to restore.\n",
                    cave_addr);
            close(memfd);
            free(maps);
            detach_process(pid);
            return 1;
        }

        uint8_t zero_stub[STUB_LEN] = {0};
        if (!write_mem(memfd, patch_addr, k_original_patch_bytes, PATCH_LEN) ||
            !write_mem(memfd, cave_addr, zero_stub, STUB_LEN)) {
            close(memfd);
            free(maps);
            detach_process(pid);
            die("restore write");
        }
        printf("Restored original FOV code at 0x%" PRIxPTR ".\n", patch_addr);

    } else {
        uint8_t current[PATCH_LEN];
        if (!read_mem(memfd, patch_addr, current, PATCH_LEN)) {
            close(memfd);
            free(maps);
            detach_process(pid);
            die("read patch site");
        }

        uint32_t bits = float_bits(fov);

        if (current[0] == 0xe9) {
            /* Patch already applied — update the float in the existing stub. */
            uintptr_t cave_addr = 0;
            if (!read_stub_target(memfd, patch_addr, &cave_addr) ||
                !validate_stub(memfd, cave_addr, patch_addr)) {
                fprintf(stderr, "Stub at 0x%" PRIxPTR " looks invalid; refusing to update.\n",
                        cave_addr);
                close(memfd);
                free(maps);
                detach_process(pid);
                return 1;
            }

            if (!write_mem(memfd, cave_addr + 1, &bits, sizeof(bits))) {
                close(memfd);
                free(maps);
                detach_process(pid);
                die("update fov write");
            }
            printf("Updated FOV to %.6g (stub 0x%" PRIxPTR ").\n", fov, cave_addr);

        } else {
            if (memcmp(current, k_original_patch_bytes, PATCH_LEN) != 0) {
                fprintf(stderr, "Unexpected bytes at patch site 0x%" PRIxPTR "; refusing to patch.\n",
                        patch_addr);
                close(memfd);
                free(maps);
                detach_process(pid);
                return 1;
            }

            /* Fresh patch: find a code cave and install the stub. */
            uintptr_t cave_addr = find_cave(memfd, maps, map_count, patch_addr);
            if (!cave_addr) {
                fprintf(stderr, "No suitable code cave found near patch site.\n");
                close(memfd);
                free(maps);
                detach_process(pid);
                return 1;
            }

            int32_t back = 0;
            if (!rel32(cave_addr + STUB_LEN, patch_addr + PATCH_LEN, &back)) {
                fprintf(stderr, "Stub return jump is out of range.\n");
                close(memfd);
                free(maps);
                detach_process(pid);
                return 1;
            }

            uint8_t stub[STUB_LEN] = {0};
            stub[0] = 0xb8;
            memcpy(stub + 1, &bits, 4);
            stub[5] = 0x4c;
            stub[6] = 0x8b;
            stub[7] = 0xc2;
            stub[8] = 0xe9;
            memcpy(stub + 9, &back, 4);

            int32_t to_stub = 0;
            if (!rel32(patch_addr + 5, cave_addr, &to_stub)) {
                fprintf(stderr, "Patch jump is out of range.\n");
                close(memfd);
                free(maps);
                detach_process(pid);
                return 1;
            }

            uint8_t patch[PATCH_LEN] = {0xe9, 0, 0, 0, 0, 0x90};
            memcpy(patch + 1, &to_stub, 4);

            if (!write_mem(memfd, cave_addr, stub, STUB_LEN) ||
                !write_mem(memfd, patch_addr, patch, PATCH_LEN)) {
                close(memfd);
                free(maps);
                detach_process(pid);
                die("patch write");
            }
            printf("Patched pid %d: FOV %.6g at 0x%" PRIxPTR ", stub 0x%" PRIxPTR ".\n",
                   pid, fov, patch_addr, cave_addr);
        }
    }

    close(memfd);
    free(maps);
    detach_process(pid);
    return 0;
}
