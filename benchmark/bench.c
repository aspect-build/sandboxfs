// bench.c — sandbox laydown + workload microbenchmark for sandboxfs.
//
//   bench gen     <dir> [seed]      generate a bazel-like input tree
//   bench clone   <src> <dst>       whole-tree clonefile(2) laydown
//   bench symlink <src> <dst>       per-file symlink(2) laydown (abs targets)
//   bench link    <src> <dst>       per-file link(2) laydown (same inode)
//   bench copy    <src> <dst>       per-file read/write copy laydown
//   bench manifest <src>            emit a sandboxfs proto Manifest (stdout)
//   bench work    <dir>             time getattrlistbulk/readdir/stat/read, JSON to stdout
//
// One binary so the three impls share identical generation, laydown and
// measurement code — the only variable in a `work` run is the filesystem.

#define _DARWIN_C_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/attr.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/clonefile.h>
#include <pthread.h>
#include <CommonCrypto/CommonDigest.h>

// clock_gettime(CLOCK_MONOTONIC) quantizes to ~1us on this machine — too
// coarse for the low-microsecond effects this harness measures. CLOCK_UPTIME_RAW
// is a commpage read (mach_absolute_time scaled by the timebase, no syscall)
// at the mach tick's real resolution (~42ns here).
static uint64_t now_ns(void) {
    return clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
}

static void die(const char *what) { perror(what); exit(1); }


// A bazel-ish action input tree: `pkgs` workspace packages plus `ext`
// self-contained external repos under external/ (the clonefile(dir) sweet
// spot). Three payload profiles stress different costs: mixed (balanced),
// manysmall (metadata/stat-bound), fewlarge (read/throughput-bound).
typedef struct {
    const char *name;
    int pkgs, ext, hdr_dirs, hdrs_dir, srcs, bigs;
    size_t hdr_sz, src_sz, big_sz;
} profile;
static const profile PROFILES[] = {
    {"manysmall",120, 4, 6, 20, 2, 0,  1024,   4096,           0},  // metadata/stat-bound
    {"fewlarge",   8, 2, 1,  2, 2, 6,   512, 262144, 4 * 1024 * 1024},  // read/throughput-bound
    {"nodemod",    0, 0, 0,  0, 0, 0,      0,      0,           0},  // node_modules stat swarm (special builder)
    {"treeheavy",  0, 0, 0,  0, 0, 0,      0,      0,           0},  // deep dir skeleton (special builder)
};

static unsigned g_seed;
static void wr(const char *path, size_t bytes, int exec) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, exec ? 0755 : 0644);
    if (fd < 0) die(path);
    char buf[65536];
    for (size_t i = 0; i < sizeof buf; i++) buf[i] = (char)(rand_r(&g_seed));
    size_t left = bytes;
    while (left) {
        size_t n = left < sizeof buf ? left : sizeof buf;
        if (write(fd, buf, n) != (ssize_t)n) die("write");
        left -= n;
    }
    close(fd);
}

// One self-contained package/repo at `base`. `scale` multiplies the nesting
// and big-file count so external repos come out as larger, deeper subtrees.
static void gen_pkg(const char *base, const profile *P, int scale) {
    char p[4096], mk[4096];
    if (mkdir(base, 0755) && errno != EEXIST) die(base);
    for (int d = 0; d < P->hdr_dirs * scale; d++) {
        char dir[4096];
        snprintf(mk, sizeof mk, "%s/include", base); mkdir(mk, 0755);
        snprintf(mk, sizeof mk, "%s/include/sub%d", base, d); mkdir(mk, 0755);
        snprintf(dir, sizeof dir, "%s/include/sub%d/deep", base, d); mkdir(dir, 0755);
        for (int h = 0; h < P->hdrs_dir; h++) {
            snprintf(p, sizeof p, "%s/h%02d.h", dir, h);
            wr(p, P->hdr_sz + (rand_r(&g_seed) % (P->hdr_sz + 1)), 0);
        }
    }
    for (int s = 0; s < P->srcs; s++) {
        snprintf(p, sizeof p, "%s/src%d.cc", base, s);
        wr(p, P->src_sz + (rand_r(&g_seed) % (P->src_sz + 1)), 0);
    }
    for (int b = 0; b < P->bigs * scale; b++) {
        snprintf(p, sizeof p, "%s/lib%d.a", base, b);
        wr(p, P->big_sz, 1);
    }
}

// node_modules stat swarm: deep, recursive node_modules nesting, every package
// dir a clutch of tiny files (package.json/index.js/...). The shape real
// JS tooling stats its way through — many dirs, many small files, deep paths.
#define NM_TOP 16
#define NM_FANOUT 3
#define NM_DEPTH 3
static void nm_pkg(const char *dir, int depth) {
    char p[4096];
    if (mkdir(dir, 0755) && errno != EEXIST) die(dir);
    snprintf(p, sizeof p, "%s/package.json", dir); wr(p, 400 + rand_r(&g_seed) % 800, 0);
    snprintf(p, sizeof p, "%s/index.js", dir);     wr(p, 1024 + rand_r(&g_seed) % 2048, 0);
    snprintf(p, sizeof p, "%s/README.md", dir);    wr(p, 200 + rand_r(&g_seed) % 400, 0);
    snprintf(p, sizeof p, "%s/.npmignore", dir);   wr(p, 64, 0);
    if (depth > 0) {
        char nm[4096]; snprintf(nm, sizeof nm, "%s/node_modules", dir); mkdir(nm, 0755);
        for (int i = 0; i < NM_FANOUT; i++) {
            char d[4096]; snprintf(d, sizeof d, "%s/dep%d", nm, i);
            nm_pkg(d, depth - 1);
        }
    }
}
static void gen_nodemod(const char *root) {
    char nm[4096];
    if (mkdir(root, 0755) && errno != EEXIST) die(root);
    snprintf(nm, sizeof nm, "%s/node_modules", root); mkdir(nm, 0755);
    for (int i = 0; i < NM_TOP; i++) {
        char d[4096]; snprintf(d, sizeof d, "%s/pkg%02d", nm, i);
        nm_pkg(d, NM_DEPTH);
    }
}

// tree-heavy: a deep, wide directory skeleton — dirs dominate, one tiny file each.
// Stresses per-entry metadata: clonefile COWs every dir inode, the symlink farm
// mkdir+symlinks each, and fskit readdir/getattrlistbulk run on thousands of dirs.
#define TH_FANOUT 4
#define TH_DEPTH 6
static void th_dir(const char *dir, int depth) {
    if (mkdir(dir, 0755) && errno != EEXIST) die(dir);
    char p[4096]; snprintf(p, sizeof p, "%s/f", dir);
    wr(p, 256 + rand_r(&g_seed) % 512, 0);
    if (depth > 0)
        for (int i = 0; i < TH_FANOUT; i++) {
            char d[4096]; snprintf(d, sizeof d, "%s/d%d", dir, i);
            th_dir(d, depth - 1);
        }
}

static void gen(const char *root, const profile *P, unsigned seed) {
    g_seed = seed;
    char p[4096];
    if (!strcmp(P->name, "nodemod")) { gen_nodemod(root); return; }
    if (!strcmp(P->name, "treeheavy")) { th_dir(root, TH_DEPTH); return; }
    if (mkdir(root, 0755) && errno != EEXIST) die(root);
    for (int pk = 0; pk < P->pkgs; pk++) {
        snprintf(p, sizeof p, "%s/pkg%03d", root, pk);
        gen_pkg(p, P, 1);
    }
    // external/ — self-contained repos, deeper and bigger; the dirs you'd
    // clonefile() whole rather than file-by-file.
    snprintf(p, sizeof p, "%s/external", root);
    mkdir(p, 0755);
    for (int r = 0; r < P->ext; r++) {
        snprintf(p, sizeof p, "%s/external/repo%02d", root, r);
        gen_pkg(p, P, 3);
    }
}


typedef int (*place_fn)(const char *src_abs, const char *dst);

static int place_symlink(const char *src, const char *dst) {
    return symlink(src, dst);
}

static int place_link(const char *src, const char *dst) {
    return linkat(AT_FDCWD, src, AT_FDCWD, dst, AT_SYMLINK_FOLLOW);
}

// A byte copy through read/write, never clonefile: what a copying sandbox pays.
static int place_copy(const char *src, const char *dst) {
    int in = open(src, O_RDONLY);
    if (in < 0) return -1;
    struct stat st;
    if (fstat(in, &st)) { close(in); return -1; }
    int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, st.st_mode & 07777);
    if (out < 0) { close(in); return -1; }
    static char buf[1 << 20];
    ssize_t n;
    while ((n = read(in, buf, sizeof buf)) > 0)
        if (write(out, buf, n) != n) { n = -1; break; }
    close(in);
    close(out);
    return n < 0 ? -1 : 0;
}

// clonefile(2) on a directory COW-clones the whole subtree in one syscall —
// the real clonefile-sandbox fast path for self-contained inputs. We clone the
// root in one shot rather than walking + cloning per file.
static void clone_tree(const char *src, const char *dst) {
    if (clonefile(src, dst, 0)) die(dst);
}

// Recursive copy of structure: dirs are mkdir'd in dst, files placed via fn.
// Used for symlink laydown (symlink can't clone a subtree).
static void laydown(const char *src, const char *dst, place_fn fn) {
    DIR *d = opendir(src);
    if (!d) die(src);
    if (mkdir(dst, 0755) && errno != EEXIST) die(dst);
    struct dirent *e;
    while ((e = readdir(d))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        char s[4096], t[4096];
        snprintf(s, sizeof s, "%s/%s", src, e->d_name);
        snprintf(t, sizeof t, "%s/%s", dst, e->d_name);
        struct stat st;
        if (lstat(s, &st)) die(s);
        if (S_ISDIR(st.st_mode)) {
            laydown(s, t, fn);
        } else {
            // src must be absolute for symlink targets to resolve from anywhere.
            char abs[4096];
            if (s[0] == '/') snprintf(abs, sizeof abs, "%s", s);
            else { char cwd[4096]; getcwd(cwd, sizeof cwd); snprintf(abs, sizeof abs, "%s/%s", cwd, s); }
            if (fn(abs, t)) die(t);
        }
    }
    closedir(d);
}

//
// The appex's wire contract (libsandboxfs/Sandbox.swift): a standard REAPI Merkle
// tree at field 15 (Tree{ root Directory=1, children Directory=2 }), the root key
// at field 11 (input_root_digest), and host source paths out-of-tree at field 12
// (host_mapping: tree-path -> abs host path). A Directory's digest is the SHA-256
// of its serialized bytes; the decoder re-derives it to resolve child references.

typedef struct { uint8_t *p; size_t len, cap; } buf;
static void bput(buf *b, const void *src, size_t n) {
    if (!n) return;
    if (b->len + n > b->cap) { b->cap = (b->len + n) * 2 + 64; b->p = realloc(b->p, b->cap); }
    memcpy(b->p + b->len, src, n); b->len += n;
}
static void bvarint(buf *b, uint64_t v) {
    uint8_t t[10]; int i = 0;
    do { t[i] = v & 0x7f; v >>= 7; if (v) t[i] |= 0x80; i++; } while (v);
    bput(b, t, i);
}
static void btag(buf *b, int field, int wire) { bvarint(b, ((uint64_t)field << 3) | wire); }
static void bbytes(buf *b, int field, const void *p, size_t n) { btag(b, field, 2); bvarint(b, n); bput(b, p, n); }
static void bstr(buf *b, int field, const char *s) { bbytes(b, field, s, strlen(s)); }
static void buint(buf *b, int field, uint64_t v) { btag(b, field, 0); bvarint(b, v); }
static void bmsg(buf *b, int field, buf *child) { bbytes(b, field, child->p, child->len); }

static void to_hex(const uint8_t *d, int n, char *out) {
    static const char h[] = "0123456789abcdef";
    for (int i = 0; i < n; i++) { out[2 * i] = h[d[i] >> 4]; out[2 * i + 1] = h[d[i] & 0xf]; }
    out[2 * n] = 0;
}
static void sha256_buf(const uint8_t *p, size_t n, char hex[65]) {
    uint8_t d[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(p, (CC_LONG)n, d);
    to_hex(d, CC_SHA256_DIGEST_LENGTH, hex);
}
static void sha256_file_hex(const char *path, char hex[65], uint64_t *size) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) die(path);
    CC_SHA256_CTX c; CC_SHA256_Init(&c);
    static char rb[1 << 20]; ssize_t n; uint64_t total = 0;
    while ((n = read(fd, rb, sizeof rb)) > 0) { CC_SHA256_Update(&c, rb, (CC_LONG)n); total += n; }
    close(fd);
    uint8_t d[CC_SHA256_DIGEST_LENGTH]; CC_SHA256_Final(d, &c);
    to_hex(d, CC_SHA256_DIGEST_LENGTH, hex);
    *size = total;
}
static void abspath(const char *s, char *out, size_t outsz) {
    if (s[0] == '/') snprintf(out, outsz, "%s", s);
    else { char cwd[4096]; getcwd(cwd, sizeof cwd); snprintf(out, outsz, "%s/%s", cwd, s); }
}

static int cmp_name(const void *a, const void *b) { return strcmp((const char *)a, (const char *)b); }

static buf g_children;   // field-2-framed Tree.children (each a serialized Directory)
static buf g_hostmap;    // field-12-framed host_mapping entries (tree-path -> abs host path)

// Serialize the REAPI Directory at `dir` (tree-path `path`) into `out`; set its
// SHA-256 hex digest and byte size. Names sorted for a canonical digest.
static void ser_dir(const char *dir, const char *path, buf *out, char digest_hex[65], uint64_t *size) {
    DIR *d = opendir(dir);
    if (!d) die(dir);
    char (*names)[256] = NULL; size_t nn = 0, cap = 0;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        if (nn == cap) { cap = cap ? cap * 2 : 64; names = realloc(names, cap * 256); }
        snprintf(names[nn++], 256, "%s", e->d_name);
    }
    closedir(d);
    qsort(names, nn, 256, cmp_name);

    for (size_t i = 0; i < nn; i++) {
        char s[4096]; snprintf(s, sizeof s, "%s/%s", dir, names[i]);
        struct stat st;
        if (lstat(s, &st)) die(s);
        char full[4096];
        if (path[0]) snprintf(full, sizeof full, "%s/%s", path, names[i]);
        else snprintf(full, sizeof full, "%s", names[i]);

        if (S_ISDIR(st.st_mode)) {
            buf child = {0}; char cdg[65]; uint64_t csize;
            ser_dir(s, full, &child, cdg, &csize);
            bmsg(&g_children, 2, &child);                 // Tree.children += this Directory
            buf dn = {0}; bstr(&dn, 1, names[i]);          // DirectoryNode{ name, Digest }
            buf dg = {0}; bstr(&dg, 1, cdg); buint(&dg, 2, csize); bmsg(&dn, 2, &dg);
            bmsg(out, 2, &dn);
            free(dg.p); free(dn.p); free(child.p);
        } else if (S_ISLNK(st.st_mode)) {
            char tgt[4096]; ssize_t k = readlink(s, tgt, sizeof tgt - 1); if (k < 0) k = 0; tgt[k] = 0;
            buf sn = {0}; bstr(&sn, 1, names[i]); bstr(&sn, 2, tgt); bmsg(out, 3, &sn); free(sn.p);
        } else if (S_ISREG(st.st_mode)) {
            char abs[4096]; abspath(s, abs, sizeof abs);
            char hex[65]; uint64_t fsize; sha256_file_hex(abs, hex, &fsize);
            buf fn = {0}; bstr(&fn, 1, names[i]);          // FileNode{ name, Digest, is_executable=4 }
            buf dg = {0}; bstr(&dg, 1, hex); buint(&dg, 2, fsize); bmsg(&fn, 2, &dg);
            if (st.st_mode & S_IXUSR) buint(&fn, 4, 1);
            bmsg(out, 1, &fn);
            free(dg.p); free(fn.p);
            buf me = {0}; bstr(&me, 1, full); bstr(&me, 2, abs); bmsg(&g_hostmap, 12, &me); free(me.p);
        }
    }
    free(names);
    *size = out->len;
    sha256_buf(out->p, out->len, digest_hex);
}

static void manifest(const char *src) {
    buf root = {0}; char rootdg[65]; uint64_t rootsize;
    ser_dir(src, "", &root, rootdg, &rootsize);
    buf m = {0};
    buf dg = {0}; bstr(&dg, 1, rootdg); buint(&dg, 2, rootsize); bmsg(&m, 11, &dg);  // input_root_digest
    bput(&m, g_hostmap.p, g_hostmap.len);                                            // host_mapping (field 12)
    buf tree = {0}; bmsg(&tree, 1, &root); bput(&tree, g_children.p, g_children.len);
    bmsg(&m, 15, &tree);                                                             // Tree
    if (write(1, m.p, m.len) != (ssize_t)m.len) die("write manifest");
    free(dg.p); free(tree.p); free(root.p); free(m.p);
}


typedef struct { uint64_t *v; size_t n, cap; } samples;
static void add(samples *s, uint64_t ns) {
    if (s->n == s->cap) { s->cap = s->cap ? s->cap * 2 : 4096; s->v = realloc(s->v, s->cap * sizeof *s->v); }
    s->v[s->n++] = ns;
}
static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : x > y;
}
static samples S_stat, S_read, S_readdir, S_bulk, S_open, S_fault;
static uint64_t g_bytes;
static long g_pagesz;
static int g_mode;        // work: 0 full, 1 meta (no open), 2 open+close only, 3 open+read, no mmap
static unsigned g_cpu_hist[64];   // which CPU the harness thread was on after each readdir

// getattrlistbulk over one directory, timed as a single enumeration.
static void time_bulk(const char *path) {
    int fd = open(path, O_RDONLY, 0);
    if (fd < 0) return;
    struct attrlist al = {0};
    al.bitmapcount = ATTR_BIT_MAP_COUNT;
    al.commonattr = ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_NAME | ATTR_CMN_OBJTYPE |
                    ATTR_CMN_MODTIME | ATTR_CMN_ACCESSMASK;
    al.fileattr = ATTR_FILE_DATALENGTH;
    char abuf[64 * 1024];
    uint64_t t0 = now_ns();
    for (;;) {
        int c = getattrlistbulk(fd, &al, abuf, sizeof abuf, 0);
        if (c <= 0) break;
    }
    add(&S_bulk, now_ns() - t0);
    close(fd);
}

static void work(const char *path) {
    time_bulk(path);

    DIR *d = opendir(path);
    if (!d) die(path);
    // readdir: full enumeration timed as one sample (cost to list this dir).
    samples local_names = {0};
    char (*names)[256] = NULL; size_t nn = 0, ncap = 0;
    uint64_t t0 = now_ns();
    struct dirent *e;
    while ((e = readdir(d))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        if (nn == ncap) { ncap = ncap ? ncap * 2 : 64; names = realloc(names, ncap * 256); }
        snprintf(names[nn++], 256, "%s", e->d_name);
    }
    add(&S_readdir, now_ns() - t0);
    { size_t cpu = 0; if (pthread_cpu_number_np(&cpu) == 0 && cpu < 64) g_cpu_hist[cpu]++; }
    closedir(d);
    (void)local_names;

    for (size_t i = 0; i < nn; i++) {
        char s[4096];
        snprintf(s, sizeof s, "%s/%s", path, names[i]);
        struct stat st;
        t0 = now_ns();
        int r = stat(s, &st);          // follow symlinks: a real reader opens through them
        add(&S_stat, now_ns() - t0);
        if (r) continue;
        if (S_ISDIR(st.st_mode)) {
            work(s);
        } else if (S_ISREG(st.st_mode) && g_mode != 1) {
            t0 = now_ns();
            int fd = open(s, O_RDONLY);
            add(&S_open, now_ns() - t0);
            if (fd < 0) continue;
            if (g_mode == 2) { close(fd); continue; }
            static char rb[1 << 20]; ssize_t got;
            t0 = now_ns();
            while ((got = read(fd, rb, sizeof rb)) > 0) g_bytes += got;
            add(&S_read, now_ns() - t0);
            if (g_mode == 3) { close(fd); continue; }
            // page-fault read: mmap and touch one byte per page. This is the dyld /
            // dlopen / mmap-reader path — each fault is serviced by the filesystem
            // (for fskit, a userspace round-trip), distinct from a read() syscall.
            if (st.st_size > 0) {
                void *m = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
                if (m != MAP_FAILED) {
                    volatile char acc = 0;
                    t0 = now_ns();
                    for (off_t o = 0; o < st.st_size; o += g_pagesz) acc ^= ((volatile char *)m)[o];
                    add(&S_fault, now_ns() - t0);
                    (void)acc;
                    munmap(m, st.st_size);
                }
            }
            close(fd);
        }
    }
    free(names);
}

static void emit(const char *name, samples *s, int last) {
    if (s->n == 0) {
        printf("\"%s\":{\"count\":0,\"total_ns\":0,\"p50_ns\":0,\"p99_ns\":0,\"min_ns\":0,\"max_ns\":0}%s",
               name, last ? "" : ",");
        return;
    }
    qsort(s->v, s->n, sizeof *s->v, cmp_u64);
    uint64_t total = 0;
    for (size_t i = 0; i < s->n; i++) total += s->v[i];
    size_t p50 = (size_t)(s->n * 0.50), p99 = (size_t)(s->n * 0.99);
    if (p99 >= s->n) p99 = s->n - 1;
    printf("\"%s\":{\"count\":%zu,\"total_ns\":%llu,\"p50_ns\":%llu,\"p99_ns\":%llu,\"min_ns\":%llu,\"max_ns\":%llu}%s",
           name, s->n, total, s->v[p50], s->v[p99], s->v[0], s->v[s->n - 1], last ? "" : ",");
}


// fork+execve a binary living in the sandbox `iters` times, timing each launch.
// execve is where the kernel validates the code signature (AMFI) and Gatekeeper
// assesses the binary — so the FIRST launch of a fresh inode pays that cost,
// reported separately from the warm steady-state. The backend matters: a symlink
// resolves to an already-validated original; a clonefile is a new inode that may
// re-validate; an fskit file is paged in through the userspace volume.
static void exec_bench(const char *path, int iters) {
    samples s = {0};
    uint64_t first = 0;
    int failed = 0;
    for (int i = 0; i < iters; i++) {
        uint64_t t0 = now_ns();
        pid_t pid = fork();
        if (pid == 0) { execl(path, path, (char *)NULL); _exit(127); }
        if (pid < 0) die("fork");
        int st; waitpid(pid, &st, 0);
        uint64_t dt = now_ns() - t0;
        if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) failed++;
        if (i == 0) first = dt; else add(&s, dt);
    }
    qsort(s.v, s.n, sizeof *s.v, cmp_u64);
    uint64_t p50 = s.n ? s.v[(size_t)(s.n * 0.50)] : 0;
    uint64_t p99 = s.n ? s.v[(size_t)(s.n * 0.99) < s.n ? (size_t)(s.n * 0.99) : s.n - 1] : 0;
    printf("{\"first_ns\":%llu,\"p50_ns\":%llu,\"p99_ns\":%llu,\"count\":%d,\"failed\":%d}\n",
           first, p50, p99, iters, failed);
}


// One stat(2) per call, timed individually — isolates a single path-component
// lookup/getattr round trip (namecache hit or miss) from the noise of a full
// recursive `work` pass. Used to compare a reused leaf name against a fresh
// one across repeated create/destroy cycles at the same parent directory.
static void lookup_bench(const char *path, int n) {
    printf("[");
    for (int i = 0; i < n; i++) {
        struct stat st;
        uint64_t t0 = now_ns();
        int r = stat(path, &st);
        uint64_t dt = now_ns() - t0;
        if (r) die(path);
        printf("%llu%s", dt, i + 1 < n ? "," : "");
    }
    printf("]\n");
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "modes: gen <dir> <profile> [seed] | clone | symlink | link | copy | manifest | work | exec | lookup | rename\n"); return 2; }
    const char *m = argv[1];
    if (!strcmp(m, "gen") && argc >= 4) {
        const profile *P = NULL;
        for (size_t i = 0; i < sizeof PROFILES / sizeof *PROFILES; i++)
            if (!strcmp(PROFILES[i].name, argv[3])) P = &PROFILES[i];
        if (!P) { fprintf(stderr, "unknown profile %s\n", argv[3]); return 2; }
        gen(argv[2], P, argc >= 5 ? (unsigned)atoi(argv[4]) : 1);
    } else if (!strcmp(m, "clone") && argc == 4) {
        uint64_t t0 = now_ns();
        clone_tree(argv[2], argv[3]);
        printf("%llu\n", now_ns() - t0);          // laydown ns, spawn excluded
    } else if (!strcmp(m, "symlink") && argc == 4) {
        uint64_t t0 = now_ns();
        laydown(argv[2], argv[3], place_symlink);
        printf("%llu\n", now_ns() - t0);
    } else if (!strcmp(m, "link") && argc == 4) {
        uint64_t t0 = now_ns();
        laydown(argv[2], argv[3], place_link);
        printf("%llu\n", now_ns() - t0);
    } else if (!strcmp(m, "copy") && argc == 4) {
        uint64_t t0 = now_ns();
        laydown(argv[2], argv[3], place_copy);
        printf("%llu\n", now_ns() - t0);
    } else if (!strcmp(m, "symlinkdir") && argc == 4) {
        char abs[4096]; abspath(argv[2], abs, sizeof abs);
        uint64_t t0 = now_ns();
        if (symlink(abs, argv[3])) die(argv[3]);  // ONE symlink for the whole tree
        printf("%llu\n", now_ns() - t0);
    } else if (!strcmp(m, "manifest") && argc == 3) {
        uint64_t t0 = now_ns();
        manifest(argv[2]);                        // proto → stdout
        fprintf(stderr, "%llu\n", now_ns() - t0); // build ns → stderr
    } else if (!strcmp(m, "exec") && argc == 4) {
        exec_bench(argv[2], atoi(argv[3]));
    } else if (!strcmp(m, "lookup") && argc == 4) {
        lookup_bench(argv[2], atoi(argv[3]));
    } else if (!strcmp(m, "rename") && argc == 4) {
        uint64_t t0 = now_ns();
        if (rename(argv[2], argv[3])) die(argv[3]);   // atomic catalog relink, no new inode
        printf("%llu\n", now_ns() - t0);
    } else if (!strcmp(m, "work") && (argc == 3 || argc == 4)) {
        const char *modes[] = {"full", "meta", "open", "read"};
        for (int i = 0; argc == 4 && i < 4; i++) if (!strcmp(argv[3], modes[i])) g_mode = i;
        g_pagesz = sysconf(_SC_PAGESIZE);
        work(argv[2]);
        printf("{");
        emit("readdir", &S_readdir, 0);
        emit("getattrlistbulk", &S_bulk, 0);
        emit("stat", &S_stat, 0);
        emit("open", &S_open, 0);
        emit("read", &S_read, 0);
        emit("fault", &S_fault, 1);
        printf(",\"bytes_read\":%llu,\"cpus\":{", g_bytes);
        for (int i = 0, first = 1; i < 64; i++) if (g_cpu_hist[i]) { printf("%s\"%d\":%u", first ? "" : ",", i, g_cpu_hist[i]); first = 0; }
        printf("}}\n");
    } else {
        fprintf(stderr, "bad args for %s\n", m);
        return 2;
    }
    return 0;
}
