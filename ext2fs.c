#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdalign.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <unistd.h>

#include "ext2fs_defs.h"
#include "ext2fs.h"

/* If you want debugging output, use the following macro.  When you hand
 * in, remove the #define DEBUG line. */
#undef DEBUG
#ifdef DEBUG
#define debug(...) printf(__VA_ARGS__)
#else
#define debug(...)
#endif

/* Call this function when an unfixable error has happened. */
static noreturn void panic(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  fputc('\n', stderr);
  va_end(ap);
  exit(EXIT_FAILURE);
}

/* Number of lists containing buffered blocks. */
#define NBUCKETS 16

/* Since majority of files in a filesystem are small, `idx` values will be
 * usually low. Since ext2fs tends to allocate blocks at the beginning of each
 * block group, `ino` values are less predictable. */
#define BUCKET(ino, idx) (((ino) + (idx)) % NBUCKETS)

/* That should give us around 64kB worth of buffers. */
#define NBLOCKS (NBUCKETS * 4)

/* Structure that is used to manage buffer of single block. */
typedef struct blk {
  TAILQ_ENTRY(blk) b_hash;
  TAILQ_ENTRY(blk) b_link;
  uint32_t b_blkaddr; /* block address on the block device */
  uint32_t b_inode;   /* i-node number of file this buffer refers to */
  uint32_t b_index;   /* block index from the beginning of file */
  uint32_t b_refcnt;  /* if zero then block can be reused */
  void *b_data;       /* raw data from this buffer */
} blk_t;

typedef TAILQ_HEAD(blk_list, blk) blk_list_t;

/* BLK_ZERO is a special value that reflect the fact that block 0 may be used to
 * represent a block filled with zeros. You must not dereference the value! */
#define BLK_ZERO ((blk_t *)-1L)

/* All memory for buffers and buffer management is allocated statically.
 * Using malloc for these would introduce unnecessary complexity. */
static alignas(BLKSIZE) char blkdata[NBLOCKS][BLKSIZE];
static blk_t blocks[NBLOCKS];
static blk_list_t buckets[NBUCKETS]; /* all blocks with valid data */
static blk_list_t lrulst;            /* free blocks with valid data */
static blk_list_t freelst;           /* free blocks that are empty */

/* File descriptor that refers to ext2 filesystem image. */
static int fd_ext2 = -1;

/* How many i-nodes fit into one block? */
#define BLK_INODES (BLKSIZE / sizeof(ext2_inode_t))

/* How many block pointers fit into one block? */
#define BLK_POINTERS (BLKSIZE / sizeof(uint32_t))

/* Properties extracted from a superblock and block group descriptors. */
static size_t inodes_per_group;      /* number of i-nodes in block group */
static size_t blocks_per_group;      /* number of blocks in block group */
static size_t group_desc_count;      /* numbre of block group descriptors */
static size_t block_count;           /* number of blocks in the filesystem */
static size_t inode_count;           /* number of i-nodes in the filesystem */
static size_t first_data_block;      /* first block managed by block bitmap */
static ext2_groupdesc_t *group_desc; /* block group descriptors in memory */

/*
 * Buffering routines.
 */

/* Opens filesystem image file and initializes block buffers. */
static int blk_init(const char *fspath) {
  if ((fd_ext2 = open(fspath, O_RDONLY)) < 0)
    return errno;

  /* Initialize list structures. */
  TAILQ_INIT(&lrulst);
  TAILQ_INIT(&freelst);
  for (int i = 0; i < NBUCKETS; i++)
    TAILQ_INIT(&buckets[i]);

  /* Initialize all blocks and put them on free list. */
  for (int i = 0; i < NBLOCKS; i++) {
    blocks[i].b_data = blkdata[i];
    TAILQ_INSERT_TAIL(&freelst, &blocks[i], b_link);
  }

  return 0;
}

/* Allocates new block buffer. */
static blk_t *blk_alloc(void) {
  // debug("blk_alloc\n");
  blk_t *blk = NULL;

  /* Initially every empty block is on free list. */
  if (!TAILQ_EMPTY(&freelst)) {
    /* TODO */
    // debug("get block from block_free_list\n");
    blk = TAILQ_FIRST(&freelst);
    TAILQ_REMOVE(&freelst, blk, b_link);
    return blk;
  }

  /* Eventually free list will become exhausted.
   * Then we'll take the last recently used entry from LRU list. */
  if (!TAILQ_EMPTY(&lrulst)) {
    /* TODO */
    // debug("get block from block_lru_list\n");
    blk = TAILQ_LAST(&lrulst, blk_list);
    TAILQ_REMOVE(&lrulst, blk, b_link);
    uint32_t ino = blk->b_inode;
    uint32_t idx = blk->b_index;
    blk_list_t *bucket = &buckets[BUCKET(ino, idx)];
    TAILQ_REMOVE(bucket, blk, b_hash);
    // debug("get block from block_lru_list -end\n");
    return blk;
  }

  /* No buffers!? Have you forgot to release some? */
  panic("Free buffers pool exhausted!");
}

/* Acquires a block buffer for file identified by `ino` i-node and block index
 * `idx`. When `ino` is zero the buffer refers to filesystem metadata (i.e.
 * superblock, block group descriptors, block & i-node bitmap, etc.) and `off`
 * offset is given from the start of block device. */

static blk_t *blk_get(uint32_t ino, uint32_t idx) {
  debug("blk_get ino=%d, idx=%d\n", ino, idx);
  blk_list_t *bucket = &buckets[BUCKET(ino, idx)];
  blk_t *blk = NULL;

  /* Locate a block in the buffer and return it if found. */

  /* TODO */
  blk_t *elm = TAILQ_FIRST(bucket);
  // debug("elem from bucket=%p\n",elm);
  while (elm != NULL) {
    if (elm->b_inode == ino && elm->b_index == idx) {
      if (elm->b_refcnt == 0) {
        TAILQ_REMOVE(&lrulst, elm, b_link);
      }
      elm->b_refcnt++;
      // debug("get block from buckets\n");
      return elm;
    }
    elm = TAILQ_NEXT(elm, b_hash);
  }

  long blkaddr = ext2_blkaddr_read(ino, idx);
  debug("ext2_blkaddr_read(%d, %d) -> %ld\n", ino, idx, blkaddr);
  if (blkaddr == -1)
    return NULL;
  if (blkaddr == 0)
    return BLK_ZERO;
  if (ino > 0 && !ext2_block_used(blkaddr))
    panic("Attempt to read block %d that is not in use!", blkaddr);

  blk = blk_alloc();
  blk->b_inode = ino;
  blk->b_index = idx;
  blk->b_blkaddr = blkaddr;
  blk->b_refcnt = 1;

  ssize_t nread =
    pread(fd_ext2, blk->b_data, BLKSIZE, blk->b_blkaddr * BLKSIZE);
  if (nread != BLKSIZE)
    panic("Attempt to read past the end of filesystem!");

  TAILQ_INSERT_HEAD(bucket, blk, b_hash);
  debug("blk_get - positive end\n");
  return blk;
}

/* Releases a block buffer. If reference counter hits 0 the buffer can be
 * reused to cache another block. The buffer is put at the beginning of LRU list
 * of unused blocks. */
static void blk_put(blk_t *blk) {
  debug("blk put\n");
  if (--blk->b_refcnt > 0) {
    // debug("blk put end, refcnt>0\n");
    return;
  }
  TAILQ_INSERT_HEAD(&lrulst, blk, b_link);
  // debug("blk put end, refcnt=0\n");
}

/*
 * Ext2 filesystem routines.
 */

/* Reads block bitmap entry for `blkaddr`. Returns 0 if the block is free,
 * 1 if it's in use, and EINVAL if `blkaddr` is out of range. */
int ext2_block_used(uint32_t blkaddr) {
  debug("ext2_block_used (%d)\n", blkaddr);
  if (blkaddr >= block_count)
    return EINVAL;
  int used = 0;
  /* TODO */
  int index_group = (blkaddr - 1) / blocks_per_group;
  ext2_groupdesc_t group_descriptor = group_desc[index_group];
  int index_block = (blkaddr - 1) % blocks_per_group;
  blk_t *block_bitmap = blk_get(0, group_descriptor.gd_b_bitmap);
  debug("block bitmap_blocks=%d\n", group_descriptor.gd_i_bitmap);
  uint8_t *bitmap_blocks = block_bitmap->b_data;
  used = *(bitmap_blocks + (index_block / 8)) & (1 << (index_block % 8));
  blk_put(block_bitmap);
  debug("ext2_inode_used? =%d\n", used != 0);
  return used != 0;
}

/* Reads i-node bitmap entry for `ino`. Returns 0 if the i-node is free,
 * 1 if it's in use, and EINVAL if `ino` value is out of range. */
int ext2_inode_used(uint32_t ino) {
  debug("ext2_inode_used (%d)\n", ino);
  if (!ino || ino >= inode_count) {
    debug("ino=%d value is out of range inode_count=%ld\n", ino, inode_count);
    return EINVAL;
  }
  int used = 0;
  /* TODO */
  int index_group = (ino - 1) / inodes_per_group;
  ext2_groupdesc_t group_descriptor = group_desc[index_group];
  int index_inode = (ino - 1) % inodes_per_group;
  blk_t *block_bitmap = blk_get(0, group_descriptor.gd_i_bitmap);
  debug("block bitmap=%d\n", group_descriptor.gd_i_bitmap);
  uint8_t *bitmap_inodes = block_bitmap->b_data;
  used = *(bitmap_inodes + (index_inode / 8)) & (1 << (index_inode % 8));
  blk_put(block_bitmap);
  debug("ext2_inode_used? =%d\n", used != 0);
  return used != 0;
}

/* Reads i-node identified by number `ino`.
 * Returns 0 on success. If i-node is not allocated returns ENOENT. */
static int ext2_inode_read(off_t ino, ext2_inode_t *inode) {
  debug("ext2_inode_read ino=%ld\n", ino);
  /* TODO */
  if (ino == 0)
    return ENOENT;
  if (!ext2_inode_used(ino))
    return ENOENT;
  int index_group = (ino - 1) / inodes_per_group;
  ext2_groupdesc_t group_descriptor = group_desc[index_group];
  int index_inode = (ino - 1) % inodes_per_group;
  ext2_read(0, inode,
            BLKSIZE * group_descriptor.gd_i_tables +
              index_inode * sizeof(ext2_inode_t),
            sizeof(ext2_inode_t));
  debug("ext2_inode_read - positive end\n");
  return 0;
}

/* Returns block pointer `blkidx` from block of `blkaddr` address. */
static uint32_t ext2_blkptr_read(uint32_t blkaddr, uint32_t blkidx) {
  debug("blkptr_read (%d, %d)\n", blkaddr, blkidx);
  /* TODO */
  uint32_t block_addr;
  ext2_read(0, &block_addr, BLKSIZE * blkaddr + sizeof(uint32_t) * blkidx,
            sizeof(uint32_t));
  return block_addr;
}

/* Translates i-node number `ino` and block index `idx` to block address.
 * Returns -1 on failure, otherwise block address. */
long ext2_blkaddr_read(uint32_t ino, uint32_t blkidx) {
  /* No translation for filesystem metadata blocks. */
  debug("ext2_blkaddr_read (%d, %d)\n", ino, blkidx);
  if (ino == 0)
    return blkidx;

  ext2_inode_t inode;
  if (ext2_inode_read(ino, &inode)) {
    debug("ext2_blkaddr_read - negative end\n");
    return -1;
  }

  /* Read direct pointers or pointers from indirect blocks. */

  /* TODO */
  if (blkidx < 12) {
    debug("ext2_blkaddr_read <12, return (%d, %d) -> %d\n", ino, blkidx,
          inode.i_blocks[blkidx]);
    return inode.i_blocks[blkidx];
  } else if (blkidx < BLK_POINTERS + 12) {
    debug("ext2_blkaddr_read <%ld\n", BLK_POINTERS + 12);
    return ext2_blkptr_read(inode.i_blocks[12], blkidx - 12);
  } else if (blkidx < BLK_POINTERS * BLK_POINTERS + BLK_POINTERS + 12) {
    debug("ext2_blkaddr_read <%ld\n",
          BLK_POINTERS * BLK_POINTERS + BLK_POINTERS + 12);
    uint32_t indirect_block = ext2_blkptr_read(
      inode.i_blocks[13], (blkidx - BLK_POINTERS - 12) / BLK_POINTERS);
    return ext2_blkptr_read(indirect_block,
                            (blkidx - BLK_POINTERS - 12) % BLK_POINTERS);
  } else if (blkidx < BLK_POINTERS * BLK_POINTERS * BLK_POINTERS +
                        BLK_POINTERS * BLK_POINTERS + BLK_POINTERS + 12) {
    debug("ext2_blkaddr_read <%ld\n",
          BLK_POINTERS * BLK_POINTERS * BLK_POINTERS +
            BLK_POINTERS * BLK_POINTERS + BLK_POINTERS + 12);
    uint32_t index =
      (blkidx - BLK_POINTERS * BLK_POINTERS - BLK_POINTERS - 12) /
      (BLK_POINTERS * BLK_POINTERS);
    uint32_t indirect_block = ext2_blkptr_read(inode.i_blocks[14], index);
    uint32_t deeper_index = (blkidx - index * BLK_POINTERS * BLK_POINTERS -
                             BLK_POINTERS * BLK_POINTERS - BLK_POINTERS - 12) /
                            BLK_POINTERS;
    uint32_t deepeest_indirect_block =
      ext2_blkptr_read(indirect_block, deeper_index);
    uint32_t deepest_index = (blkidx - index * BLK_POINTERS * BLK_POINTERS -
                              BLK_POINTERS * BLK_POINTERS -
                              deeper_index * BLK_POINTERS - BLK_POINTERS - 12) %
                             BLK_POINTERS;
    return ext2_blkptr_read(deepeest_indirect_block, deepest_index);
  }

  return -1;
}

/* Reads exactly `len` bytes starting from `pos` position from any file (i.e.
 * regular, directory, etc.) identified by `ino` i-node. Returns 0 on success,
 * EINVAL if `pos` and `len` would have pointed past the last block of file.
 *
 * WARNING: This function assumes that `ino` i-node pointer is valid! */
int ext2_read(uint32_t ino, void *data, size_t pos, size_t len) {
  debug("ext2_read inode=%d pos=%ld len=%ld\n", ino, pos, len);
  /* TODO */
  ext2_inode_t inode;
  if (ino != 0)
    ext2_inode_read(ino, &inode);
  while (len > 0) {
    uint32_t idx = pos / BLKSIZE;
    uint32_t position_in_current_block = pos % BLKSIZE;
    debug("idx=%d, inode_nblock=%d, position_in_current_block=%d len=%ld,", idx,
          inode.i_nblock, position_in_current_block, len);
    if (ino != 0 && pos + len > inode.i_size) {
      debug("out of file\n");
      return EINVAL;
    }

    blk_t *block = blk_get(ino, idx);

    if (position_in_current_block + len <= BLKSIZE) {
      if (block != BLK_ZERO)
        memcpy(data, (void *)(block->b_data) + position_in_current_block, len);
      else
        memset(data, 0, len);
      len -= len;
    } else {
      uint32_t read_bytes = BLKSIZE - position_in_current_block;
      if (block != BLK_ZERO)
        memcpy(data, (void *)(block->b_data) + position_in_current_block,
               read_bytes);
      else
        memset(data, 0, len);
      len -= read_bytes;
      data += read_bytes;
      pos += read_bytes;
    }
    if (block != BLK_ZERO)
      blk_put(block);
  }
  debug("ext2_read -end\n");
  return 0;
}

/* Reads a directory entry at position stored in `off_p` from `ino` i-node that
 * is assumed to be a directory file. The entry is stored in `de` and
 * `de->de_name` must be NUL-terminated. Assumes that entry offset is 0 or was
 * set by previous call to `ext2_readdir`. Returns 1 on success, 0 if there are
 * no more entries to read. */
#define de_name_offset offsetof(ext2_dirent_t, de_name)

int ext2_readdir(uint32_t ino, uint32_t *off_p, ext2_dirent_t *de) {
  debug("ext2_readdir (%d, %d)\n", ino, *off_p);

  /* TODO */
  ext2_inode_t inode;
  ext2_inode_read(ino, &inode);
  if (inode.i_size <= *off_p) {
    debug("ext2_readdir (%d, %d) - end, no more entries\n", ino, *off_p);
    return 0;
  }
  ext2_read(ino, de, *off_p, 8);
  uint8_t name_len = de->de_namelen;
  ext2_read(ino, de->de_name, *off_p + 8, name_len);
  de->de_name[name_len] = '\0';
  *off_p = *off_p + de->de_reclen;

  debug("ext2_readdir (%d, %d) -> %s - positive end\n", ino, *off_p,
        de->de_name);
  return 1;
}

/* Read the target of a symbolic link identified by `ino` i-node into buffer
 * `buf` of size `buflen`. Returns 0 on success, EINVAL if the file is not a
 * symlink or read failed. */
int ext2_readlink(uint32_t ino, char *buf, size_t buflen) {
  debug("ext2_readlink (%d)\n", ino);
  int error;

  ext2_inode_t inode;
  if ((error = ext2_inode_read(ino, &inode)))
    return error;

  /* Check if it's a symlink and read it. */

  /* TODO */
  uint32_t type = EXT2_IFMT & inode.i_mode;
  if (EXT2_IFLNK != type) {
    debug("ext2_readlink - negative end\n");
    return EINVAL;
  }

  if (inode.i_size > buflen)
    return EINVAL;

  if (inode.i_size < 60) {
    memcpy(buf, inode.i_blocks, inode.i_size);
    buf[inode.i_size] = '\0';
    debug("ext2_readlink - positive end\n");
    return 0;
  } else {
    long read_bytes = ext2_read(ino, buf, 0, inode.i_size);
    if (read_bytes < 0) {
      debug("ext2_readlink - negative end\n");
      return EINVAL;
    }
    buf[read_bytes] = '\0';
    debug("ext2_readlink - positive end\n");
    return 0;
  }
}

/* Read metadata from file identified by `ino` i-node and convert it to
 * `struct stat`. Returns 0 on success, or error if i-node could not be read. */
int ext2_stat(uint32_t ino, struct stat *st) {
  debug("stat ino=%d\n", ino);
  int error;

  ext2_inode_t inode;
  if ((error = ext2_inode_read(ino, &inode)))
    return error;

  /* Convert the metadata! */

  /* TODO */
  st->st_ino = ino;
  st->st_mode = inode.i_mode;
  st->st_nlink = inode.i_nlink;
  st->st_uid = inode.i_uid;
  st->st_gid = inode.i_gid;
  st->st_size = inode.i_size;
  st->st_blksize = BLKSIZE;
  st->st_blocks = inode.i_nblock;
  st->st_atime = inode.i_atime;
  st->st_mtime = inode.i_mtime;
  st->st_ctime = inode.i_ctime;
  debug("stat - koniec\n");
  return 0;
}

/* Reads file identified by `ino` i-node as directory and performs a lookup of
 * `name` entry. If an entry is found, its i-inode number is stored in `ino_p`
 * and its type in stored in `type_p`. On success returns 0, or EINVAL if `name`
 * is NULL or zero length, or ENOTDIR is `ino` file is not a directory, or
 * ENOENT if no entry was found. */
int ext2_lookup(uint32_t ino, const char *name, uint32_t *ino_p,
                uint8_t *type_p) {
  int error;

  if (name == NULL || !strlen(name)) {
    debug("EINVAL - end lookup");
    return EINVAL;
  }

  ext2_inode_t inode;
  if ((error = ext2_inode_read(ino, &inode))) {
    debug("error ext2_inode_read - negative end lookup");
    return error;
  }

  /* TODO */
  if ((EXT2_IFDIR & inode.i_mode) == 0) {
    debug("lookup - negative end, inode is not dir\n");
    debug("inode_mode=%d\n", inode.i_mode);
    return ENOTDIR;
  }
  ext2_dirent_t entry;
  uint32_t offset = 0;
  if (ext2_readdir(ino, &offset, &entry) == 0) {
    return ENOENT;
  }
  while (strcmp(name, entry.de_name)) {
    if (ext2_readdir(ino, &offset, &entry) == 0) {
      debug("lookup - end of dir\n");
      return ENOENT;
    }
  }
  debug("zapisuje\n");
  if (ino_p != NULL)
    *ino_p = entry.de_ino;
  if (type_p != NULL)
    *type_p = entry.de_type;
  return 0;
}

/* Initializes ext2 filesystem stored in `fspath` file.
 * Returns 0 on success, otherwise an error. */
int ext2_mount(const char *fspath) {
  int error;

  if ((error = blk_init(fspath)))
    return error;

  /* Read superblock and verify we support filesystem's features. */
  ext2_superblock_t sb;
  ext2_read(0, &sb, EXT2_SBOFF, sizeof(ext2_superblock_t));

  debug(">>> super block\n"
        "# of inodes      : %d\n"
        "# of blocks      : %d\n"
        "block size       : %ld\n"
        "blocks per group : %d\n"
        "inodes per group : %d\n"
        "inode size       : %d\n",
        sb.sb_icount, sb.sb_bcount, 1024UL << sb.sb_log_bsize, sb.sb_bpg,
        sb.sb_ipg, sb.sb_inode_size);

  if (sb.sb_magic != EXT2_MAGIC)
    panic("'%s' cannot be identified as ext2 filesystem!", fspath);

  if (sb.sb_rev != EXT2_REV1)
    panic("Only ext2 revision 1 is supported!");

  size_t blksize = 1024UL << sb.sb_log_bsize;
  if (blksize != BLKSIZE)
    panic("ext2 filesystem with block size %ld not supported!", blksize);

  if (sb.sb_inode_size != sizeof(ext2_inode_t))
    panic("The only i-node size supported is %d!", sizeof(ext2_inode_t));

  /* Load interesting data from superblock into global variables.
   * Read group descriptor table into memory. */

  /* TODO */
  inodes_per_group = sb.sb_ipg;
  blocks_per_group = sb.sb_bpg;
  group_desc_count = 1 + (sb.sb_bcount - 1) / blocks_per_group;
  block_count = sb.sb_bcount;
  inode_count = sb.sb_icount;
  first_data_block = sb.sb_first_dblock;
  group_desc = malloc(group_desc_count * sizeof(ext2_groupdesc_t));
  ext2_read(0, group_desc, EXT2_GDOFF,
            group_desc_count * sizeof(ext2_groupdesc_t));
  return 0;
}
