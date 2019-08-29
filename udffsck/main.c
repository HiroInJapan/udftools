/*
 * Copyright (C) 2017 Vojtech Vladyka <vojtech.vladyka@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _POSIX_C_SOURCE 200808L
#define _DEFAULT_SOURCE

#include "config.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/file.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <limits.h>
#include <signal.h>
#include <mntent.h>
#include <sys/vfs.h>
#include <sys/stat.h>
#include <sys/vfs.h>

#include <ecma_167.h>
#include <libudffs.h>

#include "utils.h"
#include "options.h"
#include "udffsck.h"


#define PRINT_DISC 

#define MAX_VERSION 0x0201

/**
 * \brief User interrupt hander (Ctrl + C or SIGINT)
 *
 * After calling this, program exits with code 32 (User interrupt).
 */
void user_interrupt(int dummy) {
    (void)dummy;
    warn("\nUser interrupted operation. Exiting.\n");
    exit(ESTATUS_USER_CANCEL);
}

/**
 * \brief Segmentation fault handler
 *
 * If program dies because of SEGV, this handler catches it and dies properly.
 * It instructs user to report it, because this behavior is a bug.
 */
void segv_interrupt(int dummy) {
    (void)dummy;
    fatal("Unexpected error (SEGV), please report it. More info at man page. Exiting.\n");
    exit(ESTATUS_OPERATIONAL_ERROR);
}

/**
 * \brief Bus error handler
 *
 * If program dies because of SIGBUS, this handler catches it and dies properly.
 * It instructs user to report it, because this behavior is a bug.
 */
void sigbus_interrupt(int dummy) {
    (void)dummy;
    fatal("Medium changed size during fsck run. Is somebody manipulating it? Exiting.\n");
    exit(ESTATUS_OPERATIONAL_ERROR);
}

/**
 * \brief Return non-zero when error found in any generic descriptor (e.g. not in filetree)
 *
 * \param[in] seq Error sequence structure
 *
 * \return 0 all descriptors are Ok
 */
int any_error(vds_sequence_t *seq) {
    int status = 0;

    status |= seq->anchor[0].error;
    status |= seq->anchor[1].error;
    if(seq->anchor[2].error != 255)
        status |= seq->anchor[2].error;
    status |= seq->lvid.error;
    status |= seq->pd.error;

    for(int i=0; i<VDS_STRUCT_AMOUNT; ++i) {
        status |= seq->main[MAIN_VDS].error;
        status |= seq->main[RESERVE_VDS].error;
    }

    return status;
}

#define ES_AVDP1 0x0001 
#define ES_AVDP2 0x0002
#define ES_PD    0x0004
#define ES_LVID  0x0008

static void integrity_msg(const char* label, const char* valueFormat,
                          uint64_t lvidValue, uint64_t calcValue,
                          int bPrintLVID)
{
    static char lvidText[32];
    static char calcText[32];

    static char msgBuf[128];

    if (bPrintLVID)
    {
        if (strcmp(valueFormat, "%s") == 0)
            snprintf(lvidText, sizeof(lvidText), valueFormat, (const char*) lvidValue);
        else
            snprintf(lvidText, sizeof(lvidText), valueFormat, lvidValue);
    }
    else
        lvidText[0] = '\0';

    if (!bPrintLVID || !fast_mode) {
        if (strcmp(valueFormat, "%s") == 0)
            snprintf(calcText, sizeof(calcText), valueFormat, (const char*) calcValue);
        else
            snprintf(calcText, sizeof(calcText), valueFormat, calcValue);
    } else
        calcText[0] = '\0';

    if (bPrintLVID)
    {
        const char* diffFlag = "";
        if (bPrintLVID && !fast_mode && (strcmp(valueFormat, "%s") != 0) && (calcValue != lvidValue))
            diffFlag = "<--";

        msg("%-20s%10s  %10s %s\n", label, lvidText, calcText, diffFlag);
    }
    else
        msg("%-20s%10s\n", label, calcText);
}

/**
 * \brief **udffsck** entry point
 *
 * This is entry point for **udffsck**. It contains structure of whole tool and calls 
 * functions in udffsck.c
 *
 * It accepts inputs via argv.
 *
 * \return 0 -- No error
 * \return 1 -- Filesystem errors were fixed
 * \return 2 -- Filesystem errors were fixed, reboot is recommended (Unsupported)
 * \return 4 -- Filesystem errors remain unfixed
 * \return 8 -- Program error
 * \return 16 -- Wrong input parameters
 * \return 32 -- Check was interrupted by user request
 * \return 128 -- Shared library error (Unsupported)
 */
int main(int argc, char *argv[]) {
    char *path = NULL;
    udf_media_t media;
    FILE *fp;
    int status = 0;
    struct stat stat;
    vds_sequence_t *seq; 
    struct filesystemStats stats;
    uint16_t error_status = 0;
    uint16_t fix_status = 0;
    int force_sectorsize = 0;
    int third_avdp_missing = 0;
    struct sigaction new_action;
    int source = -1;

    memset(&media, 0, sizeof(media));
    media.sectorsize = -1;

    memset(&stats, 0, sizeof(struct filesystemStats));
    stats.found.nextUID = 0x10;     // Min valid unique ID
    stats.found.maxUDFWriteRev = MAX_VERSION;

    sigemptyset (&new_action.sa_mask);
    new_action.sa_flags = 0;

    new_action.sa_handler = user_interrupt;
    sigaction (SIGINT, &new_action, NULL);

    new_action.sa_handler = sigbus_interrupt;
    sigaction (SIGBUS, &new_action, NULL);

#ifndef DEBUG //if debugging, we want Address Sanitizer to catch those
    new_action.sa_handler = segv_interrupt;
    sigaction (SIGSEGV, &new_action, NULL);
#endif

    parse_args(argc, argv, &path, &media.sectorsize);
#ifdef MEMTRACE
    dbg("Path: %p\n", path);    
#endif

    note("Verbose: %d, Autofix: %d, Interactive: %d\n", verbosity, autofix, interactive);
    if(fast_mode)
        warn("Fast mode active. File tree checks will be skipped if rest of filesystem is clean.\n");

    if(path == NULL) {
        err("No medium given. Use -h for help.\n");
        exit(ESTATUS_USAGE);
    }

    if (media.sectorsize > 0) {
        force_sectorsize = 1;
    }

    msg("Medium to analyze: %s\n", path);

    /* TODO remove. Replaced by check during opening
    //Check if medium is mounted or not
    FILE* mtab = setmntent("/proc/mounts", "r");
    struct mntent* m;
    struct mntent mnt;
    char strings[4096];
    while ((m = getmntent_r(mtab, &mnt, strings, sizeof(strings)))) {
    dbg("%s\n", mnt.mnt_fsname);
    if(strcmp(mnt.mnt_fsname, path) == 0) { //Match
    err("Medium is mounted, therefore cannot be checked. Exiting.\n");
    exit(ESTATUS_USAGE);
    }
    }

    endmntent(mtab);
    */

    int flags = O_RDONLY;
    // If is there some request for corrections, we need read/write access to medium
    if(interactive || autofix) {
        flags = O_RDWR;
        dbg("RW\n");
    }

    media.fd = open(path, flags, 0660);
    if (media.fd == -1) {
        fatal("Error opening %s: %s.", path, strerror(errno));
        exit(ESTATUS_USAGE);
    } else {
        int fd2;
        int flags2;
        char filename2[64];
        const char *error;

        if (fstat(media.fd, &stat) != 0) {
            fatal("Cannot stat device '%s': %s\n", path, strerror(errno));
            exit(ESTATUS_USAGE);
        }

        flags2 = flags; 
        if (snprintf(filename2, sizeof(filename2), "/proc/self/fd/%d", media.fd) >= (int)sizeof(filename2))
        {
            fatal("Cannot open device '%s': %s\n", path, strerror(ENAMETOOLONG));
            exit(ESTATUS_USAGE);
        }

        // Re-open block device with O_EXCL mode which fails when device is already mounted
        if (S_ISBLK(stat.st_mode))
            flags2 |= O_EXCL;

        fd2 = open(filename2, flags2);
        if (fd2 < 0)
        {
            if (errno != ENOENT)
            {
                error = (errno != EBUSY) ? strerror(errno) : "Device is mounted or udffsck is already running";
                fatal("Cannot open device '%s': %s\n", path, error);
                exit(ESTATUS_USAGE);
            }

            // Fallback to original filename when /proc is not available,
            // but this introduces a race condition between stat and open
            fd2 = open(path, flags2);
            if (fd2 < 0)
            {
                error = (errno != EBUSY) ? strerror(errno) : "Device is mounted or udffsck is already running";
                fatal("Cannot open device '%s': %s\n", path, error);
                exit(ESTATUS_USAGE);
            }
        }

        close(media.fd);
        media.fd = fd2;

    }

    if((fp = fopen(path, "r")) == NULL) {
        fatal("Error opening %s: %s.", path, strerror(errno));
        exit(ESTATUS_USAGE);
    }

    // Lock medium to ensure no-one is going to change during our operation.
    // Make nonblocking, so it will fail when medium is already locked.
    if (flock(media.fd, LOCK_EX | LOCK_NB)) {
        fatal("Error locking %s, %s. Is another process using it?\n", path, strerror(errno));
        exit(ESTATUS_USAGE);
    }

    note("FD: 0x%x\n", media.fd);

    if(fseeko(fp, 0 , SEEK_END) != 0) {
        if(errno == EBADF) {
            err("Medium is not seekable. Aborting.\n");
            exit(ESTATUS_USAGE);
        } else {
            err("Unknown seek error (errno: %d). Aborting.\n", errno);
            exit(ESTATUS_USAGE);
        }
    } 
    media.devsize = ftello(fp);
    dbg("Size: 0x%" PRIx64 "\n", media.devsize);

    uint32_t chunksize = CHUNK_SIZE;
    uint32_t rest       = (uint32_t) media.devsize % chunksize;
    uint32_t num_chunks = (uint32_t) ((media.devsize / chunksize) + (rest > 0 ? 1 : 0));
    dbg("Chunk size %u, rest: %u\n", chunksize, rest);
    media.mapping = calloc(sizeof(uint8_t *), num_chunks);
    dbg("Amount of chunks: %u\n", num_chunks);
    for(uint32_t i=0; i<num_chunks; i++) {
        media.mapping[i] = NULL;
    }

    //------------- Detections -----------------------

    seq = calloc(1, sizeof(vds_sequence_t));

    stats.AVDPSerialNum = 0xFFFF;
    status = is_udf(&media, force_sectorsize, &stats); // Check for UDF recognition sequence. Also tries to detect blocksize.
    if(status < 0) {
        exit(status);
    } else if(status == 1) { //Unclosed or bridged medium 
        status = get_avdp(&media, -1, force_sectorsize, &stats); // load AVDP and verify blocksize
        source = FIRST_AVDP; // Unclosed medium has only one AVDP and that is saved at first position.
        if(status) {
            err("AVDP is broken. Aborting.\n");
            exit(ESTATUS_UNCORRECTED_ERRORS);
        }
    } else { //Normal medium
        seq->anchor[0].error = get_avdp(&media, FIRST_AVDP, force_sectorsize, &stats); //try load FIRST AVDP
        if(seq->anchor[0].error) {
            err("AVDP[0] is broken.\n");
        } else {
            force_sectorsize = 1;
        }

        seq->anchor[1].error = get_avdp(&media, SECOND_AVDP, force_sectorsize, &stats); //load AVDP
        if(seq->anchor[1].error) {
            err("AVDP[1] is broken.\n");
        } else {
            force_sectorsize = 1;
        }

        seq->anchor[2].error = get_avdp(&media, THIRD_AVDP, force_sectorsize, &stats); //load AVDP
        if(seq->anchor[2].error) {
            dbg("AVDP[2] somehow errored, not necessarily a bad thing.\n");
            if(seq->anchor[2].error < 255) { //Third AVDP is not necessarily present.
                err("AVDP[2] is broken.\n");
            } else {
                third_avdp_missing = 1;
            }
        }

        if((seq->anchor[0].error & ~E_EXTLEN) == 0) {
            dbg("FIRST AVDP as source\n");
            source = FIRST_AVDP;
        } else if((seq->anchor[1].error & ~E_EXTLEN) == 0) {
            dbg("SECOND AVDP as source\n");
            source = SECOND_AVDP;
        } else if((seq->anchor[2].error & ~E_EXTLEN) == 0 && third_avdp_missing == 0) {
            dbg("THIRD AVDP as source\n");
            source = THIRD_AVDP;
        } else {
            if(force_sectorsize)
                err("All AVDP are broken or wrong block size was entered. Try running without -b option. Aborting.\n");
            else
                err("All AVDP are broken. Aborting.\n");
            exit(ESTATUS_UNCORRECTED_ERRORS);
        }
    }

    msg("Sectorsize: %d\n", media.sectorsize);

    if (media.sectorsize == -1) {
        err("Device blocksize is not defined. Please define it with -b BLOCKSIZE parameter\n");
        exit(ESTATUS_USAGE);
    }

    // Correct blocksize MUST be blocksize%512 == 0. We keep definitive list for now.
    switch (media.sectorsize) {
        case 512:
        case 1024:
        case 2048:
        case 4096:
    	    break;

        default:
            err("Invalid blocksize. Supported values are 512, 1024, 2048, and 4096.\n");
            exit(ESTATUS_USAGE);
    }

    note("\nTrying to load first VDS\n");
    status |= get_vds(&media, source, MAIN_VDS, seq); //load main VDS
    note("\nTrying to load second VDS\n");
    status |= get_vds(&media, source, RESERVE_VDS, seq); //load reserve VDS

    dbg("First VDS verification\n");
    verify_vds(&media.disc, MAIN_VDS, seq, &stats);
    dbg("Second VDS verification\n");
    verify_vds(&media.disc, RESERVE_VDS, seq, &stats);

    //Check if blocksize matches. If not, exit.
    int blocksize_status = check_blocksize(&media, force_sectorsize, seq);
    if(blocksize_status != ESTATUS_OK)
        exit(status | blocksize_status);


    integrity_info_t *lvid = &stats.lvid;
    status |= get_lvid(&media, lvid, seq);
    if(lvid->minUDFReadRev > MAX_VERSION){
        err("Medium UDF revision is %04x and we are able to check up to %04x\n",
            lvid->minUDFReadRev, MAX_VERSION);
        exit(ESTATUS_OPERATIONAL_ERROR);
    }

#ifdef PRINT_DISC
    print_disc(&media.disc);
#endif

    stats.blocksize = media.sectorsize;

    if (get_pd(&media, &stats, seq)) {
        err("PD error\n");
        exit(ESTATUS_OPERATIONAL_ERROR);
    }

    uint32_t lbnlsn = 0;
    dbg("STATUS: 0x%02x\n", status);
    status |= get_fsd(&media, &lbnlsn, &stats, seq);
    dbg("STATUS: 0x%02x\n", status);
    if(status >= ESTATUS_OPERATIONAL_ERROR) {
        err("Unable to continue without FSD. Consider submitting a bug report. Exiting.\n");
        exit(status);
    } else if(status >= ESTATUS_UNCORRECTED_ERRORS) {
        err("Unable to continue without FSD. Medium seems unrecoverable. Exiting.\n");
        exit(status);
    }

    note("LBNLSN: %u\n", lbnlsn);
    if (any_error(seq) || (media.disc.udf_lvid->integrityType != LVID_INTEGRITY_TYPE_CLOSE) || !fast_mode) {
        status |= get_file_structure(&media, lbnlsn, &stats, seq);
    }

    dbg("PD PartitionsContentsUse\n");
    for(int i=0; i<128; ) {
        for(int j=0; j<8; j++, i++) {
            note("%02x ", media.disc.udf_pd[0]->partitionContentsUse[i]);
        }
        note("\n");
    }

    integrity_info_t *found = &stats.found;
    int lvid_invalid = seq->lvid.error & (E_CRC | E_CHECKSUM | E_WRONGDESC);

    //---------- Corrections --------------
    msg("\nFilesystem status\n-----------------\n");
    get_volume_identifier(&media.disc, &stats, seq);
    msg("Volume set identifier: %s\n", stats.volumeSetIdent);
    msg("Partition identifier: %s\n", stats.partitionIdent);

    uint64_t lvidUsedBlocks  = lvid->partitionNumBlocks  - lvid->freeSpaceBlocks;
    uint64_t foundUsedBlocks = found->partitionNumBlocks - found->freeSpaceBlocks;

    integrity_msg("\n", "%s", (uint64_t) "Recorded",   (uint64_t) "Calculated", !lvid_invalid);
    integrity_msg("",   "%s", (uint64_t) "----------", (uint64_t) "----------", !lvid_invalid);

    integrity_msg("Next unique ID:",     "%" PRIu64,   lvid->nextUID,            found->nextUID,            !lvid_invalid);
    integrity_msg("# files:",            "%" PRIu64,   lvid->numFiles,           found->numFiles,           !lvid_invalid);
    integrity_msg("# directories:",      "%" PRIu64,   lvid->numDirs,            found->numDirs,            !lvid_invalid);
    integrity_msg("UDF rev: min read:",  "%04" PRIx64, lvid->minUDFReadRev,      found->minUDFReadRev,      !lvid_invalid);
    integrity_msg(".........min write:", "%04" PRIx64, lvid->minUDFWriteRev,     found->minUDFWriteRev,     !lvid_invalid);
    integrity_msg(".........max write:", "%04" PRIx64, lvid->maxUDFWriteRev,     found->maxUDFWriteRev,     !lvid_invalid);
    integrity_msg("Partition blocks:",   "%" PRIu64,   lvid->partitionNumBlocks, found->partitionNumBlocks, !lvid_invalid);
    integrity_msg("............free:",   "%" PRIu64,   lvid->freeSpaceBlocks,    found->freeSpaceBlocks,    !lvid_invalid);
    integrity_msg("............used:",   "%" PRIu64,   lvidUsedBlocks,           foundUsedBlocks,           !lvid_invalid);

    if (lvid->numDirs != found->numDirs || lvid->numFiles != found->numFiles) {
        seq->lvid.error |= E_FILES;
    }

    msg("\n");
    if (!fast_mode && (stats.partitionAccessType != PD_ACCESS_TYPE_READ_ONLY)) {
        msg("Space descriptor used blocks: %u\n", get_used_blocks(&stats.spacedesc));
        msg(".................free blocks: %u\n", stats.spacedesc.freeSpaceBlocks);
        msg("\n");

        if (!lvid_invalid) {
            int32_t lvidFreeDiff = stats.lvid.freeSpaceBlocks - stats.found.freeSpaceBlocks;
            if (lvidFreeDiff < 0) {
                err("%" PRId64 " blocks are free but counted as allocated in Free Space Table.\n", -lvidFreeDiff);
                err("Correct free space: %" PRId64 "\n", stats.found.freeSpaceBlocks);
                seq->lvid.error |= E_FREESPACE;
            } else if (lvidFreeDiff > 0) {
                err("%" PRId64 " blocks are allocated but counted as free in Free Space Table.\n", lvidFreeDiff);
                err("Correct free space: %" PRId64 "\n", stats.found.freeSpaceBlocks);
                seq->lvid.error |= E_FREESPACE;
            }
        }

        int64_t spaceDescDiffBlocks = get_used_blocks(&stats.spacedesc) - get_used_blocks(&stats.found);
        if (spaceDescDiffBlocks > 0) {
            err("%" PRId64 " blocks are unused but marked as allocated in SBD.\n", spaceDescDiffBlocks);
            seq->pd.error |= E_FREESPACE;
        } else if (spaceDescDiffBlocks < 0) {
            err("%" PRId64 " blocks are used but marked as unallocated in SBD.\n", -spaceDescDiffBlocks);
            seq->pd.error |= E_FREESPACE;
        }
    }

    status |= dstring_error("FSD, Logical Volume Identifier", stats.dstringFSDLogVolIdentErr);
    status |= dstring_error("FSD, File Set Identifier", stats.dstringFSDFileSetIdentErr);
    status |= dstring_error("FSD, Copyright File Identifier", stats.dstringFSDCopyrightFileIdentErr);
    status |= dstring_error("FSD, Abstract File Identifier", stats.dstringFSDAbstractFileIdentErr);

    status |= dstring_error("PVD, Main VDS, Volume Identifier", stats.dstringPVDVolIdentErr[MAIN_VDS]);
    status |= dstring_error("PVD, Main VDS, Volume Set Identifier", stats.dstringPVDVolSetIdentErr[MAIN_VDS]);
    status |= dstring_error("LVD, Main VDS, Logical Volume Identifier", stats.dstringLVDLogicalVolIdentErr[MAIN_VDS]);
    status |= dstring_error("IUVD, Main VDS, Logical Volume Info 1", stats.dstringIUVDLVInfo1Err[MAIN_VDS]);
    status |= dstring_error("IUVD, Main VDS, Logical Volume Info 2", stats.dstringIUVDLVInfo2Err[MAIN_VDS]);
    status |= dstring_error("IUVD, Main VDS, Logical Volume Info 3", stats.dstringIUVDLVInfo3Err[MAIN_VDS]);
    status |= dstring_error("IUVD, Main VDS, Logical Volume Identifier", stats.dstringIUVDLogicalVolIdentErr[MAIN_VDS]);
     
    status |= dstring_error("PVD, Reserve VDS, Volume Identifier", stats.dstringPVDVolIdentErr[RESERVE_VDS]);
    status |= dstring_error("PVD, Reserve VDS, Volume Set Identifier", stats.dstringPVDVolSetIdentErr[RESERVE_VDS]);
    status |= dstring_error("LVD, Reserve VDS, Logical Volume Identifier", stats.dstringLVDLogicalVolIdentErr[RESERVE_VDS]);
    status |= dstring_error("IUVD, Reserve VDS, Logical Volume Info 1", stats.dstringIUVDLVInfo1Err[RESERVE_VDS]);
    status |= dstring_error("IUVD, Reserve VDS, Logical Volume Info 2", stats.dstringIUVDLVInfo2Err[RESERVE_VDS]);
    status |= dstring_error("IUVD, Reserve VDS, Logical Volume Info 3", stats.dstringIUVDLVInfo3Err[RESERVE_VDS]);
    status |= dstring_error("IUVD, Reserve VDS, Logical Volume Identifier", stats.dstringIUVDLogicalVolIdentErr[RESERVE_VDS]);

    if(seq->anchor[0].error + seq->anchor[1].error + seq->anchor[2].error != 0) { //Something went wrong with AVDPs
        int target1 = -1;
        int target2 = -1;

        if((seq->anchor[0].error & ~E_EXTLEN) == 0) {
            source = FIRST_AVDP;
            if((seq->anchor[1].error & ~E_EXTLEN) != 0)
                target1 = SECOND_AVDP;
            if((seq->anchor[2].error & ~E_EXTLEN) != 0 && third_avdp_missing == 0)
                target2 = THIRD_AVDP;
        } else if((seq->anchor[1].error & ~E_EXTLEN) == 0) {
            source = SECOND_AVDP;
            target1 = FIRST_AVDP;
            if((seq->anchor[2].error & ~E_EXTLEN) != 0 && third_avdp_missing == 0)
                target2 = THIRD_AVDP;
        } else if((seq->anchor[2].error & ~E_EXTLEN) == 0 && third_avdp_missing == 0) {
            source = THIRD_AVDP;
            target1 = FIRST_AVDP;
            target2 = SECOND_AVDP;
        } else {
            err("Unrecoverable AVDP failure. Aborting.\n");
            exit(ESTATUS_UNCORRECTED_ERRORS);
        }

        if(target1 >= 0)
            error_status |= ES_AVDP1;

        if(target2 >= 0)
            error_status |= ES_AVDP2;

        int fixavdp = 0;
        if(interactive) {
            if(prompt("Found AVDP error(s). Do you want to fix them? [Y/n]") != 0) {
                fixavdp = 1;
            }
        }
        if(autofix)
            fixavdp = 1;


        if(fixavdp) {
            msg("Source: %d, Target1: %d, Target2: %d\n", source, target1, target2);
            if(target1 >= 0) {
                if (write_avdp(&media, source, target1) != 0) {
                    fatal("AVDP recovery failed. Is medium writable?\n");
                } else {
                    imp("AVDP recovery was successful.\n");
                    error_status &= ~ES_AVDP1;
                    fix_status |= ES_AVDP1;
                } 
            } 
            if(target2 >= 0) {
                if (write_avdp(&media, source, target2) != 0) {
                    fatal("AVDP recovery failed. Is medium writable?\n");
                } else {
                    imp("AVDP recovery was successful.\n");
                    error_status &= ~ES_AVDP2;
                    fix_status |= ES_AVDP2;
                }
            }
        }

        if(fixavdp) {
            if(seq->anchor[0].error & E_EXTLEN) {
                status |= fix_avdp(&media, FIRST_AVDP);
            }
            if(seq->anchor[1].error & E_EXTLEN) {
                status |= fix_avdp(&media, SECOND_AVDP);
            }
            if((seq->anchor[2].error & E_EXTLEN) && third_avdp_missing == 0) {
                status |= fix_avdp(&media, THIRD_AVDP);
            }
        }
    }


    print_metadata_sequence(seq);

    status |= fix_vds(&media, source, seq);

    int fixlvid = 0;
    int fixpd = 0;
    int lviderr = lvid_invalid;
    if(found->nextUID > lvid->nextUID || (seq->lvid.error & E_UUID)) {
        err("Max found Unique ID is same or bigger that Unique ID found at LVID.\n");
        lviderr = 1;
    }
    if (media.disc.udf_lvid->integrityType != LVID_INTEGRITY_TYPE_CLOSE) {
        //There are some unfinished writes
        err("Opened integrity type. Some writes may be unfinished.\n");
        lviderr = 1;
    }
    if(seq->lvid.error & E_TIMESTAMP) {
        err("LVID timestamp is older than timestamps of files.\n");
        lviderr=1;
    }
    if(seq->lvid.error & E_FILES) {
        err("Number of files or directories is not corresponding to counted number\n");
        lviderr=1;
    }
    if(seq->lvid.error & E_FREESPACE) {
        err("Free Space table is not corresponding to reality.\n");
        lviderr=1;
    }

    if(lviderr) {
        error_status |= ES_LVID;
        if(interactive) {
            if(prompt("Fix it? [Y/n]") != 0) {
                fixlvid = 1;
            }
        }
        if(autofix)
            fixlvid = 1;
    }

    if(seq->pd.error != 0) {
        error_status |= ES_PD;
        if(interactive) {
            if(prompt("Fix SBD? [Y/n]") != 0)
                fixpd = 1;
        }
        if(autofix)
            fixpd = 1;
    }


    if(fixlvid == 1) {
        if (fix_lvid(&media, &stats, seq) == 0) {
            error_status &= ~(ES_LVID | ES_PD); 
            fix_status |= (ES_LVID | ES_PD);
        }
    } else if(fixlvid == 0 && fixpd == 1) {
        if (fix_pd(&media, &stats, seq) == 0) {
            error_status &= ~(ES_PD); 
            fix_status |= ES_PD;
        }
    }

#if DEBUG && 0
    note("\n ACT \t EXP\n");
    uint32_t shift = 0;
    uint32_t line = 0;
    uint32_t amount = 50000;
    for(int i=0+shift, k=0+shift; i<stats.partitionNumBlocks/8 && i < amount+shift; ) {
        note("[%04u] ",line++);
        for(int j=0; j<16; j++, i++) {
            note("%02x ", stats.actPartitionBitmap[i]);
        }
        note("| "); 
        for(int j=0; j<16; j++, k++) {
            note("%02x ", stats.expPartitionBitmap[k]);
        }
        note("\n");
    }
#endif

    //---------------- Error & Fix Status -------------
    if(error_status != 0) {
        status |= ESTATUS_UNCORRECTED_ERRORS; //Errors remained unfixed
    }

    if(fix_status != 0) {
        status |= ESTATUS_CORRECTED_ERRORS; // Errors were fixed
    }

    if(status <= ESTATUS_CORRECTED_ERRORS) {
        msg("Filesystem clean.\n");
    }
    else if(status == ESTATUS_CORRECTED_ERRORS) {
        msg("Filesystem errors were fixed.\n");
    }
    //---------------- Clean up -----------------

    note("Clean allocations\n");
    free(media.mapping);

    free(media.disc.udf_anchor[0]);
    free(media.disc.udf_anchor[1]);
    free(media.disc.udf_anchor[2]);

    free(media.disc.udf_pvd[0]);
    free(media.disc.udf_lvd[0]);
    free(media.disc.udf_usd[0]);
    free(media.disc.udf_iuvd[0]);
    free(media.disc.udf_pd[0]);
    free(media.disc.udf_td[0]);

    free(media.disc.udf_pvd[1]);
    free(media.disc.udf_lvd[1]);
    free(media.disc.udf_usd[1]);
    free(media.disc.udf_iuvd[1]);
    free(media.disc.udf_pd[1]);
    free(media.disc.udf_td[1]);

    free(media.disc.udf_lvid);
    free(media.disc.udf_fsd);

    free(seq);
    free(stats.actPartitionBitmap);
    free(stats.volumeSetIdent);
    free(stats.partitionIdent);

    flock(media.fd, LOCK_UN);
    close(media.fd);
    fclose(fp);

    msg("All done\n");
    return status;
}
