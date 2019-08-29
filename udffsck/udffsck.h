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

#ifndef __UDFFSCK_H__
#define __UDFFSCK_H__

#include "config.h"

#include <ecma_167.h>
#include <libudffs.h>

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

#define UDFFSCK_VERSION "1.0-beta" ///< **udffsck** version number

#define VDS_STRUCT_AMOUNT 8 ///< Maximum amount of VDS descriptors 
#define BLOCK_SIZE 2048 ///< Minimal VRS search block size
#define CHUNK_SIZE ((uint32_t)0x800000) ///< mmap() the device in multiples of this many bytes

// Exit status bitmask
#define ESTATUS_OK                         0
#define ESTATUS_CORRECTED_ERRORS           (1U << 0)  // 1
#define ESTATUS_UNCORRECTED_ERRORS         (1U << 2)  // 4
#define ESTATUS_OPERATIONAL_ERROR          (1U << 3)  // 8
#define ESTATUS_USAGE                      (1U << 4)  // 16
#define ESTATUS_USER_CANCEL                (1U << 5)  // 32

typedef enum {
    FIRST_AVDP = 0, 
    SECOND_AVDP,    
    THIRD_AVDP,
} avdp_type_e;

typedef enum {
    MAIN_VDS = 0,
    RESERVE_VDS,
} vds_type_e;

typedef struct {
    uint16_t tagIdent;      ///< descriptor identifier
    uint32_t tagLocation;   ///< descriptor declared position
    uint8_t error;          ///< errors found on descriptor
} metadata_t;

typedef struct {
    metadata_t anchor[3];
    metadata_t main[VDS_STRUCT_AMOUNT];
    metadata_t reserve[VDS_STRUCT_AMOUNT];   
    metadata_t lvid;
    metadata_t pd;
} vds_sequence_t;

typedef struct {
    uint16_t flags;
    uint32_t lsn;
    uint32_t blocks;
    uint32_t size;
} file_t;

typedef struct {
    uint64_t  nextUID;
    uint16_t  minUDFReadRev;
    uint16_t  minUDFWriteRev;
    uint16_t  maxUDFWriteRev;
    uint32_t  numFiles;
    uint32_t  numDirs;
    uint32_t  freeSpaceBlocks;
    uint32_t  partitionNumBlocks;
    timestamp recordedTime;

} integrity_info_t;

typedef struct {
    int             fd;          // File descriptor for mmapped access to media
    uint8_t       **mapping;     // mmapped chunks of the media
    struct udf_disc disc;
    uint64_t        devsize;     // Size of the whole device in bytes
    int             sectorsize;
} udf_media_t;

struct filesystemStats {
    uint64_t blocksize;  // This is 64 bits to simplify block->byte conversions
    uint16_t AVDPSerialNum;
    uint32_t partitionAccessType;
    uint8_t * actPartitionBitmap;
    uint8_t * expPartitionBitmap;
    char * partitionIdent;
    char * volumeSetIdent;
    uint8_t dstringFSDLogVolIdentErr;
    uint8_t dstringFSDFileSetIdentErr;
    uint8_t dstringFSDCopyrightFileIdentErr;
    uint8_t dstringFSDAbstractFileIdentErr;
    uint8_t dstringPVDVolIdentErr[VDS_STRUCT_AMOUNT];
    uint8_t dstringPVDVolSetIdentErr[VDS_STRUCT_AMOUNT];
    uint8_t dstringLVDLogicalVolIdentErr[VDS_STRUCT_AMOUNT];
    uint8_t dstringIUVDLVInfo1Err[VDS_STRUCT_AMOUNT];
    uint8_t dstringIUVDLVInfo2Err[VDS_STRUCT_AMOUNT];
    uint8_t dstringIUVDLVInfo3Err[VDS_STRUCT_AMOUNT];
    uint8_t dstringIUVDLogicalVolIdentErr[VDS_STRUCT_AMOUNT];

    integrity_info_t lvid;      // Information from recorded LVID
    integrity_info_t spacedesc; // Information from recorded space descriptor (if any)
    integrity_info_t found;     // Calculated
};

struct fileInfo {
    char * filename;
    uint8_t fileCharacteristics;
    uint8_t fileType;
    uint32_t permissions;
    uint64_t size;
    uint16_t FIDSerialNum;
    timestamp modTime;
};

// Implementation Use for Logical Volume Integrity Descriptor (ECMA 167r3 3/10.10, UDF 2.2.6.4)
struct impUseLVID {
    regid impID;
    uint32_t numOfFiles;
    uint32_t numOfDirs;
    uint16_t minUDFReadRev;
    uint16_t minUDFWriteRev;
    uint16_t maxUDFWriteRev;
    uint8_t  impUse[0]; 
} __attribute__ ((packed));

#define E_CHECKSUM      0b00000001
#define E_CRC           0b00000010
#define E_POSITION      0b00000100
#define E_WRONGDESC     0b00001000
#define E_UUID          0b00010000
#define E_TIMESTAMP     0b00100000
#define E_FREESPACE     0b01000000
#define E_FILES         0b10000000
#define E_EXTLEN        0b10000000 //AVDP specific

#define DSTRING_E_NONZERO_PADDING       0x01
#define DSTRING_E_WRONG_LENGTH          0x02
#define DSTRING_E_INVALID_CHARACTERS    0x04
#define DSTRING_E_NOT_EMPTY             0x08
#define DSTRING_E_UNKNOWN_COMP_ID       0x10

// Support functions
char * print_timestamp(timestamp ts);
uint32_t get_used_blocks(const integrity_info_t *info);
int get_volume_identifier(struct udf_disc *disc, struct filesystemStats *stats, vds_sequence_t *seq );
void unmap_chunk(udf_media_t *media, uint32_t chunk);
void map_chunk(udf_media_t *media, uint32_t chunk, char * file, int line);

// UDF detection
int is_udf(udf_media_t* media, int force_sectorsize, struct filesystemStats *stats);
int get_avdp(udf_media_t *media, avdp_type_e type, int force_sectorsize,
             struct filesystemStats *stats);
int write_avdp(udf_media_t *media, avdp_type_e source, avdp_type_e target);
int fix_avdp(udf_media_t *media, avdp_type_e target);

// VDS functions
int get_vds(udf_media_t *media, avdp_type_e avdp, vds_type_e vds, vds_sequence_t *seq);
int verify_vds(struct udf_disc *disc, vds_type_e vds, vds_sequence_t *seq, struct filesystemStats *stats);
int fix_vds(udf_media_t *media, avdp_type_e source, vds_sequence_t *seq);

// LVID functions
int get_lvid(udf_media_t *media, integrity_info_t *info, vds_sequence_t *seq );
int fix_lvid(udf_media_t *media, struct filesystemStats *stats, vds_sequence_t *seq);

// PD (SBD) functions
int get_pd(udf_media_t *media, struct filesystemStats *stats, vds_sequence_t *seq);
int fix_pd(udf_media_t *media, struct filesystemStats *stats, vds_sequence_t *seq);

// Filetree functions
uint8_t get_fsd(udf_media_t *media, uint32_t *lbnlsn, struct filesystemStats * stats, vds_sequence_t *seq);
uint8_t get_file_structure(udf_media_t *media, uint32_t lbnlsn, struct filesystemStats *stats, vds_sequence_t *seq );

// Check for match on blocksize
int check_blocksize(udf_media_t *media, int force_sectorsize, vds_sequence_t *seq);

// Check and correct d-string
uint8_t check_dstring(dstring *in, size_t field_size);
uint8_t dstring_error(char * string_name, uint8_t e_code);

#endif //__UDFFSCK_H__
