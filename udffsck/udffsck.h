/*
 * udffsck.h
 *
 * Copyright (c) 2016    Vojtech Vladyka <vojtch.vladyka@gmail.com>
 * All rights reserved.
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
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
#define CHUNK_SIZE ((uint32_t)0x800000) ///< Chunk size for using

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

struct filesystemStats {
    uint16_t blocksize;
    uint64_t actUUID;
    uint64_t maxUUID;
    uint32_t expNumOfFiles;
    uint32_t countNumOfFiles;
    uint32_t expNumOfDirs;
    uint32_t countNumOfDirs;
    uint16_t minUDFReadRev;
    uint16_t minUDFWriteRev;
    uint16_t maxUDFWriteRev;
    uint16_t AVDPSerialNum;
    uint64_t usedSpace;
    uint32_t freeSpaceBlocks;
    uint32_t partitionSizeBlocks;
    uint32_t expUsedBlocks;
    uint32_t expUnusedBlocks;
    uint32_t partitionNumOfBytes;
    uint32_t partitionNumOfBits;
    uint8_t * actPartitionBitmap;
    uint8_t * expPartitionBitmap;
    timestamp LVIDtimestamp;
    dstring * partitionIdent;
    char * volumeSetIdent;
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

// Support functions
char * print_timestamp(timestamp ts);
uint64_t count_used_bits(struct filesystemStats *stats);
int get_volume_identifier(struct udf_disc *disc, struct filesystemStats *stats, vds_sequence_t *seq );
void unmap_chunk(uint8_t **dev, uint32_t chunk, size_t st_size);
void map_chunk(int fd, uint8_t **dev, uint32_t chunk, size_t st_size);

// UDF detection
int is_udf(int fd, uint8_t **dev, int *sectorsize, size_t st_size, int force_sectorsize);
int get_avdp(int fd, uint8_t **dev, struct udf_disc *disc, int *sectorsize, size_t devsize, avdp_type_e type, int force_sectorsize, struct filesystemStats *stats);
int write_avdp(uint8_t *dev, struct udf_disc *disc, size_t sectorsize, size_t devsize,  avdp_type_e source, avdp_type_e target);
int fix_avdp(uint8_t *dev, struct udf_disc *disc, size_t sectorsize, size_t devsize,  avdp_type_e target);

// VDS functions
int get_vds(int fd, uint8_t **dev, struct udf_disc *disc, int sectorsize, size_t st_size, avdp_type_e avdp, vds_type_e vds, vds_sequence_t *seq);
int verify_vds(struct udf_disc *disc, vds_type_e vds, vds_sequence_t *seq);
int fix_vds(uint8_t *dev, struct udf_disc *disc, size_t sectorsize, avdp_type_e source, vds_sequence_t *seq/*, uint8_t interactive, uint8_t autofix*/); 

// LVID functions
int get_lvid(uint8_t *dev, struct udf_disc *disc, int sectorsize, struct filesystemStats *stats, vds_sequence_t *seq);
int fix_lvid(uint8_t *dev, struct udf_disc *disc, size_t sectorsize, struct filesystemStats *stats, vds_sequence_t *seq);

// PD (SBD) functions
int get_pd(uint8_t *dev, struct udf_disc *disc, size_t sectorsize, struct filesystemStats *stats, vds_sequence_t *seq); 
int fix_pd(uint8_t *dev, struct udf_disc *disc, size_t sectorsize, struct filesystemStats *stats, vds_sequence_t *seq);

// Filetree functions
uint8_t get_fsd(uint8_t *dev, struct udf_disc *disc, int sectorsize, uint32_t *lbnlsn, struct filesystemStats * stats, vds_sequence_t *seq);
uint8_t get_file_structure(const uint8_t *dev, const struct udf_disc *disc, uint32_t lbnlsn, struct filesystemStats *stats, vds_sequence_t *seq );

#endif //__UDFFSCK_H__
