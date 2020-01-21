/* 
 * Copyright (c) 2019 Nuvoton Technology Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mbed.h"
#include "mbedtls/config.h"
#include "entropy_poll.h"
#include "psa/crypto.h"
#include "kvstore_global_api.h"
#include "KVStore.h"
#include "TDBStore.h"
#include "KVMap.h"
#include "kv_config.h"
#include "DeviceKey.h"
#if MBED_CONF_USER_FILESYSTEM_PRESENT
#include "FATFileSystem.h"
#include "LittleFileSystem.h"
#endif

#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif
#include <inttypes.h>

/* Simulate provision process for development
 *
 * 1. Reset kvstore
 * 2. Inject entropy seed (if no entropy source)
 * 3. Initialize user filesystem (if enabled)
 * 4. Mark the device as provisioned
 *
 * WARNING: For mass production, remove this file and run real provision process.
 */

/* Check weak reference/definition at the link:
 * http://www.keil.com/support/man/docs/ARMLINK/armlink_pge1362065917715.htm */

extern "C" {
    MBED_USED void provision(void);
}

/* Stringize */
#define STR_EXPAND(tok) #tok
#define STR(tok) STR_EXPAND(tok)

#define _GET_FILESYSTEM_concat(dev, ...) _get_filesystem_##dev(__VA_ARGS__)
#define GET_FILESYSTEM(dev, ...) _GET_FILESYSTEM_concat(dev, __VA_ARGS__)

/* Key for the device provisioned */
#define KV_KEY_PROVISION    "provision"

static void do_provision(KVStore *inner_store);

#if MBED_CONF_USER_FILESYSTEM_PRESENT
static void mount_user_filesystem(int format);
static inline uint64_t align_up(uint64_t val, uint64_t size);
static inline uint64_t align_down(uint64_t val, uint64_t size);
static int get_aligned_addresses(BlockDevice *bd, bd_addr_t start_address, bd_size_t size, bd_addr_t *out_start_addr, bd_addr_t *out_end_addr);
static bool address_overlap(bd_addr_t start_address, bd_addr_t end_address, bd_addr_t start_address2, bd_addr_t end_address2);
static FileSystem *_get_filesystem_FAT(const char *mount);
static FileSystem *_get_filesystem_LITTLE(const char *mount);
#endif /* #if MBED_CONF_USER_FILESYSTEM_PRESENT */

void provision(void)
{
    int kv_reset(const char *kvstore_path);
    
    /* Initialize kvstore */
    int kv_status = kv_init_storage_config();
    if (kv_status != MBED_SUCCESS) {
        MBED_ERROR1(MBED_MAKE_ERROR(MBED_MODULE_PLATFORM, MBED_ERROR_CODE_UNKNOWN), "Initialize kvstore failed", kv_status);
    }

    /* Get kvstore internal storage */
    KVMap &kv_map = KVMap::get_instance();
    KVStore *inner_store = kv_map.get_internal_kv_instance(NULL);
    if (inner_store == NULL) {
        MBED_ERROR(MBED_MAKE_ERROR(MBED_MODULE_PLATFORM, MBED_ERROR_CODE_UNKNOWN), "kvstore internal storage failed");
    }

    /* Check if the device has provisioned */
    KVStore::info_t kv_info;
    kv_status = inner_store->get_info(KV_KEY_PROVISION, &kv_info);
    if (kv_status == MBED_SUCCESS) {
        do {
            /* Get KV_KEY_PROVISION key */
            char buffer[4];
            size_t actual_size = 0;
            int kv_status = inner_store->get(KV_KEY_PROVISION, buffer, sizeof(buffer), &actual_size);
            if (kv_status != MBED_SUCCESS) {
                printf("Get \'%s\' failed: %d\r\n", KV_KEY_PROVISION, kv_status);
                break;
            }
            /* Check KV_KEY_PROVISION key's value */
            if (actual_size != 1 || buffer[0] != '1') {
                printf("\"%s\" not equal \"%s\"\r\n", KV_KEY_PROVISION, "1");
                break;
            }

            printf("The device has provisioned. Skip provision process\r\n");
            
#if MBED_CONF_USER_FILESYSTEM_PRESENT
            /* Mount user filesystem without format */
            mount_user_filesystem(0);
#endif /* #if MBED_CONF_USER_FILESYSTEM_PRESENT */
        } while (0);
    } else if (kv_status == MBED_ERROR_ITEM_NOT_FOUND) {
        /* Not provisioned yet */
        printf("The device has not provisioned yet. Try to provision it...\r\n");
        do_provision(inner_store);
    } else {
        printf("Get \'%s\' key failed: %d. Try to provision it...\r\n", KV_KEY_PROVISION, kv_status);
        do_provision(inner_store);
    }
}

static void do_provision(KVStore *inner_store)
{
    /* Provision from here */
    printf("Provision for development...\r\n");
    
    printf("Reset kvstore...\r\n");

    MBED_ASSERT(inner_store);

    /* Reset kvstore for clean kvstore */
    int kv_status = kv_reset("/" STR(MBED_CONF_STORAGE_DEFAULT_KV) "/");
    if (kv_status != MBED_SUCCESS) {
        MBED_ERROR1(MBED_MAKE_ERROR(MBED_MODULE_PLATFORM, MBED_ERROR_CODE_UNKNOWN), "kv_reset() failed", kv_status);
    }

    printf("\rReset kvstore...OK\r\n");

#if !DEVICE_TRNG && !TARGET_PSA
#if !defined(MBEDTLS_ENTROPY_HARDWARE_ALT)
    /* Inject trivial seed for development */

    printf("Inject NV seed...\r\n");

    psa_status_t psa_status;
    uint8_t seed[SEED_SIZE] = { 0 };

    /* First inject seed, expect OK or seed has injected by some provision process */
    psa_status = mbedtls_psa_inject_entropy(seed, sizeof(seed));
    if (psa_status != PSA_SUCCESS && psa_status != PSA_ERROR_NOT_PERMITTED) {
        MBED_ERROR1(MBED_MAKE_ERROR(MBED_MODULE_PLATFORM, MBED_ERROR_CODE_UNKNOWN), "Inject entropy failed", psa_status);
    }

    /* Second inject seed, expect seed has injected above or by some provision process */
    psa_status = mbedtls_psa_inject_entropy(seed, sizeof(seed));
    if (psa_status != PSA_ERROR_NOT_PERMITTED) {
        MBED_ERROR1(MBED_MAKE_ERROR(MBED_MODULE_PLATFORM, MBED_ERROR_CODE_UNKNOWN), "Re-jnject entropy expects PSA_ERROR_NOT_PERMITTED", psa_status);
    }

    printf("\rInject NV seed...OK\r\n");
#endif  /* !defined(MBEDTLS_ENTROPY_HARDWARE_ALT) */
#endif  /* #if !DEVICE_TRNG && !TARGET_PSA */

#if defined(DEVICE_TRNG) || defined(MBEDTLS_ENTROPY_NV_SEED) || defined(MBEDTLS_ENTROPY_HARDWARE_ALT)
    /* Inject ROT key for development */

    printf("Inject ROT key...\r\n");

    /* DeviceKey is a singleton */
    DeviceKey &devkey = DeviceKey::get_instance();

    /* Any salt will be OK */
    unsigned char salt[] = "SALT ----- SALT ------ SALT";

    /* Inject ROT key via generate_derived_key(...)
     *
     * To inject ROT key, we can call generate_derived_key(...) which will call
     * device_inject_root_of_trust(...) for injection of ROT key when it is not
     * injected yet.
     *
     * Ignore generated derived key.
     *
     * For Pelion, generate_derived_key(...) is called implicitly in mbed-cloud-client
     * library. For non-Pelion, we need to call this API explicitly.
     *
     * The key type (DEVICE_KEY_16BYTE/DEVICE_KEY_32BYTE) passed to generate_derived_key(...)
     * must match DEVICE_KEY_SIZE_IN_BYTES defined in kvstore_rot.cpp to be compatible with
     * mbed-bootloader. Otherwise, we will get MBED_ERROR_INVALID_SIZE error on the call to
     * mbed_cloud_client_get_rot_128bit(...).
     */
    unsigned char derived_key[16];
    int devkey_status = devkey.generate_derived_key(salt, sizeof(salt), derived_key, DEVICE_KEY_16BYTE);
    if (devkey_status != DEVICEKEY_SUCCESS) {
        MBED_ERROR1(MBED_MAKE_ERROR(MBED_MODULE_UNKNOWN, MBED_ERROR_CODE_UNKNOWN), "Injection of ROT key failed", devkey_status);
    }

    printf("Inject ROT key...OK\r\n");
#else
    #error("Missing any of DEVICE_TRNG, MBEDTLS_ENTROPY_NV_SEED, and MBEDTLS_ENTROPY_HARDWARE_ALT for generating ROT key")
#endif

#if MBED_CONF_USER_FILESYSTEM_PRESENT
    /* Mount user filesystem with format */
    mount_user_filesystem(1);
#endif /* #if MBED_CONF_USER_FILESYSTEM_PRESENT */

    /* Mark the device as provisioned */
    kv_status = inner_store->set(KV_KEY_PROVISION, "1", 1, KVStore::WRITE_ONCE_FLAG);
    if (kv_status != MBED_SUCCESS) {
        MBED_ERROR1(MBED_MAKE_ERROR(MBED_MODULE_PLATFORM, MBED_ERROR_CODE_UNKNOWN), "Mark the device as provisioned failed", kv_status);
    }

    printf("Provision for development...OK\r\n");
}

#if MBED_CONF_USER_FILESYSTEM_PRESENT

static void mount_user_filesystem(int format)
{
    /* Initialize user filesystem */
    printf("Mount user filesystem...\r\n");

    /* Get default block device */
    BlockDevice *bd = BlockDevice::get_default_instance();
    if (!bd) {
        MBED_ERROR(MBED_MAKE_ERROR(MBED_MODULE_PLATFORM, MBED_ERROR_CODE_UNKNOWN), "Default block device is null");
    }

    /* Align start/end address of blockdevice backing the filesystem */
    bd_addr_t start_address = MBED_CONF_USER_FILESYSTEM_BLOCKDEVICE_ADDRESS;
    bd_size_t size = MBED_CONF_USER_FILESYSTEM_BLOCKDEVICE_SIZE;
    bd_addr_t aligned_start_address;
    bd_addr_t aligned_end_address;
    if (get_aligned_addresses(bd, start_address, size, &aligned_start_address, &aligned_end_address) != 0) {
        MBED_ERROR(MBED_MAKE_ERROR(MBED_MODULE_PLATFORM, MBED_ERROR_CODE_UNKNOWN), "get_aligned_addresses(...) for user filesystem failed");
    }
    MBED_ASSERT(aligned_start_address != aligned_end_address);
    printf("User filesystem region: start/end address: %016" PRIx64 "/%016" PRIx64 "\r\n", aligned_start_address, aligned_end_address);

    /* TODO: Check overlap with other regions */

    /* Slice the blockdevice for backing the filesystem */
    static SlicingBlockDevice sbd(bd, aligned_start_address, aligned_end_address);
    static FileSystem *fs = GET_FILESYSTEM(MBED_CONF_USER_FILESYSTEM_TYPE, STR(MBED_CONF_USER_FILESYSTEM_MOUNT_POINT));
    MBED_ASSERT(fs);
    if (format) {
        int fs_status = fs->reformat(&sbd);
        if (fs_status != 0) {
            MBED_ERROR1(MBED_MAKE_ERROR(MBED_MODULE_PLATFORM, MBED_ERROR_CODE_UNKNOWN), "Re-format user filesystem failed: %d", fs_status);
        }
    } else {
        int fs_status = fs->mount(&sbd);
        if (fs_status != 0) {
            MBED_ERROR1(MBED_MAKE_ERROR(MBED_MODULE_PLATFORM, MBED_ERROR_CODE_UNKNOWN), "Mount user filesystem failed: %d", fs_status);
        }
    }

    printf("Mount user filesystem...OK\r\n");
}

static inline uint64_t align_up(uint64_t val, uint64_t size)
{
    return (((val - 1) / size) + 1) * size;
}

static inline uint64_t align_down(uint64_t val, uint64_t size)
{
    return (((val) / size)) * size;
}

static int get_aligned_addresses(BlockDevice *bd, bd_addr_t start_address, bd_size_t size, bd_addr_t *out_start_addr,
                   bd_addr_t *out_end_addr)
{
    bd_addr_t aligned_end_address;
    bd_addr_t end_address;
    bd_addr_t aligned_start_address;

    aligned_start_address = align_down(start_address, bd->get_erase_size(start_address));
    if (aligned_start_address != start_address) {
        printf("KV Config: Start address is not aligned. Better use %02llx", aligned_start_address);
        return -1;
    }

    if (size == 0) {
        (*out_start_addr) = aligned_start_address;
        (*out_end_addr) = bd->size();
        return 0;
    }

    end_address = start_address + size;
    aligned_end_address = align_up(end_address, bd->get_erase_size(end_address));
    if (aligned_end_address != end_address) {
        printf("KV Config: End address is not aligned. Consider changing the size parameter.");
        return -1;
    }

    if (aligned_end_address > bd->size()) {
        printf("KV Config: End address is out of boundaries");
        return -1;
    }

    (*out_start_addr) = aligned_start_address;
    (*out_end_addr) = aligned_end_address;
    return 0;
}

static bool address_overlap(bd_addr_t start_address, bd_addr_t end_address, bd_addr_t start_address2, bd_addr_t end_address2)
{
    if (start_address < start_address2) {
        return (start_address2 < end_address);
    } else if (start_address > start_address2) {
        return (start_address < end_address2);
    } else {
        return true;
    }
}

static FileSystem *_get_filesystem_FAT(const char *mount)
{
    static FATFileSystem sdcard(mount);
    return &sdcard;

}

static FileSystem *_get_filesystem_LITTLE(const char *mount)
{
    static LittleFileSystem flash(mount);
    return &flash;
}

#endif /* #if MBED_CONF_USER_FILESYSTEM_PRESENT */
