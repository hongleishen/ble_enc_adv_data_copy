/*
 * SPDX-FileCopyrightText: 2021-2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Unlicense OR CC0-1.0
 */

#include "esp_log.h"
#include "nvs_flash.h"

/* BLE */
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/ble_ead.h"
#include "host/util/util.h"
#include "console/console.h"
#include "services/gap/ble_svc_gap.h"
#include "enc_adv_data_cent.h"

#if CONFIG_EXAMPLE_ENC_ADV_DATA
static int counter = 0;
static struct km_peer kmp[CONFIG_BT_NIMBLE_MAX_CONNECTIONS + 1] = {0};

static const char *tag = "ENC_ADV_DATA_CENT";
static int enc_adv_data_cent_gap_event(struct ble_gap_event *event, void *arg);

#if MYNEWT_VAL(BLE_GATTC)
static int mtu_def = 512;
#endif

void ble_store_config_init(void);

static int
enc_adv_data_find_peer(const uint8_t *peer_addr)
{
    for (int i = 0; i <= CONFIG_BT_NIMBLE_MAX_CONNECTIONS; i++) {
        if (memcmp(peer_addr, &kmp[i].peer_addr, PEER_ADDR_VAL_SIZE) == 0) {
            return i;
        }
    }
    return -1;
}

#if MYNEWT_VAL(BLE_GATTC)
static int
enc_adv_data_set_km_exist(const uint8_t *peer_addr)
{
    int ind = enc_adv_data_find_peer(peer_addr);
    if (ind == -1) {
        return -1;
    }
    kmp[ind].key_material_exist = true;
    return 0;
}
#endif

static bool
enc_adv_data_check_km_exist(const uint8_t *peer_addr)
{
    int ind;
    ind = enc_adv_data_find_peer(peer_addr);
    if (ind == -1) {
        return false;
    }

    return kmp[ind].key_material_exist;
}

#if MYNEWT_VAL(BLE_GATTC)
/**
 * Application callback.  Called when the read has completed.
 */
static int
enc_adv_data_cent_on_read(uint16_t conn_handle,
                          const struct ble_gatt_error *error,
                          struct ble_gatt_attr *attr,
                          void *arg)
{
    int rc;
    struct ble_store_value_ead value_ead = {0};
    struct peer *p;

    printf("\n===== 第11步: 收到密码本，写入NVS，断连 =====L:%d===========\n", __LINE__);
    printf("  -> 从mbuf提取session_key+iv，ble_store_write_ead写NVS，然后主动断连。\n");

    pr_info("Read complete; status=%d conn_handle=%d", error->status,
                conn_handle);
    if (error->status == 0) {
        pr_info(" attr_handle=%d value=", attr->handle);
        print_mbuf(attr->om);
    } else {
        goto err;
    }

    p = peer_find(conn_handle);
    if (p == NULL) {
        goto err;
    }

    rc = enc_adv_data_set_km_exist(p->peer_addr);
    if (rc != 0) {
        pr_info("Setting key material exist flag failed");
    }

    value_ead.km_present = 1;

    value_ead.km = (struct key_material *) malloc (sizeof(struct key_material));

    if (value_ead.km == NULL) {
        MODLOG_DFLT(ERROR, "Failed to allocate memory for key material");
        goto err;
    }

    memset(value_ead.km, 0, sizeof(struct key_material));

    /* Validate mbuf has enough data before copying */
    if (attr->om == NULL || OS_MBUF_PKTLEN(attr->om) < (BLE_EAD_KEY_SIZE + BLE_EAD_IV_SIZE)) {
        MODLOG_DFLT(ERROR, "Invalid mbuf or insufficient data size");
        free(value_ead.km);
        value_ead.km = NULL;
        goto err;
    }

    os_mbuf_copydata(attr->om, 0, BLE_EAD_KEY_SIZE, &value_ead.km->session_key);
    os_mbuf_copydata(attr->om, BLE_EAD_KEY_SIZE, BLE_EAD_IV_SIZE, &value_ead.km->iv);

    pr_info("Session key:");
    print_bytes(value_ead.km->session_key, BLE_EAD_KEY_SIZE);

    pr_info("IV:");
    print_bytes(value_ead.km->iv, BLE_EAD_IV_SIZE);

    memcpy(&value_ead.peer_addr.val, &p->peer_addr, PEER_ADDR_VAL_SIZE);

    rc = ble_store_write_ead(&value_ead);
    if (rc == 0) {
        pr_info("Writing of session key, iv, and peer addr to NVS success");
    }

    if (value_ead.km != NULL) {
        free(value_ead.km);
        value_ead.km = NULL;
    }

err:
    /* Terminate the connection. */
    if (value_ead.km != NULL) {
        free(value_ead.km);
        value_ead.km = NULL;
    }
    return ble_gap_terminate(conn_handle, BLE_ERR_REM_USER_CONN_TERM);
}

static void
enc_adv_data_cent_read(const struct peer *peer)
{
    const struct peer_chr *chr = NULL;
    int rc;

    printf("\n===== 第10步: 读取密码本 =====L:%d===========\n", __LINE__);
    printf("  -> GATT 读 handle=7(KEY_MATERIAL 0x2B88)，回调 enc_adv_data_cent_on_read。\n");

    /* Read the supported-new-alert-category characteristic. */
    chr = peer_chr_find_uuid(peer,
                             BLE_UUID16_DECLARE(BLE_SVC_GAP_UUID16),
                             BLE_UUID16_DECLARE(BLE_SVC_GAP_CHR_UUID16_KEY_MATERIAL));
    if (chr == NULL) {
        MODLOG_DFLT(ERROR, "Error: Peer doesn't support the Key"
                    "Material characteristic\n");
        goto err;
    }

    rc = ble_gattc_read(peer->conn_handle, chr->chr.val_handle,
                        enc_adv_data_cent_on_read, NULL);
    if (rc != 0) {
        MODLOG_DFLT(ERROR, "Error: Failed to read characteristic; rc=%d\n",
                    rc);
        goto err;
    }

    return;
err:
    /* Terminate the connection. */
    ble_gap_terminate(peer->conn_handle, BLE_ERR_REM_USER_CONN_TERM);
}

/**
 * Called when service discovery of the specified peer has completed.
 */
static void
enc_adv_data_cent_on_disc_complete(const struct peer *peer, int status, void *arg)
{
    printf("\n===== 第9步: 服务发现完成 =====L:%d===========\n", __LINE__);
    printf("  -> 服务/特征/描述符全部发现，status=%d conn=%d，启动GATT read。\n", status, peer->conn_handle);

    if (status != 0) {
        /* Service discovery failed.  Terminate the connection. */
        MODLOG_DFLT(ERROR, "Error: Service discovery failed; status=%d "
                    "conn_handle=%d\n", status, peer->conn_handle);
        ble_gap_terminate(peer->conn_handle, BLE_ERR_REM_USER_CONN_TERM);
        return;
    }

    /* Service discovery has completed successfully.  Now we have a complete
     * list of services, characteristics, and descriptors that the peer
     * supports.
     */
    pr_info("Service discovery complete; status=%d "
                "conn_handle=%d\n", status, peer->conn_handle);

    if (!enc_adv_data_check_km_exist(peer->peer_addr)) {	// km不存在 返回0， if成立
        /* Now perform GATT read procedures against the peer */
        enc_adv_data_cent_read(peer);
    }
}
#endif

/**
 * Initiates the GAP general discovery procedure.
 */
static void
enc_adv_data_cent_scan(void)
{
    uint8_t own_addr_type;
    struct ble_gap_disc_params disc_params = {0};
    int rc;

    /* Figure out address to use while advertising (no privacy for now) */
    rc = ble_hs_id_infer_auto(0, &own_addr_type);
    if (rc != 0) {
        MODLOG_DFLT(ERROR, "error determining address type; rc=%d\n", rc);
        return;
    }

    printf("\n===== 第1步: 启动/重启扫描 =====L:%d===========\n", __LINE__);
    printf("  -> 被动扫描，过滤重复广播，持续扫描直到发现目标设备(UUID 0x2C01)或连接建立。\n");

    /* Tell the controller to filter duplicates; we don't want to process
     * repeated advertisements from the same device.
     */
    disc_params.filter_duplicates = 1;

    /**
     * Perform a passive scan.  I.e., don't send follow-up scan requests to
     * each advertiser.
     */
    disc_params.passive = 1;

    /* Use defaults for the rest of the parameters. */
    disc_params.itvl = 0;
    disc_params.window = 0;
    disc_params.filter_policy = 0;
    disc_params.limited = 0;

    rc = ble_gap_disc(own_addr_type, BLE_HS_FOREVER, &disc_params,
                      enc_adv_data_cent_gap_event, NULL);
    if (rc != 0) {
        MODLOG_DFLT(ERROR, "Error initiating GAP discovery procedure; rc=%d\n",
                    rc);
    }
}

static int
enc_adv_data_cent_decrypt(uint8_t length_data, const uint8_t *data, const uint8_t *peer_addr)
{
    uint8_t op;
    uint8_t len, offset = 0;
    uint8_t *enc_data;
    uint8_t enc_payload_len;
    int rc;
    uint8_t dec_data_len;
    uint8_t temp[BLE_EAD_DECRYPTED_PAYLOAD_SIZE(UINT8_MAX)];
    struct ble_store_key_ead key_ead = {0};
    struct ble_store_value_ead value_ead = {0};

    printf("\n===== 第15步: 隔空解密广播数据 =====L:%d===========\n", __LINE__);
    printf("  -> 遍历AD结构→找ENC_ADV_DATA→读NVS密钥→ble_ead_decrypt→解密成功输出。\n");
    printf("  -> 注意: EAD每包含随机Randomizer，filter_duplicates无法过滤，每30-80秒重复解密属正常现象。\n");

    while (offset < length_data) {
        len = data[offset];

        /* Bounds check: ensure we can read the type byte and the full AD field */
        if (offset + 1 >= length_data) {
            break;
        }
        op = data[offset + 1];

        if (len == 0 || offset + 1 + len > length_data) {
            break;
        }

        switch (op) {
        case BLE_GAP_ENC_ADV_DATA:
            /* Encrypted payload is AD value (len - 1 bytes, excluding the type byte) */
            enc_payload_len = len - 1;
            enc_data = (uint8_t *) malloc (sizeof(uint8_t) * enc_payload_len);
             if (enc_data == NULL) {
                 MODLOG_DFLT(ERROR, "Failed to allocate enc_data");
                 return 0;
             }
            memcpy(enc_data, data + offset + 2, enc_payload_len);

            memcpy(&key_ead.peer_addr.val, peer_addr, PEER_ADDR_VAL_SIZE);

            rc = ble_store_read_ead(&key_ead, &value_ead);
            if (rc != 0 || !value_ead.km_present) {
                pr_info("Reading of session key and iv from NVS failed rc = %d", rc);
                free(enc_data);
                return 0;
            } else {
                pr_info("Read session key and iv from NVS successfully");
            }

            rc = ble_ead_decrypt(value_ead.km->session_key, value_ead.km->iv, enc_data,
                                 enc_payload_len, temp);
            if (rc == 0) {
                pr_info("Decryption of adv data done successfully");
            } else {
                pr_info("Decryption of adv data failed");
                free(enc_data);
                return 0;
            }

            dec_data_len = temp[0];

            pr_info("Data after decryption:");
            printf("  ");
			uint8_t true_payload_len = enc_payload_len - BLE_EAD_RANDOMIZER_SIZE - BLE_EAD_MIC_SIZE;
            for (int i = 0; i < true_payload_len + 1; i++) {
                printf("0x%02X ", temp[i]);
            }
            printf("\n");
            free(enc_data);
            return 0;	// return 1;

        default:
            break;
        }
        offset += len + 1;
    }
    return 1;
}

/**
 * Indicates whether we should try to connect to the sender of the specified
 * advertisement.  The function returns a positive result if the device
 * advertises connectability and support for the Key Characteristic service.
 */
static int
enc_adv_data_cent_should_connect(const struct ble_gap_disc_desc *disc)
{
    struct ble_hs_adv_fields fields;
    int rc;
    int i;
    uint8_t test_addr[6];
    uint32_t peer_addr[6];

    memset(peer_addr, 0x0, sizeof peer_addr);

    if (disc->event_type != BLE_HCI_ADV_RPT_EVTYPE_ADV_IND &&
            disc->event_type != BLE_HCI_ADV_RPT_EVTYPE_DIR_IND) {
        return 0;
    }

    rc = ble_hs_adv_parse_fields(&fields, disc->data, disc->length_data);
    if (rc != 0) {
        return 0;
    }

    if (strlen(CONFIG_EXAMPLE_PEER_ADDR) && (strncmp(CONFIG_EXAMPLE_PEER_ADDR, "ADDR_ANY", strlen    ("ADDR_ANY")) != 0)) {
        pr_info("Peer address from menuconfig: %s", CONFIG_EXAMPLE_PEER_ADDR);
        /* Convert string to address */
        sscanf(CONFIG_EXAMPLE_PEER_ADDR, "%lx:%lx:%lx:%lx:%lx:%lx",
               &peer_addr[5], &peer_addr[4], &peer_addr[3],
               &peer_addr[2], &peer_addr[1], &peer_addr[0]);

	/* Conversion */
        for (int i=0; i<6; i++) {
            test_addr[i] = (uint8_t )peer_addr[i];
	}

        if (memcmp(test_addr, disc->addr.val, sizeof(disc->addr.val)) != 0) {
            return 0;
        }
    }

    /* The device has to advertise support for the Key Characteristic
    * service (0x2B88)
    *
    * Check if custom UUID 0x2C01 is advertised
    */
    for (i = 0; i < fields.num_uuids16; i++) {
        if (ble_uuid_u16(&fields.uuids16[i].u) == 0x2C01) {
            if (enc_adv_data_find_peer(disc->addr.val) != -1) {
                pr_info("Peer was already added with addr : %s",
                            addr_str(&disc->addr.val));
            } else {
                pr_info("Adding peer addr : %s", addr_str(&disc->addr.val));

                memcpy(&kmp[counter].peer_addr, &disc->addr.val, PEER_ADDR_VAL_SIZE);
                counter++;

                if (counter > CONFIG_BT_NIMBLE_MAX_CONNECTIONS) {
                    counter = 0;
                }
            }
            if (enc_adv_data_check_km_exist(disc->addr.val)) {  // kv存储, if真
                return enc_adv_data_cent_decrypt(disc->length_data, disc->data, disc->addr.val);
            } else {
                return 1;
            }
        }
    }

    return 0;
}

/**
 * Connects to the sender of the specified advertisement of it looks
 * interesting.  A device is "interesting" if it advertises connectability and
 * support for the Key Characteristic service.
 */
static void
enc_adv_data_cent_connect_if_interesting(void *disc)
{
    uint8_t own_addr_type;
    int rc;
    ble_addr_t *addr;

    /* Don't do anything if we don't care about this advertiser. */
    if (!enc_adv_data_cent_should_connect((struct ble_gap_disc_desc *)disc)) {
        return;
    }

#if !(MYNEWT_VAL(BLE_HOST_ALLOW_CONNECT_WITH_SCAN))
    /* Scanning must be stopped before a connection can be initiated. */
    rc = ble_gap_disc_cancel();
    if (rc != 0) {
        pr_info("Failed to cancel scan; rc=%d\n", rc);
        return;
    }
#endif

    /* Figure out address to use for connect (no privacy for now) */
    rc = ble_hs_id_infer_auto(0, &own_addr_type);
    if (rc != 0) {
        MODLOG_DFLT(ERROR, "error determining address type; rc=%d\n", rc);
        return;
    }

    /* Try to connect the the advertiser.  Allow 30 seconds (30000 ms) for
     * timeout.
     */
    addr = &((struct ble_gap_disc_desc *)disc)->addr;

    printf("\n===== 第3步: 逻辑分叉 =====L:%d===========\n", __LINE__);
    printf("  -> 分叉: 有密钥→直接解密广播(第15步)，返回0不连接；无密钥→发起连接(第4步)，走配对流程。\n");
    printf("\n===== 第4步: 停止扫描，发起连接 =====L:%d===========\n", __LINE__ + 2);
    printf("  -> 协议栈不允许同时扫描+连接，先 disc_cancel，再 ble_gap_connect。\n");

    rc = ble_gap_connect(own_addr_type, addr, 30000, NULL,
                         enc_adv_data_cent_gap_event, NULL);
    if (rc != 0) {
        MODLOG_DFLT(ERROR, "Error: Failed to connect to device; addr_type=%d "
                    "addr=%s; rc=%d\n",
                    addr->type, addr_str(addr->val), rc);
        return;
    }
}

/**
 * The nimble host executes this callback when a GAP event occurs.  The
 * application associates a GAP event callback with each connection that is
 * established.  enc_adv_data_cent uses the same callback for all connections.
 *
 * @param event                 The event being signalled.
 * @param arg                   Application-specified argument; unused by
 *                                  enc_adv_data_cent.
 *
 * @return                      0 if the application successfully handled the
 *                                  event; nonzero on failure.  The semantics
 *                                  of the return code is specific to the
 *                                  particular GAP event being signalled.
 */
static int
enc_adv_data_cent_gap_event(struct ble_gap_event *event, void *arg)
{
    struct ble_gap_conn_desc desc;
    struct ble_hs_adv_fields fields;
    int rc;

    switch (event->type) {
    case BLE_GAP_EVENT_DISC:
        rc = ble_hs_adv_parse_fields(&fields, event->disc.data,
                                     event->disc.length_data);
        if (rc != 0) {
            return 0;
        }

        /* An advertisement report was received during GAP discovery. */
        print_adv_fields(&fields);

        /* Try to connect to the advertiser if it looks interesting. */
        enc_adv_data_cent_connect_if_interesting(&event->disc);
        return 0;

    case BLE_GAP_EVENT_CONNECT:
        /* A new connection was established or a connection attempt failed. */
        if (event->connect.status == 0) {
            /* Connection successfully established. */
            printf("\n===== 第5步: 连接建立 =====L:%d===========\n", __LINE__);
            printf("  -> 连接成功后发起 security_initiate(被动侧对暗号)，完成后触发 BLE_GAP_EVENT_ENC_CHANGE。\n");
            pr_info("Connection established ");

            rc = ble_gap_conn_find(event->connect.conn_handle, &desc);
            assert(rc == 0);
            print_conn_desc(&desc);
            pr_info("");

#if MYNEWT_VAL(BLE_GATTC)
            rc = ble_att_set_preferred_mtu(mtu_def);
            if (rc != 0) {
                ESP_LOGE(tag, "Failed to set preferred MTU; rc = %d", rc);
            }

            rc = ble_gattc_exchange_mtu(event->connect.conn_handle, NULL, NULL);
            if (rc != 0) {
                ESP_LOGE(tag, "Failed to negotiate MTU; rc = %d", rc);
            }
#endif

            /* Remember peer. */
            rc = peer_add(event->connect.conn_handle);
            if (rc != 0) {
                MODLOG_DFLT(ERROR, "Failed to add peer; rc=%d\n", rc);
                return 0;
            }

            rc = peer_set_addr(event->connect.conn_handle, desc.peer_id_addr.val);
            if (rc != 0) {
                MODLOG_DFLT(ERROR, "Failed to set peer addr; rc=%d\n", rc);
                return 0;
            }

            /** Authorization is required for this characterisitc */
            rc = ble_gap_security_initiate(event->connect.conn_handle);		// 启动配对
            if (rc != 0) {
                pr_info("Security could not be initiated, rc = %d\n", rc);
                return ble_gap_terminate(event->connect.conn_handle,
                                         BLE_ERR_REM_USER_CONN_TERM);
            } else {
                pr_info("Connection secured\n");
            }

        } else {
            /* Connection attempt failed; resume scanning. */
            printf("\n===== 连接失败，继续扫描 =====L:%d===========\n", __LINE__);
            printf("  -> status=%d，重新启动扫描流程。\n", event->connect.status);
            MODLOG_DFLT(ERROR, "Error: Connection failed; status=%d\n",
                        event->connect.status);
            enc_adv_data_cent_scan();
        }

        return 0;

    case BLE_GAP_EVENT_DISCONNECT:
        /* Connection terminated. */
        printf("\n===== 第12步: 断开连接 =====L:%d===========\n", __LINE__);
        printf("  -> 密钥已取走，主动断开。reason=%d，回到扫描状态，下次收到广播直接解密。\n", event->disconnect.reason);
        pr_info("disconnect; reason=%d ", event->disconnect.reason);
        print_conn_desc(&event->disconnect.conn);
        pr_info("");

        /* Forget about peer. */
        peer_delete(event->disconnect.conn.conn_handle);

        /* Resume scanning. */
        enc_adv_data_cent_scan();
        return 0;

    case BLE_GAP_EVENT_DISC_COMPLETE:
        pr_info("discovery complete; reason=%d\n",
                    event->disc_complete.reason);
        return 0;

    case BLE_GAP_EVENT_ENC_CHANGE:
        printf("\n===== 第8步: 加密信道建立 =====L:%d===========\n", __LINE__);
        printf("  -> 配对完成，encrypted=1，authenticated=1。现在可发起服务发现，读取 Key Material。\n");
        pr_info("encryption change event; status=%d ",
                    event->enc_change.status);
        rc = ble_gap_conn_find(event->enc_change.conn_handle, &desc);
        assert(rc == 0);
        print_conn_desc(&desc);

#if MYNEWT_VAL(BLE_GATTC)
        /* Perform service discovery */
        rc = peer_disc_all(event->enc_change.conn_handle,
                           enc_adv_data_cent_on_disc_complete, NULL);
        if (rc != 0) {
            MODLOG_DFLT(ERROR, "Failed to discover services; rc=%d\n", rc);
        }
#endif
        return 0;

    case BLE_GAP_EVENT_NOTIFY_RX:
        /* Peer sent us a notification or indication. */
        pr_info("received %s; conn_handle=%d attr_handle=%d "
                    "attr_len=%d\n",
                    event->notify_rx.indication ?
                    "indication" :
                    "notification",
                    event->notify_rx.conn_handle,
                    event->notify_rx.attr_handle,
                    OS_MBUF_PKTLEN(event->notify_rx.om));

        /* Attribute data is contained in event->notify_rx.om. Use
         * `os_mbuf_copydata` to copy the data received in notification mbuf */
        return 0;

    case BLE_GAP_EVENT_MTU:
        printf("\n===== 第6步: MTU协商 =====L:%d===========\n", __LINE__);
        printf("  -> 双方协商最大传输单元，mtu=%d，仅状态记录。\n", event->mtu.value);
        pr_info("mtu update event; conn_handle=%d cid=%d mtu=%d\n",
                    event->mtu.conn_handle,
                    event->mtu.channel_id,
                    event->mtu.value);
        return 0;

#if MYNEWT_VAL(BLE_EXT_ADV)
    case BLE_GAP_EVENT_EXT_DISC:
        /* An advertisement report was received during GAP discovery. */
        ext_print_adv_report(&event->ext_disc);
        return 0;
#endif

    case BLE_GAP_EVENT_PASSKEY_ACTION:
        printf("\n===== 第7步: 双盲对暗号 =====L:%d===========\n", __LINE__);
        printf("  -> Central作为输入方(INPUT)，注入passkey=123456。双方用同一passkey协商出128位LTK加密信道。\n");
        pr_info("PASSKEY_ACTION_EVENT started %d", event->passkey.params.action);
        struct ble_sm_io pkey = {0};

        if (event->passkey.params.action == BLE_SM_IOACT_INPUT) {
            pkey.action = event->passkey.params.action;
            /* WARNING: Hardcoded passkey for demonstration only.
             * In production, generate a random passkey per pairing. */
            pkey.passkey = 123456;
            pr_info("Entering passkey %" PRIu32, pkey.passkey);
            rc = ble_sm_inject_io(event->passkey.conn_handle, &pkey);
            pr_info("ble_sm_inject_io result: %d", rc);
        }

        return 0;

    default:
        return 0;
    }
}

static void
enc_adv_data_cent_on_reset(int reason)
{
    MODLOG_DFLT(ERROR, "Resetting state; reason=%d\n", reason);
}

static void
enc_adv_data_cent_on_sync(void)
{
    int rc;

    /* Make sure we have proper identity address set (public preferred) */
    rc = ble_hs_util_ensure_addr(0);
    assert(rc == 0);

    enc_adv_data_cent_scan();
}

void enc_adv_data_cent_host_task(void *param)
{
    pr_info("BLE Host Task Started");
    /* This function will return only when nimble_port_stop() is executed */
    nimble_port_run();

    nimble_port_freertos_deinit();
}

void
app_main(void)
{
    int rc;
    /* Initialize NVS — it is used to store PHY calibration data */
    esp_err_t ret = nvs_flash_init();
    if  (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ret = nimble_port_init();
    if (ret != ESP_OK) {
        ESP_LOGE(tag, "Failed to init nimble %d ", ret);
        return;
    }

    /* Configure the host. */
    ble_hs_cfg.reset_cb = enc_adv_data_cent_on_reset;
    ble_hs_cfg.sync_cb = enc_adv_data_cent_on_sync;
    ble_hs_cfg.store_status_cb = ble_store_util_status_rr;

    /** This feature requires authentication */
    ble_hs_cfg.sm_mitm = 1;								// 启用 MITM（Man-In-The-Middle，中间人攻击）保护
    ble_hs_cfg.sm_io_cap = BLE_SM_IO_CAP_KEYBOARD_ONLY;	// 仅有键盘

    /* Initialize data structures to track connected peers. */
#if MYNEWT_VAL(BLE_INCL_SVC_DISCOVERY) || MYNEWT_VAL(BLE_GATT_CACHING_INCLUDE_SERVICES)
    rc = peer_init(MYNEWT_VAL(BLE_MAX_CONNECTIONS), 64, 64, 64, 64);
    assert(rc == 0);
#else
    rc = peer_init(MYNEWT_VAL(BLE_MAX_CONNECTIONS), 64, 64, 64);
    assert(rc == 0);
#endif

#if CONFIG_BT_NIMBLE_GAP_SERVICE
    /* Set the default device name. */
    rc = ble_svc_gap_device_name_set("enc_adv_data_cent");
    assert(rc == 0);
#endif

    /* XXX Need to have template for store */
    ble_store_config_init();

    nimble_port_freertos_init(enc_adv_data_cent_host_task);
}
#else
void
app_main(void)
{
    return;
}
#endif
