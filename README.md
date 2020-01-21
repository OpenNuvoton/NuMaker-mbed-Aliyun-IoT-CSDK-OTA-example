# Example for Firmware OTA with Alibaba Cloud IoT Platform on Nuvoton's Mbed Enabled boards

This is an example to show firmware Over-The-Air (OTA) with [Alibaba Cloud IoT Platform](https://iot.console.aliyun.com) on Nuvoton's Mbed Enabled boards.
Besides [Mbed OS](https://github.com/ARMmbed/mbed-os), it relies on the following modules:

-   [mbed-bootloader](https://github.com/ARMmbed/mbed-bootloader/):
    Generic bootloader designed by Arm to be used in conjunction with [Pelion Device Management Client](https://github.com/ARMmbed/mbed-cloud-client) for firmware Over-The-Air (OTA).
    It is designed so generic that it can also be used on non-Pelion firmware OTA cases like this.
-   [Alibaba Cloud IoT C-SDK port](https://github.com/OpenNuvoton/NuMaker-mbed-Aliyun-IoT-CSDK):
    Port of Alibaba Cloud IoT C-SDK onto Mbed OS, especially on Nuvoton's Mbed Enabled boards.
-   [mbed-bootloaer firmware update library](https://github.com/OpenNuvoton/NuMaker-mbed-bootloader-UCP):
    Library for mbed-bootloader compatible firmware update

## Support targets

Platform                        |  Connectivity     | Storage for credentials and FW candidate  | Notes
--------------------------------|-------------------|-------------------------------------------|---------------
Nuvoton NUMAKER_PFM_NUC472      | Ethernet          | NU SD card                                |
Nuvoton NUMAKER_PFM_M487        | Ethernet          | NU SD card                                |
Nuvoton NUMAKER_IOT_M487        | Wi-Fi ESP8266     | NU SD card                                |
Nuvoton NUMAKER_IOT_M263A       | Wi-Fi ESP8266     | NU SD card                                |

## Support development tools

-   [Arm's Mbed Online Compiler](https://os.mbed.com/docs/mbed-os/v5.15/tools/developing-mbed-online-compiler.html) (NOT SUPPORT)
-   [Arm's Mbed Studio](https://os.mbed.com/docs/mbed-os/v5.15/tools/developing-mbed-studio.html)
-   [Arm's Mbed CLI](https://os.mbed.com/docs/mbed-os/v5.15/tools/developing-mbed-cli.html)

The firmware OTA process needs separate firmware update image (`NuMaker-mbed-Aliyun-IoT-OTA-example_update.bin` in the below section).
This can acquire with Mbed CLI, but cannot with Mbed Online Compiler.
See the following section for details.

## Developer guide

This section is intended for developers to get started, import the example application, compile with Mbed CLI, and get it running and firmware OTA with Alibaba Cloud IoT Platform.

### Hardware requirements

-   Nuvoton's Mbed Enabled board
-   Micro SD card

### Software requirements

-   [Arm's Mbed CLI](https://os.mbed.com/docs/mbed-os/v5.15/tools/developing-mbed-cli.html)
-   Alibaba Cloud account

### Hardware setup

1.  Insert micro SD card into target board
1.  Connect target board to host through USB

### Operations on IoT Platform console

1.  Lon on to [IoT Platform console](http://iot.console.aliyun.com).
1.  Create a product/device. Take note of the acquired trituple: **ProductKey**/**DeviceName**/**DeviceSecret**. These are required to change to example code in the below section.
    1.  [Create a product](https://github.com/AlibabaCloudDocs/iot/blob/master/intl.en-US/User%20Guide/Create%20products%20and%20devices/Create%20a%20product.md)
    1.  [Create a device](https://github.com/AlibabaCloudDocs/iot/blob/master/intl.en-US/User%20Guide/Create%20products%20and%20devices/Create%20devices/Create%20a%20device.md)
1.  After device connects, run [firmware OTA process](https://github.com/AlibabaCloudDocs/iot/blob/master/intl.en-US/User%20Guide/Monitoring%20and%20Maintenance/Firmware%20update/Firmware%20update.md).
    In the **Add Firmware** dialog, check that the following items must conform:
    1.  **Type**: Choose *Full*. No support for *Differential*.
    1.  **Firmware Name**: Arbitrary
    1.  **Product**: Choose `${ProductName}` as created above
    1.  **Firmware Version**: Must be UNIX timestamp as required by [mbed-bootloaer firmware update library](https://github.com/OpenNuvoton/NuMaker-mbed-bootloader-UCP). For example, run `date +%s` in the POSIX-like environment:
        ```sh
        $ date +%s
        1577151897
        ```
        `1577151897` is the firmware version to enter.
    1.  **Signature Algorithm**: Choose *MD5*. [Alibaba Cloud IoT C-SDK port](https://github.com/OpenNuvoton/NuMaker-mbed-Aliyun-IoT-CSDK) doesn't support *SHA256* per test.
    1.  **Select firmware**: Choose `BUILD/${TARGET}/${TOOLCHAIN}/NuMaker-mbed-Aliyun-IoT-OTA-example_update.bin` generated in the following section. Rename to shorter when meeting file name length limit imposed by IoT Platform.
    1.  **Description**: Arbitrary

### Compile with Mbed CLI

In the following, we take [NuMaker-IoT-M487](https://os.mbed.com/platforms/NUMAKER-IOT-M487/) as example board to show this example.

1.  Clone the example and navigate into it
    ```sh
    $ git clone https://github.com/OpenNuvoton/NuMaker-mbed-Aliyun-IoT-CSDK-OTA-example
    $ cd NuMaker-mbed-Aliyun-IoT-CSDK-OTA-example
    ```
1.  Deploy necessary libraries
    ```sh
    $ mbed deploy
    ```
1.  Configure network interface
    -   Ethernet: In `mbed_app.json`, note resource allocation for lwIP. Might need modifications when receiving `NSAPI_ERROR_NO_MEMORY` error, dependent on applications.
        ```json
            "lwip.pbuf-pool-size"                       : 10,
            "lwip.mem-size"                             : 3200,
        ```
    -   WiFi: In `mbed_app.json`, configure WiFi **SSID**/**PASSWORD**.
        ```json
            "nsapi.default-wifi-ssid"                   : "\"SSID\"",
            "nsapi.default-wifi-password"               : "\"PASSWORD\"",
        ```
1.  In `source/ota_example_mqtt.c`, change **ProductKey**/**DeviceName**/**DeviceSecret** to acquired above. **ProductSecret** doesn't matter here.
    ```C
    char g_product_key[IOTX_PRODUCT_KEY_LEN + 1]       = "FIXME";
    char g_product_secret[IOTX_PRODUCT_SECRET_LEN + 1] = "IGNORED";
    char g_device_name[IOTX_DEVICE_NAME_LEN + 1]       = "FIXME";
    char g_device_secret[IOTX_DEVICE_SECRET_LEN + 1]   = "FIXME";
    ```
1.  Build the example on **NUMAKER_IOT_M487** target and **ARMC6** toolchain
    ```sh
    $ mbed compile -m NUMAKER_IOT_M487 -t ARMC6
    ```
1.  Flash by drag-n-drop'ing the built image file below onto **NuMaker-IoT-M487** board

    `BUILD/NUMAKER_IOT_M487/ARMC6/NuMaker-mbed-Aliyun-IoT-example.bin`

    **Note**: By drag-n-drop flash, the device is reset for clean start, including kvstore reset and so user filesystem re-initialization.

This example relies on [Arm Mbed OS managed bootloader](https://os.mbed.com/docs/mbed-os/v5.15/tutorials/bootloader.html) for firmware update support.
After successful build, user can get several image files (`.bin` or `.hex`) under `BUILD/NUMAKER_IOT_M487/ARMC6` directory:

-   `NuMaker-mbed-Aliyun-IoT-OTA-example.bin`: The first image file to flash onto device. It consists of bootloader, application header, and application itself.
-   `NuMaker-mbed-Aliyun-IoT-OTA-example_header.hex`: Application header. The original firmware version is generated by Mbed OS build tool and is embedded here.
-   `NuMaker-mbed-Aliyun-IoT-OTA-example_application.bin`: Application itself
-   `NuMaker-mbed-Aliyun-IoT-OTA-example_update.bin`: Same as `NuMaker-mbed-Aliyun-IoT-OTA-example_application.bin`. Renamed to emphasize that it is the image file to upload to IoT Platform for firmware OTA.

### Monitor the application through host console

Configure host terminal program with **115200/8-N-1**, and you should see log similar to below:

```
The device has not provisioned yet. Try to provision it...
Provision for development...
Reset kvstore...
Reset kvstore...OK
Inject ROT key...
Inject ROT key...OK
Provision for development...OK
main|322 :: hello main func
[prt] log level set as: [ 5 ]
[wrn] IOT_MQTT_Construct(274): Using default hostname: 'a1wOVhf0PmQ.iot-as-mqtt.cn-shanghai.aliyuncs.com'
[wrn] IOT_MQTT_Construct(281): Using default port: [443]
[wrn] IOT_MQTT_Construct(288): Using default client_id: a1wOVhf0PmQ.T10YogSxts4YVtugH5at|timestamp=2524608000000,_v=sdk-c-3.1.0,securemode=2,signmethod=hmacsha256,lan=C,_ss=1,gw=0,ext=0|
[wrn] IOT_MQTT_Construct(295): Using default username: T10YogSxts4YVtugH5at&a1wOVhf0PmQ
[wrn] IOT_MQTT_Construct(303): Using default password: ******
[dbg] _mqtt_nwk_connect(2708): calling TCP or TLS connect HAL for [1/3] iteration
[err] HAL_Kv_Get(49): HAL_Kv_Get(seed_key) failed
Loading the CA root certificate ...
 ok (0 skipped)
start prepare client cert .
start mbedtls_pk_parse_key[]
Connecting to /a1wOVhf0PmQ.iot-as-mqtt.cn-shanghai.aliyuncs.com/443...
Connected to the network successfully. IP address: 192.168.8.105
 ok
  . Setting up the SSL/TLS structure...
 ok
Performing the SSL/TLS handshake...
 ok
  . Verifying peer X.509 certificate..
certificate verification result: 0x00
[dbg] _mqtt_nwk_connect(2726): rc = pClient->ipstack.connect() = 0, success @ [1/3] iteration
[inf] _mqtt_connect(722): connect params: MQTTVersion=4, clientID=a1wOVhf0PmQ.T10YogSxts4YVtugH5at|timestamp=2524608000000,_v=sdk-c-3.1.0,securemode=2,signmethod=hmacsha256,lan=C,_ss=1,gw=0,ext=0|, keepAliveInterval=120, username=T10YogSxts4YVtugH5at&a1wOVhf0PmQ
[inf] _mqtt_connect(768): mqtt connect success!
```

Take note of reported firmware version before firmware update. It is embedded in firmware header.

<pre>
[dbg] iotx_report_firmware_version(146): firmware version report start in MQTT
[dbg] iotx_report_firmware_version(159): firmware report topic: /ota/device/inform/a1wOVhf0PmQ/T10YogSxts4YVtugH5at
[dbg] iotx_report_firmware_version(172): firmware report data: {"id":"0","params":{"version":"1577098827"}}
[inf] MQTTPublish(2588): Upstream Topic: '/ota/device/inform/a1wOVhf0PmQ/T10YogSxts4YVtugH5at'
[inf] MQTTPublish(2589): Upstream Payload:

> {
>     "id": "0",
>     "params": {
>         "version": "1577098827"
>     }
> }

[dbg] iotx_report_firmware_version(181): firmware version report finished, iotx_publish() = 1
</pre>

```
[dbg] wrapper_mqtt_subscribe(2917): PERFORM subscribe to '/ota/device/request/a1wOVhf0PmQ/T10YogSxts4YVtugH5at' (msgId=2)
[dbg] MQTTSubscribe(2145):         Packet Ident : 00000002
[dbg] MQTTSubscribe(2146):                Topic : /ota/device/request/a1wOVhf0PmQ/T10YogSxts4YVtugH5at
[dbg] MQTTSubscribe(2147):                  QoS : 1
[dbg] MQTTSubscribe(2148):        Packet Length : 59
[inf] wrapper_mqtt_subscribe(2928): mqtt subscribe packet sent,topic = /ota/device/request/a1wOVhf0PmQ/T10YogSxts4YVtugH5at!
[dbg] wrapper_mqtt_subscribe(2917): PERFORM subscribe to '/ota/device/upgrade/a1wOVhf0PmQ/T10YogSxts4YVtugH5at' (msgId=3)
[dbg] MQTTSubscribe(2145):         Packet Ident : 00000003
[dbg] MQTTSubscribe(2146):                Topic : /ota/device/upgrade/a1wOVhf0PmQ/T10YogSxts4YVtugH5at
[dbg] MQTTSubscribe(2147):                  QoS : 1
[dbg] MQTTSubscribe(2148):        Packet Length : 59
[inf] wrapper_mqtt_subscribe(2928): mqtt subscribe packet sent,topic = /ota/device/upgrade/a1wOVhf0PmQ/T10YogSxts4YVtugH5at!
[dbg] wrapper_mqtt_subscribe(2917): PERFORM subscribe to '/sys/a1wOVhf0PmQ/T10YogSxts4YVtugH5at/thing/config/get_reply' (msgId=4)
[dbg] MQTTSubscribe(2145):         Packet Ident : 00000004
[dbg] MQTTSubscribe(2146):                Topic : /sys/a1wOVhf0PmQ/T10YogSxts4YVtugH5at/thing/config/get_reply
[dbg] MQTTSubscribe(2147):                  QoS : 0
[dbg] MQTTSubscribe(2148):        Packet Length : 67
[inf] wrapper_mqtt_subscribe(2928): mqtt subscribe packet sent,topic = /sys/a1wOVhf0PmQ/T10YogSxts4YVtugH5at/thing/config/get_reply!
[dbg] wrapper_mqtt_subscribe(2917): PERFORM subscribe to '/sys/a1wOVhf0PmQ/T10YogSxts4YVtugH5at/thing/config/push' (msgId=5)
[dbg] MQTTSubscribe(2145):         Packet Ident : 00000005
[dbg] MQTTSubscribe(2146):                Topic : /sys/a1wOVhf0PmQ/T10YogSxts4YVtugH5at/thing/config/push
[dbg] MQTTSubscribe(2147):                  QoS : 0
[dbg] MQTTSubscribe(2148):        Packet Length : 62
[inf] wrapper_mqtt_subscribe(2928): mqtt subscribe packet sent,topic = /sys/a1wOVhf0PmQ/T10YogSxts4YVtugH5at/thing/config/push!
_ota_mqtt_client|202 :: wait ota upgrade command....
[dbg] iotx_mc_cycle(1547): PUBACK
event_handle|079 :: publish success, packet-id=1
[dbg] iotx_mc_cycle(1557): SUBACK
[dbg] iotx_mc_handle_recv_SUBACK(1055):         Return Value : 1
[dbg] iotx_mc_handle_recv_SUBACK(1056):            Packet ID : 2
[dbg] iotx_mc_handle_recv_SUBACK(1057):                Count : 1
[dbg] iotx_mc_handle_recv_SUBACK(1059):      Granted QoS[00] : 1
[dbg] _iotx_mqtt_event_handle_sub(1015): packet_id = 2, event_type=3
event_handle|055 :: subscribe success, packet-id=2
[dbg] iotx_mc_cycle(1557): SUBACK
[dbg] iotx_mc_handle_recv_SUBACK(1055):         Return Value : 1
[dbg] iotx_mc_handle_recv_SUBACK(1056):            Packet ID : 3
[dbg] iotx_mc_handle_recv_SUBACK(1057):                Count : 1
[dbg] iotx_mc_handle_recv_SUBACK(1059):      Granted QoS[00] : 1
[dbg] _iotx_mqtt_event_handle_sub(1015): packet_id = 3, event_type=3
event_handle|055 :: subscribe success, packet-id=3
[dbg] iotx_mc_cycle(1557): SUBACK
[dbg] iotx_mc_handle_recv_SUBACK(1055):         Return Value : 1
[dbg] iotx_mc_handle_recv_SUBACK(1056):            Packet ID : 4
[dbg] iotx_mc_handle_recv_SUBACK(1057):                Count : 1
[dbg] iotx_mc_handle_recv_SUBACK(1059):      Granted QoS[00] : 1
[dbg] _iotx_mqtt_event_handle_sub(1015): packet_id = 4, event_type=3
event_handle|055 :: subscribe success, packet-id=4
_ota_mqtt_client|202 :: wait ota upgrade command....
[dbg] iotx_mc_cycle(1557): SUBACK
[dbg] iotx_mc_handle_recv_SUBACK(1055):         Return Value : 1
[dbg] iotx_mc_handle_recv_SUBACK(1056):            Packet ID : 5
[dbg] iotx_mc_handle_recv_SUBACK(1057):                Count : 1
[dbg] iotx_mc_handle_recv_SUBACK(1059):      Granted QoS[00] : 1
[dbg] _iotx_mqtt_event_handle_sub(1015): packet_id = 5, event_type=3
event_handle|055 :: subscribe success, packet-id=5
_ota_mqtt_client|202 :: wait ota upgrade command....
_ota_mqtt_client|202 :: wait ota upgrade command....
```

From IoT Platform console, run the firmware OTA process, and you should see:

<pre>
[dbg] iotx_mc_cycle(1565): PUBLISH
[inf] iotx_mc_handle_recv_PUBLISH(1402): Downstream Topic: '/ota/device/upgrade/a1wOVhf0PmQ/T10YogSxts4YVtugH5at'
[inf] iotx_mc_handle_recv_PUBLISH(1403): Downstream Payload:

< {
<     "code": "1000",
<     "data": {
<         "size": 314676,
<         "sign": "24545b9331082cc3b4faceb9d16b2e8c",
<         "version": "1577151897",
<         "url": "https: //ota.iot-thing.cn-shanghai.aliyuncs.com/ota/fa24240997fa39c9174a2a7c1325df24/ck4j7kovi00002688nivip21r.bin?Expires=1577238418&OSSAccessKeyId=cS8uRRy54RszYWna&Signature=FQgpZxIpUxWzfAU8vzgzI7za29Y%3D",
<         "signMethod": "Md5",
<         "md5": "24545b9331082cc3b4faceb9d16b2e8c"
<     },
<     "id": 1577152018928,
<     "message": "success"
< }

[dbg] iotx_mc_handle_recv_PUBLISH(1408):         Packet Ident : 00000000
[dbg] iotx_mc_handle_recv_PUBLISH(1409):         Topic Length : 52
[dbg] iotx_mc_handle_recv_PUBLISH(1413):           Topic Name : /ota/device/upgrade/a1wOVhf0PmQ/T10YogSxts4YVtugH5at
[dbg] iotx_mc_handle_recv_PUBLISH(1416):     Payload Len/Room : 416 / 424
[dbg] iotx_mc_handle_recv_PUBLISH(1417):       Receive Buflen : 481
[dbg] iotx_mc_handle_recv_PUBLISH(1433): delivering msg ...
[dbg] iotx_mc_deliver_message(1253): topic be matched
[dbg] otamqtt_UpgrageCb(111): topic=/ota/device/upgrade/a1wOVhf0PmQ/T10YogSxts4YVtugH5at
[dbg] otamqtt_UpgrageCb(112): len=416, topic_msg={"code":"1000","data":{"size":314676,"sign":"24545b9331082cc3b4faceb9d16b2e8c","version":"1577151897","url":"https://ota.iot-thing.cn-shanghai.aliyuncs.com/ota/fa24240997fa39c9174a2a7c1325df24/ck4j7kovi00002688nivip21r.bin?Expires=15772 ...
[dbg] otamqtt_UpgrageCb(129): receive device upgrade
[inf] ofc_Init(46): protocol: https
_ota_mqtt_client|217 :: Firmware size: 314676 bytes, version: 1577151897
[dbg] httpclient_connect(418): calling TCP or TLS connect HAL for [1/3] iteration
Loading the CA root certificate ...
 ok (0 skipped)
start prepare client cert .
start mbedtls_pk_parse_key[]
Connecting to /ota.iot-thing.cn-shanghai.aliyuncs.com/443...
 ok
  . Setting up the SSL/TLS structure...
 ok
Performing the SSL/TLS handshake...
 ok
  . Verifying peer X.509 certificate..
certificate verification result: 0x00
[dbg] httpclient_connect(427): rc = client->net.connect() = 0, success @ [1/3] iteration
[dbg] _http_send_header(171): REQUEST (Length: 312 Bytes)
> GET /ota/fa24240997fa39c9174a2a7c1325df24/ck4j7kovi00002688nivip21r.bin?Expires=1577238418&OSSAccessKeyId=cS8uRRy54RszYWna&Signature=FQgpZxIpUxWzfAU8vzgzI7za29Y%3D HTTP/1.1
> Host: ota.iot-thing.cn-shanghai.aliyuncs.com
> Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
> Range: bytes=0-
>
[inf] _http_recv(214): ret of _http_recv is 32
[dbg] httpclient_recv_response(488): RESPONSE (Length: 32 Bytes)
< HTTP/1.1 206 Partial Content
< Da
[dbg] _http_parse_response_header(374): Reading headers: HTTP/1.1 206 Partial Content
[inf] _http_recv(214): ret of _http_recv is 32
[inf] _http_recv(214): ret of _http_recv is 32
[inf] _http_recv(214): ret of _http_recv is 32
[inf] _http_recv(214): ret of _http_recv is 32
[inf] _http_recv(214): ret of _http_recv is 32
[inf] _http_recv(214): ret of _http_recv is 32
[inf] _http_recv(214): ret of _http_recv is 32
[inf] _http_recv(214): ret of _http_recv is 32
[inf] _http_recv(214): ret of _http_recv is 32
[inf] _http_recv(214): ret of _http_recv is 32
[inf] _http_recv(214): ret of _http_recv is 32
[inf] _http_recv(214): ret of _http_recv is 32
[inf] _http_recv(214): ret of _http_recv is 32
[inf] _http_recv(214): ret of _http_recv is 32
[inf] _http_recv(214): ret of _http_recv is 32
[inf] _http_recv(214): ret of _http_recv is 32
[inf] _http_recv(214): ret of _http_recv is 96
[dbg] _http_get_response_body(326): Total- remaind Payload: 314645 Bytes; currently Read: 96 Bytes
[inf] MQTTPublish(2588): Upstream Topic: '/ota/device/progress/a1wOVhf0PmQ/T10YogSxts4YVtugH5at'
[inf] MQTTPublish(2589): Upstream Payload:

> {
>     "id": 0,
>     "params": {
>         "step": "0",
>         "desc": "Enter in downloading state"
>     }
> }

_ota_mqtt_client|228 :: IOT_OTA_FetchYield result: 127
[inf] _http_recv(214): ret of _http_recv is 127
[dbg] _http_get_response_body(326): Total- remaind Payload: 314549 Bytes; currently Read: 127 Bytes
_ota_mqtt_client|228 :: IOT_OTA_FetchYield result: 127
[inf] _http_recv(214): ret of _http_recv is 127
[dbg] _http_get_response_body(326): Total- remaind Payload: 314422 Bytes; currently Read: 127 Bytes
</pre>

At the end of firmware download process, you should see:

```
_ota_mqtt_client|228 :: IOT_OTA_FetchYield result: 127
[inf] _http_recv(214): ret of _http_recv is 127
[dbg] _http_get_response_body(326): Total- remaind Payload: 224 Bytes; currently Read: 127 Bytes
_ota_mqtt_client|228 :: IOT_OTA_FetchYield result: 127
[inf] _http_recv(214): ret of _http_recv is 97
[dbg] _http_get_response_body(326): Total- remaind Payload: 97 Bytes; currently Read: 97 Bytes
_ota_mqtt_client|228 :: IOT_OTA_FetchYield result: 97
[inf] MQTTPublish(2588): Upstream Topic: '/ota/device/progress/a1wOVhf0PmQ/T10YogSxts4YVtugH5at'
[inf] MQTTPublish(2589): Upstream Payload:

> {
>     "id": 0,
>     "params": {
>         "step": "100",
>         "desc": ""
>     }
> }

[inf] MQTTPublish(2588): Upstream Topic: '/ota/device/progress/a1wOVhf0PmQ/T10YogSxts4YVtugH5at'
[inf] MQTTPublish(2589): Upstream Payload:

> {
>     "id": 0,
>     "params": {
>         "step": "100",
>         "desc": "hello"
>     }
> }

[dbg] IOT_OTA_Ioctl(865): origin=24545b9331082cc3b4faceb9d16b2e8c, now=24545b9331082cc3b4faceb9d16b2e8c
_ota_mqtt_client|270 :: The firmware is valid
need release client crt&key
ssl_disconnect
[inf] httpclient_close(503): client disconnected
[dbg] iotx_mc_disconnect(2642): rc = MQTTDisconnect() = 0
need release client crt&key
ssl_disconnect
[inf] iotx_mc_disconnect(2651): mqtt disconnect!
[inf] wrapper_mqtt_release(2830): mqtt release!
main|332 :: out of sample!
```

Reset the system (maybe press `r` key from host console):

```
System reset after 2 secs...
```

Check the boot meesage generated by mbed-bootloader. It should show firmware update message. Firmware header and firmware itself are updated to internal flash for active here.

```
Mbed Bootloader
[DBG ] Update active firmware
[DBG ] Erase active application
[DBG ] Write header
[DBG ] Copy application
[DBG ] Verify application
[DBG ] New active firmware is valid
booting...
```

Application message should show as usual, except firmware version:

```
The device has provisioned. Skip provision process
main|322 :: hello main func
[prt] log level set as: [ 5 ]
[wrn] IOT_MQTT_Construct(274): Using default hostname: 'a1wOVhf0PmQ.iot-as-mqtt.cn-shanghai.aliyuncs.com'
[wrn] IOT_MQTT_Construct(281): Using default port: [443]
[wrn] IOT_MQTT_Construct(288): Using default client_id: a1wOVhf0PmQ.T10YogSxts4YVtugH5at|timestamp=2524608000000,_v=sdk-c-3.1.0,securemode=2,signmethod=hmacsha256,lan=C,_ss=1,gw=0,ext=0|
[wrn] IOT_MQTT_Construct(295): Using default username: T10YogSxts4YVtugH5at&a1wOVhf0PmQ
[wrn] IOT_MQTT_Construct(303): Using default password: ******
[dbg] _mqtt_nwk_connect(2708): calling TCP or TLS connect HAL for [1/3] iteration
Loading the CA root certificate ...
 ok (0 skipped)
start prepare client cert .
start mbedtls_pk_parse_key[]
Connecting to /a1wOVhf0PmQ.iot-as-mqtt.cn-shanghai.aliyuncs.com/443...
Connected to the network successfully. IP address: 192.168.8.105
 ok
  . Setting up the SSL/TLS structure...
 ok
Performing the SSL/TLS handshake...
 ok
  . Verifying peer X.509 certificate..
certificate verification result: 0x00
[dbg] _mqtt_nwk_connect(2726): rc = pClient->ipstack.connect() = 0, success @ [1/3] iteration
[inf] _mqtt_connect(722): connect params: MQTTVersion=4, clientID=a1wOVhf0PmQ.T10YogSxts4YVtugH5at|timestamp=2524608000000,_v=sdk-c-3.1.0,securemode=2,signmethod=hmacsha256,lan=C,_ss=1,gw=0,ext=0|, keepAliveInterval=120, username=T10YogSxts4YVtugH5at&a1wOVhf0PmQ
[inf] _mqtt_connect(768): mqtt connect success!
```

Check reported firmware version after update. It should be as entered on IoT Platform console in the above section.

<pre>
[dbg] iotx_report_firmware_version(146): firmware version report start in MQTT
[dbg] iotx_report_firmware_version(159): firmware report topic: /ota/device/inform/a1wOVhf0PmQ/T10YogSxts4YVtugH5at
[dbg] iotx_report_firmware_version(172): firmware report data: {"id":"0","params":{"version":"1577151897"}}
[inf] MQTTPublish(2588): Upstream Topic: '/ota/device/inform/a1wOVhf0PmQ/T10YogSxts4YVtugH5at'
[inf] MQTTPublish(2589): Upstream Payload:

> {
>     "id": "0",
>     "params": {
>         "version": "1577151897"
>     }
> }

[dbg] iotx_report_firmware_version(181): firmware version report finished, iotx_publish() = 1
</pre>

The other application message after firmware update:

```
[dbg] wrapper_mqtt_subscribe(2917): PERFORM subscribe to '/ota/device/request/a1wOVhf0PmQ/T10YogSxts4YVtugH5at' (msgId=2)
[dbg] MQTTSubscribe(2145):         Packet Ident : 00000002
[dbg] MQTTSubscribe(2146):                Topic : /ota/device/request/a1wOVhf0PmQ/T10YogSxts4YVtugH5at
[dbg] MQTTSubscribe(2147):                  QoS : 1
[dbg] MQTTSubscribe(2148):        Packet Length : 59
[inf] wrapper_mqtt_subscribe(2928): mqtt subscribe packet sent,topic = /ota/device/request/a1wOVhf0PmQ/T10YogSxts4YVtugH5at!
[dbg] wrapper_mqtt_subscribe(2917): PERFORM subscribe to '/ota/device/upgrade/a1wOVhf0PmQ/T10YogSxts4YVtugH5at' (msgId=3)
[dbg] MQTTSubscribe(2145):         Packet Ident : 00000003
[dbg] MQTTSubscribe(2146):                Topic : /ota/device/upgrade/a1wOVhf0PmQ/T10YogSxts4YVtugH5at
[dbg] MQTTSubscribe(2147):                  QoS : 1
[dbg] MQTTSubscribe(2148):        Packet Length : 59
[inf] wrapper_mqtt_subscribe(2928): mqtt subscribe packet sent,topic = /ota/device/upgrade/a1wOVhf0PmQ/T10YogSxts4YVtugH5at!
[dbg] wrapper_mqtt_subscribe(2917): PERFORM subscribe to '/sys/a1wOVhf0PmQ/T10YogSxts4YVtugH5at/thing/config/get_reply' (msgId=4)
[dbg] MQTTSubscribe(2145):         Packet Ident : 00000004
[dbg] MQTTSubscribe(2146):                Topic : /sys/a1wOVhf0PmQ/T10YogSxts4YVtugH5at/thing/config/get_reply
[dbg] MQTTSubscribe(2147):                  QoS : 0
[dbg] MQTTSubscribe(2148):        Packet Length : 67
[inf] wrapper_mqtt_subscribe(2928): mqtt subscribe packet sent,topic = /sys/a1wOVhf0PmQ/T10YogSxts4YVtugH5at/thing/config/get_reply!
[dbg] wrapper_mqtt_subscribe(2917): PERFORM subscribe to '/sys/a1wOVhf0PmQ/T10YogSxts4YVtugH5at/thing/config/push' (msgId=5)
[dbg] MQTTSubscribe(2145):         Packet Ident : 00000005
[dbg] MQTTSubscribe(2146):                Topic : /sys/a1wOVhf0PmQ/T10YogSxts4YVtugH5at/thing/config/push
[dbg] MQTTSubscribe(2147):                  QoS : 0
[dbg] MQTTSubscribe(2148):        Packet Length : 62
[inf] wrapper_mqtt_subscribe(2928): mqtt subscribe packet sent,topic = /sys/a1wOVhf0PmQ/T10YogSxts4YVtugH5at/thing/config/push!
_ota_mqtt_client|202 :: wait ota upgrade command....
[dbg] iotx_mc_cycle(1547): PUBACK
event_handle|079 :: publish success, packet-id=1
[dbg] iotx_mc_cycle(1557): SUBACK
[dbg] iotx_mc_handle_recv_SUBACK(1055):         Return Value : 1
[dbg] iotx_mc_handle_recv_SUBACK(1056):            Packet ID : 2
[dbg] iotx_mc_handle_recv_SUBACK(1057):                Count : 1
[dbg] iotx_mc_handle_recv_SUBACK(1059):      Granted QoS[00] : 1
[dbg] _iotx_mqtt_event_handle_sub(1015): packet_id = 2, event_type=3
event_handle|055 :: subscribe success, packet-id=2
[dbg] iotx_mc_cycle(1557): SUBACK
[dbg] iotx_mc_handle_recv_SUBACK(1055):         Return Value : 1
[dbg] iotx_mc_handle_recv_SUBACK(1056):            Packet ID : 3
[dbg] iotx_mc_handle_recv_SUBACK(1057):                Count : 1
[dbg] iotx_mc_handle_recv_SUBACK(1059):      Granted QoS[00] : 1
[dbg] _iotx_mqtt_event_handle_sub(1015): packet_id = 3, event_type=3
event_handle|055 :: subscribe success, packet-id=3
[dbg] iotx_mc_cycle(1557): SUBACK
[dbg] iotx_mc_handle_recv_SUBACK(1055):         Return Value : 1
[dbg] iotx_mc_handle_recv_SUBACK(1056):            Packet ID : 4
[dbg] iotx_mc_handle_recv_SUBACK(1057):                Count : 1
[dbg] iotx_mc_handle_recv_SUBACK(1059):      Granted QoS[00] : 1
[dbg] _iotx_mqtt_event_handle_sub(1015): packet_id = 4, event_type=3
event_handle|055 :: subscribe success, packet-id=4
_ota_mqtt_client|202 :: wait ota upgrade command....
[dbg] iotx_mc_cycle(1557): SUBACK
[dbg] iotx_mc_handle_recv_SUBACK(1055):         Return Value : 1
[dbg] iotx_mc_handle_recv_SUBACK(1056):            Packet ID : 5
[dbg] iotx_mc_handle_recv_SUBACK(1057):                Count : 1
[dbg] iotx_mc_handle_recv_SUBACK(1059):      Granted QoS[00] : 1
[dbg] _iotx_mqtt_event_handle_sub(1015): packet_id = 5, event_type=3
event_handle|055 :: subscribe success, packet-id=5
_ota_mqtt_client|202 :: wait ota upgrade command....
_ota_mqtt_client|202 :: wait ota upgrade command....
```

### Walk through source code

#### Pre-main (`pre-main/`)

In Mbed OS boot sequence, `mbed_main()`, designed for user application override, is run before `main()`.
Here, it is used to run the following tasks:

1.  Simulate provision process for development
    1.  Reset [kvstore](https://os.mbed.com/docs/mbed-os/v5.15/reference/storage.html)
    1.  Inject entropy seed (if no entropy source) for mbedtls communication
    1.  Inject ROT key (device key) for firmware OTA
    1.  Initialize user filesystem (if enabled)
    1.  Mark the device as provisioned
    ```
    The device has not provisioned yet. Try to provision it...
    Provision for development...
    Reset kvstore...
    Reset kvstore...OK
    Inject ROT key...
    Inject ROT key...OK
    Mount user filesystem...
    User filesystem region: start/end address: 0000000004400000/0000000076100000
    Mount user filesystem...OK
    Provision for development...OK
    ```

1.  Set up event queue for dispatching host command. Currently, press the following command:
    1.  `h` for printing heap statistics
        ```
        ** MBED HEAP STATS **
        **** current_size: 28779
        **** max_size    : 32180
        *****************************
        ```

    1.  `s` for printing stack statistics
        ```
        ** MBED THREAD STACK STATS **
        Thread: 0x20003170, Stack size: 2048, Max stack: 552
        Thread: 0x20005da8, Stack size: 512, Max stack: 104
        Thread: 0x20005d64, Stack size: 8192, Max stack: 3440
        Thread: 0x20005dec, Stack size: 768, Max stack: 96
        *****************************
        ```

    1.  `r` for resetting system
        ```
        System reset after 2 secs...
        ```

#### Main with firmware OTA over MQTT (`source/ota_example_mqtt.c`)

The examplle here is extract from [Alibaba Cloud IoT C-SDK](https://github.com/aliyun/iotkit-embedded) and shows firmware OTA with Alibaba Cloud IoT Platform over MQTT protocol.
Related explanation can be found in [Device OTA](https://www.alibabacloud.com/help/doc-detail/97351.htm).

During firmware download process, to be compatible with mbed-bootloader, write downloaded firmware fragments through `MBEDBL_UCP` API exported in [mbed-bootloaer firmware update library](https://github.com/OpenNuvoton/NuMaker-mbed-bootloader-UCP).

#### Experimental examples (`TARGET_IGNORE/examples/`)

The examples here are experimental. They are not well tested and don't rely on them.

#### Pre-built bootloader (`bootloader/`)

This directory contains pre-built bootloader for supported targets.
The flash and storage layout of this example must be compatible with corresponding bootloader.

### Flash and storage layout

This section shows layout of flash and storage.

**Note**: For simplicity, gap and alignment requirements, e.g. flash erase size and storage block size, are not represented here.

#### Internal flash layout

    +---------------------------+ <-+ MBED_ROM_START + MBED_ROM_SIZE
    |        FREE SPACE         |
    +---------------------------+ <-+ FLASHIAP_APP_ROM_END_ADDR
    |                           |
    |                           |
    |        ACTIVE APP         |
    |                           |
    |                           |
    +---------------------------+ <-+ MBED_APP_START =
    +                           |     MBED_ROM_START + target.app_offset
    |ACTIVE APP METADATA HEADER |
    |                           |
    +---------------------------+ <-+ MBED_ROM_START + target.header_offset =
    |                           |     update-client.application-details =
    |    KVSTORE (internal)     |     storage_filesystem.internal_base_address +
    |                           |     storage_filesystem.rbp_internal_size
    +---------------------------+ <-+ storage_filesystem.internal_base_address =
    |                           |     MBED_ROM_START + MBED_BOOTLOADER_SIZE
    |        BOOTLOADER         |
    |                           |
    +---------------------------+ <-+ MBED_ROM_START

-   `BOOTLOADER`: Area for placing bootloader code. It is written with `NuMaker-mbed-Aliyun-IoT-OTA-example.bin` flash, and won't be re-written until next re-flash.
-   `KVSTORE (internal)`: Area for kvstore internal part (located in internal flash).
-   `ACTIVE APP METADATA HEADER` Area for placing metadata header of active application. It is first written with `NuMaker-mbed-Aliyun-IoT-OTA-example.bin` flash and then re-written by mbed-bootloader for firmware update.
-   `ACTIVE APP`: Area for placing application code. Its start is configurable and its size is determined by image file size. It is first written with `NuMaker-mbed-Aliyun-IoT-OTA-example.bin` flash and then re-written by mbed-bootloader for firmware update.

**Note**: The symbols `MBED_ROM_START`/`MBED_ROM_SIZE` are generated by Mbed OS build tool. They mean start/size of internal flash.

**Note**: The symbol `MBED_APP_START` is generated by Mbed OS build tool and its definition can be found at [Bootloader configuration](https://os.mbed.com/docs/mbed-os/v5.15/reference/bootloader-configuration.html).

**Note**: The symbol `FLASHIAP_APP_ROM_END_ADDR` comes from `mbed-os/drivers/FlashIAP.h`. It means end of application code.

**Note**: This layout must be compatible with mbed-bootloader.

#### External storage (`NUSD`) layout

    +---------------------------+ <-+ user-filesystem.blockdevice-address +
    |                           |     user-filesystem.blockdevice-size
    |     USER FILESYSTEM       |
    |                           |
    |---------------------------| <-+ user-filesystem.blockdevice-address
    |           GAP             |
    +---------------------------+ <=+ update-client.storage-address +
    |                           |     update-client.storage-size
    |    FIRMWARE CANDIDATE     |
    |                           |
    |---------------------------| <-+ update-client.storage-address
    |           GAP             |
    +---------------------------+ <-+ storage_filesystem.external_base_address +
    |                           |     storage_filesystem.external_size
    |    KVSTORE (external)     |
    |                           |
    +---------------------------+ <-+ storage_filesystem.external_base_address

-   `KVSTORE (external)`: Area for kvstore external part (located in external storage)
-   `FIRMWARE CANDIDATE`: Area for placing firmware candidate downloaded in firmware OTA
-   `USER FILESYSTEM`: Area for user filesystem. It is defined in `user-filesystem/mbed_lib.json`.

**Note**: When `user-filesystem.blockdevice-size` equals 0, it means extension to end of storage.

**Note**: User must guarantee these areas don't overlap.

**Note**: This layout must be compatible with mbed-bootloader.
