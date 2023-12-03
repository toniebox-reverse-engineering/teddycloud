# TeddyCloud

## Features
TeddyCloud is an alternative server for your Toniebox, allowing you to host the cloud services locally.
This gives you the control about which data is sent to the original manufacturer's cloud and allows you
to host your own figurine audio files on e.g. your NAS or any other server.

Currently implemented are:
* Provide audio content over the air
* Cache original tonie audio content
* Simulate live content (.live)
* Passthrough original tonie audio content
* Convert any audio file to a tonie audio file (web)
* On-the-fly convert audio streams via ffmpeg for webradio and streams
* Basic Web fronted
* Filter custom tags to prevent deletion (.nocloud)
* Configure maximum volume for speaker and headphones
* Configure LED
* Configure slapping
* Customize original box sounds (ex. jingle) over the air
* Extract/Inject certitifcates on a esp32 firmware dump
* Decode RTNL logs
* MQTT client
* Home Assistant integration (MQTT)
* [Web frontend](https://github.com/toniebox-reverse-engineering/teddycloud_web) (full stack developers welcome)

## Planned
* teddyBench integration

## Preparation
### Generate certificates
First of all you'll need to generate the CA and certificates with the starting date 2015-11-03: ```./gencerts.sh``` Those will be placed in ```/certs/server/```.
This also generates the replacement CA for the toniebox ```certs/server/ca.der```.
If you are using docker, this will happen automatically.

### Dump certificates of your toniebox
You'll need the ```flash:/cert/ca.der``` (Boxine CA), ```flash:/cert/client.der``` (Client Cert) and ```flash:/cert/private.der``` (Client private key). Place those files under ```/certs/client/*```. You can either power the box with the battery (be sure it is note empty) or with the power supply. (recommended)

#### CC3200
You can use the [cc3200tool](https://github.com/toniebox-reverse-engineering/cc3200tool) to dump your certificates over the Tag Connect debug port of the box. If you have installed the HackieboxNG Bootloader you should already have those files in your backup.
```
cc3200tool -p COM3 read_file /cert/ca.der cert/ca.der read_file /cert/private.der cert/private.der read_file /cert/client.der cert/client.der
```
#### CC3235
You'll have to manually extract it from the flash of the box with a SOP8 clamp directly from the memory or by desoldering it. Reading in-circuit can be tricky, but is possible. I recommend flashrom as tool for that. It may be necessary to use a more recent version of it.
You can use the [cc3200tool](https://github.com/toniebox-reverse-engineering/cc3200tool) to extract your certificates from the flash dump.
```
cc3200tool -if cc32xx-flash.bin -d cc32xx read_all_files extract/
```
#### ESP32
You can extract the flash memory via the debug port of the box and the esptool. Keep your backup! Please use a recent version of esptool. (>v4.4)
Please connect the jumper J100 (Boot) and reset the box to put it into the required mode. Connect your 3.3V UART to J103 (TxD, RxD, GND).
If connected with the Boot jumper, the box just start in "DOWNLOAD (USB/UART0)" mode. (Check with a serial monitor). Beware, if the serial monitor is open it will block esptool.py from accessing the esp. If you get a "BROWNOUT_RST" check your power supply / battery. "SPI_FAST_FLASH_BOOT" indicates a boot without the J100 jumper. 

##### Browser based
You can use the build in ESP32 box flashing tool in the webinterface of teddyCloud to backup your box with "Read ESP32".
After that you can manually extract them into the ```/certs/client/``` directory.
```
# Please check the filename of your backup
teddycloud ESP32CERT extract data/firmware/ESP32_<mac>.bin certs/client
```

##### Legacy
```
# extract firmware
esptool.py -b 921600 read_flash 0x0 0x800000 tb.esp32.bin
# extract certficates from firmware
mkdir certs/client/esp32
teddycloud ESP32CERT extract tb.esp32.bin certs/client/esp32
# Copy box certificates to teddyCloud
cp certs/client/esp32/CLIENT.DER  certs/client/client.der
cp certs/client/esp32/PRIVATE.DER  certs/client/private.der
cp certs/client/esp32/CA.DER  certs/client/ca.der

# Copy certificates to temporary dir
mkdir certs/client/esp32-fakeca
cp certs/client/esp32/CLIENT.DER certs/client/esp32-fakeca/
cp certs/client/esp32/PRIVATE.DER certs/client/esp32-fakeca/
cp certs/server/ca.der certs/client/esp32-fakeca/CA.DER
```

### Flash the replacement CA
#### CC3200
It is recommended to flash the replacement CA to /cert/c2.der and use the hackiebox-ng bootloader with the altCA patch. This will allow you to switch between the original and your replacement certificate. If you have installed the HackieboxNG Bootloader and the Hackiebox CFW you may upload the certificate via the webinterface of the CFW.
```
cc3200tool -p COM3 write_file certs/server/ca.der /cert/c2.der
```
**Beware** The ```blockCheckRemove.310```, ```noCerts.305``` and the ```noHide.308``` patch breaks the content passthrough to Boxine. If you are using firmware 3.1.0_BF4 isn't compatible with many patches, except the alt* ones. Please disable them by removing them in the [```ngCfg.json```](https://toniebox-reverse-engineering.github.io/docs/custom-firmware/cc3200/hackieboxng-bl/bootloader/#configuration) on the SD card.

#### CC3235
Replace the original CA within your flash dump with the replacement CA and reflash it to your box. I recommend flashrom for that
```
cc3200tool -if cc32xx-flash.bin -of cc32xx-flash.customca.bin -d cc32xx customca.der /cert/ca.der
```

#### ESP32
##### Browser based
With teddyCloud you can also write a new image with your custom CA and a DNS/IP so the box connects to teddyCloud.
If you have a Fritzbox you can set it to tc.fritz.box (see CC3200 how to configure the hostname on your Fritzbox), if not set it to the IP of teddyCloud.

##### Legacy
Replace the original CA within your flash dump with esptool.

```
# copy firmware backup
cp tb.esp32.bin tb.esp32.fakeca.bin
# inject new CA into firmware
teddycloud ESP32CERT inject tb.esp32.fakeca.bin certs/client/esp32-fakeca
# flash firmware with new CA
esptool.py -b 921600 write_flash 0x0 tb.esp32.fakeca.bin
```

### DNS
#### CC3200 with altUrl patch
With a CC3200 box it is recommened to use the altUrl patch. Set the DNS entries for ```prod.revvox``` and ```rtnl.revvox``` to the TeddyCloud servers ip-address.
If you have a fritzbox you can use the [altUrl tc.fritz.box](https://github.com/toniebox-reverse-engineering/hackiebox_cfw_ng/blob/master/sd-bootloader-ng/bootmanager/sd/revvox/boot/patch/altUrl.tc.fritz.box.json) patch. You'll just have to set the name of your server in your fritzbox to ```tc``` (Heimnetz -> Netzwerk -> Netzwerkverbindungen -> bearbeiten
).
You may also edit the patch yourself to set the ip-address directly. Please beware, it should not be longer than the original url, which is 12 characters.

#### CC3235
Set the DNS entries for ```prod.de.tbs.toys``` and ```rtnl.bxcl.de``` to the TeddyCloud servers ip-address. Beware, this will cut off the connection of all tonieboxes within your network, which arn't patched with your replacement CA!
As an alternative you can set the gateway for the tonieboxes to the ip of teddyCloud. With OpenWRT it works this way:
```
uci set dhcp.teddycloud="tag"
uci set dhcp.teddycloud.dhcp_option="3,1.2.3.4" # 1.2.3.4=teddycloud ip

uci add dhcp host
uci set dhcp.@host[-1].name="toniebox_1"
uci set dhcp.@host[-1].mac="00:11:22:33:44:55" # toniebox mac
uci set dhcp.@host[-1].ip="1.2.3.101" # toniebox_1 ip
uci set dhcp.@host[-1].tag="teddycloud"
uci commit dhcp
/etc/init.d/dnsmasq restart
```

#### ESP32
You can either set the IP/DNS within the image or you may do it like on the CC3235.

### Content
Please put your content into the ```/data/content/default/``` in the same structure as on your toniebox. You can edit ```500304E0.json``` file beside the content files to mark them as live or you can prevent the usage of the Boxine cloud for that tag with the nocloud parameter. By setting a source teddyCloud can stream any content that ffmpeg can decode (urls and files).

### Webinterface
Currently the interface to teddycloud is reachable through the IP of the docker container at port 80 or 443 (depending on your ```docker-compose.yaml```). Changes affecting the toniebox (volume, LED) which are made through this interface will only be reflected onto the toniebox after pressing the big ear for a few seconds until a beep occurs.

As an additional frontend is still being developed, you can reach a second frontend at ```xxx.xxx.xxx/web```. Changes made here are instantly live on the box.

## Docker hints
The docker container automatically generates the server certificates on first run. You can extract the ```certs/server/ca.der``` for your box after that. The container won't run without the ```flash:/cert/ca.der``` (Boxine CA), ```flash:/cert/client.der``` (Client Cert) and ```flash:/cert/private.der``` (Client private key).

An example [docker-compose.yaml can be found within the docker subdir.](docker/docker-compose.yaml)


## Attribution

The icons used are from here:
* img_empty.png: https://www.flaticon.com/free-icon/ask_1372671
* img_unknown.png: https://www.flaticon.com/free-icon/ask_1923795
* img_custom.png/favicon.ico: https://www.flaticon.com/free-icon/dog_2829818

Thanks for the original authors for these great icons.

