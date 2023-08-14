# TeddyCloud

## Features
TeddyCloud is an alternative server for your Toniebox, allowing you to host the could services locally.
This gives you the control about which data is sent to the original manufacturer's cloud and allows you
to host your own figurine audio files on e.g. your NAS or any other server.

Currently implemented are:
* Provide audio content over the air
* Cache original tonie audio content
* Simulate live content (.live)
* Passthrough original tonie audio content
* Basic Web fronted
* Filter custom tags to prevent deletion (.nocloud)
* Configure maximum volume for speaker and headphones
* Configure LED
* Configure slapping
* Customize original box sounds (ex. jingle) over the air
* Extract/Inject certitifcates on a esp32 firmware dump

## Planned
* Decode RTNL logs
* MQTT client
* Home Assistant integration (ideas welcome)
* TeddyBench integration
* [Web frontend](https://github.com/toniebox-reverse-engineering/teddycloud_web) (full stack developers welcome)

## Preparation
### Generate certificates
First of all you'll need to generate the CA and certificates with the starting date 2015-11-03: ```./gencerts.sh``` Those will be placed in ```/certs/server/```.
This also generates the replacement CA for the toniebox ```certs/server/ca.der```.
If you are using docker, this will happen automatically.

### Dump certificates of your toniebox
You'll need the ```flash:/cert/ca.der``` (Boxine CA), ```flash:/cert/client.der``` (Client Cert) and ```flash:/cert/private.der``` (Client private key). Place those files under ```/certs/client/*```
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
You can extract the flash memory via the debug port of the box and the esptool. Keep your backup!
Please connect the jumper J100 (Boot) and reset the box to put it into the required mode. Connect your 3.3V UART to J103 (TxD, RxD, GND).

```
esptool.py -b 921600 read_flash 0x0 0x800000 tb.esp32.bin
mkdir certs/client/esp32
bin/teddycloud ESP32CERT extract tb.esp32.bin certs/client/esp32
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
**Beware** The ```blockCheckRemove.310```, ```noCerts.305``` and the ```noHide.308``` patch breaks the content passthrough to Boxine. If you are using firmware 3.1.0_BF4 isn't compatible with many patches, except the alt* ones. Please disable them by removing them in the [```ngCfg.json```](https://github.com/toniebox-reverse-engineering/hackiebox_cfw_ng/wiki/Bootloader#configuration) on the SD card.

To have the patched toniebox booting, stage 2 of the [hackiebox_cfw_ng install](https://github.com/toniebox-reverse-engineering/hackiebox_cfw_ng/wiki/Install#2-bootloader-stage-2) has to be modified, so that only the content of the *sd* folder is copied and the ```ngCfg.json```  selects e.g. ```ofw2``` as the active image with activated alt* patches.

#### CC3235
Replace the original CA within your flash dump with the replacement CA and reflash it to your box. I recommend flashrom for that
```
cc3200tool -if cc32xx-flash.bin -of cc32xx-flash.customca.bin -d cc32xx customca.der /cert/ca.der
```

#### ESP32
Replace the original CA within your flash dump with esptool.

```
cp tb.esp32.bin tb.esp32.fakeca.bin
bin/teddycloud ESP32CERT inject tb.esp32.fakeca.bin certs/client/esp32-fakeca
esptool.py -b 921600 write_flash 0x0 tb.esp32.fakeca.bin
```

### DNS
#### CC3200 with altUrl patch
With a CC3200 box it is recommened to use the altUrl patch. Set the DNS entries for ```prod.revvox``` and ```rtnl.revvox``` to the TeddyCloud servers ip-address. 

#### CC3235 / ESP32
Set the DNS entries for ```prod.de.tbs.toys``` and ```rtnl.bxcl.de``` to the TeddyCloud servers ip-address. Beware, this will cut off the connection of all tonieboxes within your network, which arn't patched with your replacement CA!

### Content
Please put your content into the ```/data/content/default/``` in the same structure as on your toniebox. You can place an empty ```500304E0.live``` file beside the content files to mark them as live. With ```500304E0.nocloud``` you can prevent the usage of the Boxine cloud for that tag.

### Webinterface
Currently the interface to teddycloud is reachable through the IP of the docker container at port 80 or 443 (depending on your ```docker-compose.yaml```). Changes affecting the toniebox (volume, LED) which are made through this interface will only be reflected onto the toniebox after pressing the big ear for a few seconds until a beep occurs.

As an additional frontend is still being developed, you can reach the frontend at ```xxx.xxx.xxx/web```. Changes made here are instantly live on the box.

## Docker hints
The docker container automatically generates the server certificates on first run. You can extract the ```certs/server/ca.der``` for your box after that. The container won't run without the ```flash:/cert/ca.der``` (Boxine CA), ```flash:/cert/client.der``` (Client Cert) and ```flash:/cert/private.der``` (Client private key).

An example [docker-compose.yaml can be found within the docker subdir.](docker/docker-compose.yaml)


## Attribution

The icons used are from here:
* img_empty.png: https://www.flaticon.com/free-icon/ask_1372671
* img_unknown.png: https://www.flaticon.com/free-icon/ask_1923795
* img_custom.png/favicon.ico: https://www.flaticon.com/free-icon/dog_2829818

Thanks for the original authors for these great icons.

