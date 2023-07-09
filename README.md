# TeddyCloud

## Features
TeddyCloud is an alternative cloudless server for your Toniebox. 
* Send content over the air
* Simulate live content

## Planned
* Passthrough and cache original tonies
* Update live content only when changed
* Configure maximum volume for speaker and headphones
* Configure LED
* Configure slapping
* Filter custom tags to prevent deletion (.nocloud)
* Decode RTNL logs
* MQTT client

## Preparation
### Generate certificates
First of all you'll need to generate the CA and certificates with the starting date 2015-11-04: ```faketime '2015-11-04 00:00:00' gencerts.sh``` Those will be placed in ```/certs/server/```.
This also generates the replacement CA for the toniebox ```certs/server/ca.der```.

### Dump certificates of your toniebox
You'll need the ```flash:/cert/ca.der``` (Boxing CA), ```flash:/cert/client.der``` (Client Cert) and ```flash:/cert/private.der``` (Client private key). Place those files under ```/certs/*```
#### CC3200
You can use the [cc3200tool](https://github.com/toniebox-reverse-engineering/cc3200tool) to dump your certificates over the Tag Connect debug port of the box.
```
python cc.py -p COM3 read_file /cert/ca.der cert/ca.der read_file /cert/private.der cert/private.der read_file /cert/client.der cert/client.der
```
#### CC3235
You'll have to manually extract it from the flash of the box with a SOP8 clamp directly from the memory or by desoldering it. Reading in-circuit can be tricky, but is possible. 

#### ESP32
You can extract the flash memory either with a SOP8 clamp or via the debug port of the box. 

### Flash the replacement CA
#### CC3200
It is recommended to flash the replacement CA to /cert/c2.der and use the hackiebox-ng bootloader with the altCA patch. This will allow you to switch between the original and your replacement certificate.
```
python cc.py -p COM3 write_file certs/ca.der /cert/c2.der
```

#### CC3235 / ESP32
Replace the original CA within your flash dump with the replacement CA and reflash it to your box.

### DNS
#### CC3200 with altUrl patch
With a CC3200 box it is recommened to use the altUrl patch. Set the DNS entries for ```prod.revvox``` and ```rtnl.revvox``` to the Teddy Cloud servers ip-address. 

#### CC3235 / ESP32
Set the DNS entries for ```prod.de.tbs.toys``` and ```rtnl.bxcl.de``` to the Teddy Cloud servers ip-address. Beware, this will cut off the connection of all tonieboxes within your network, which arn't patched with your replacement CA!

### Content
Please put your content into the ```/www/CONTENT/``` in the same structure as on your toniebox. You can place an empty ```500304E0.live``` file beside the content files to mark them as live.

## Docker hints
The docker container automatically generates the server certificates on first run. You can extract the ```certs/server/ca.der``` for your box after that. The container won't run without the ```flash:/cert/ca.der``` (Boxing CA), ```flash:/cert/client.der``` (Client Cert) and ```flash:/cert/private.der``` (Client private key).

An example [docker-compose.yaml can be found within the docker subdir.](blob/master/docker/docker-compose.yaml)
