#include "error.h"

#define ERROR_COUNT 598 + 1

static char *error_text[ERROR_COUNT];

char *error2text(error_t error)
{
    return error_text[error];
}

void error_text_init()
{
    for (int i = 0; i < ERROR_COUNT; i++)
    {
        error_text[i] = "";
    }

    // (\d*)\t[A-Z_]*\t([A-Za-z0-9 \-]*)
    // error_text[$1] = "$2 [$1]";
    error_text[0] = "Success [0]";
    error_text[1] = "Generic error code [1]";
    error_text[2] = "Invalid parameter [2]";
    error_text[3] = "Specified parameter is out of range [3]";
    error_text[4] = "Bad CRC detected [4]";
    error_text[5] = "Bad block detected [5]";
    error_text[6] = "Invalid recipient [6]";
    error_text[7] = "Invalid interface [7]";
    error_text[8] = "Invalid endpoint [8]";
    error_text[9] = "Alternate setting does not exist [9]";
    error_text[10] = "Unsupported request [10]";
    error_text[11] = "Unsupported configuration [11]";
    error_text[12] = "Unsupported feature [12]";
    error_text[13] = "Endpoint already in use [13]";
    error_text[14] = "USB reset [14]";
    error_text[15] = "Operation aborted [15]";
    error_text[100] = "Out of memory [100]";
    error_text[101] = "Out of resources [101]";
    error_text[102] = "Invalid request [102]";
    error_text[103] = "Not implemented [103]";
    error_text[104] = "Version not supported [104]";
    error_text[105] = "Invalid syntax [105]";
    error_text[106] = "Authentication failed [106]";
    error_text[107] = "Unexpected response [107]";
    error_text[108] = "Invalid response [108]";
    error_text[109] = "Unexpected value [109]";
    error_text[110] = "Wait canceled [110]";
    error_text[200] = "Open failed [200]";
    error_text[201] = "Connection failed [201]";
    error_text[202] = "Connection refused [202]";
    error_text[203] = "Connection closing [203]";
    error_text[204] = "Connection reset [204]";
    error_text[205] = "Not connected [205]";
    error_text[206] = "Already closed [206]";
    error_text[207] = "Already connected [207]";
    error_text[208] = "Invalid socket [208]";
    error_text[209] = "Protocol unreachable [209]";
    error_text[210] = "Port unreachable [210]";
    error_text[211] = "Invalid frame [211]";
    error_text[212] = "Invalid header [212]";
    error_text[213] = "Wrong checksum [213]";
    error_text[214] = "Wrong identifier [214]";
    error_text[215] = "Wrong client ID [215]";
    error_text[216] = "Wrong server ID [216]";
    error_text[217] = "Wrong cookie [217]";
    error_text[218] = "No response received [218]";
    error_text[219] = "Receive queue full [219]";
    error_text[220] = "Timeout [220]";
    error_text[221] = "Operation would block [221]";
    error_text[222] = "Invalid name [222]";
    error_text[223] = "Invalid option [223]";
    error_text[224] = "Unexpected state [224]";
    error_text[225] = "Invalid command [225]";
    error_text[226] = "Invalid protocol [226]";
    error_text[227] = "Invalid status [227]";
    error_text[228] = "Invalid address [228]";
    error_text[229] = "Invalid port [229]";
    error_text[230] = "Invalid message [230]";
    error_text[231] = "Invalid key [231]";
    error_text[232] = "Invalid key length [232]";
    error_text[233] = "Invalid epoch [233]";
    error_text[234] = "Invalid sequence number [234]";
    error_text[235] = "Invalid character [235]";
    error_text[236] = "Invalid length [236]";
    error_text[237] = "Invalid padding [237]";
    error_text[238] = "Invalid MAC [238]";
    error_text[239] = "Invalid tag [239]";
    error_text[240] = "Invalid type [240]";
    error_text[241] = "Invalid value [241]";
    error_text[242] = "Invalid class [242]";
    error_text[243] = "Invalid version [243]";
    error_text[244] = "Invalid PIN code [244]";
    error_text[245] = "Wrong length [245]";
    error_text[246] = "Wrong type [246]";
    error_text[247] = "Wrong encoding [247]";
    error_text[248] = "Wrong value [248]";
    error_text[249] = "Inconsistent value [249]";
    error_text[250] = "Unsupported type [250]";
    error_text[251] = "Unsupported algorithm [251]";
    error_text[252] = "Unsupported cipher suite [252]";
    error_text[253] = "Unsupported cipher mode [253]";
    error_text[254] = "Unsupported cipher algorithm [254]";
    error_text[255] = "Unsupported hash algorithm [255]";
    error_text[256] = "Unsupported key exchange algorithm [256]";
    error_text[257] = "Unsupported signature algorithm [257]";
    error_text[258] = "Unsupported elliptic curve [258]";
    error_text[259] = "Invalid signature algorithm [259]";
    error_text[260] = "Certificate required [260]";
    error_text[261] = "Message too long [261]";
    error_text[262] = "Out of range [262]";
    error_text[263] = "Message discarded [263]";
    error_text[264] = "Invalid packet [264]";
    error_text[265] = "Buffer is empty [265]";
    error_text[266] = "Buffer overflow [266]";
    error_text[267] = "Buffer underflow [267]";
    error_text[268] = "Invalid resource [268]";
    error_text[269] = "Invalid path [269]";
    error_text[270] = "Not found [270]";
    error_text[271] = "Access denied [271]";
    error_text[272] = "Not writable [272]";
    error_text[273] = "Authentication required [273]";
    error_text[274] = "Transmitter is busy [274]";
    error_text[275] = "No running operation [275]";
    error_text[300] = "Invalid file [300]";
    error_text[301] = "File not found [301]";
    error_text[302] = "File opening failed [302]";
    error_text[303] = "File reading failed [303]";
    error_text[304] = "End of file reached [304]";
    error_text[305] = "Unexpected end of file [305]";
    error_text[306] = "Unknown file format [306]";
    error_text[307] = "Invalid directory [307]";
    error_text[308] = "Directory not found [308]";
    error_text[400] = "File system not supported [400]";
    error_text[401] = "Unknown file system [401]";
    error_text[402] = "Invalid file system [402]";
    error_text[403] = "Invalid boot sector signature [403]";
    error_text[404] = "Invalid sector size [404]";
    error_text[405] = "Invalid cluster size [405]";
    error_text[406] = "Invalid file record size [406]";
    error_text[407] = "Invalid index buffer size [407]";
    error_text[408] = "Invalid volume descriptor signature [408]";
    error_text[409] = "Invalid volume descriptor [409]";
    error_text[410] = "Invalid file record [410]";
    error_text[411] = "Invalid index buffer [411]";
    error_text[412] = "Invalid data runs [412]";
    error_text[413] = "Wrong tag identifier [413]";
    error_text[414] = "Wrong tag checksum [414]";
    error_text[415] = "Wrong magic number [415]";
    error_text[416] = "Wrong sequence number [416]";
    error_text[417] = "Descriptor not found [417]";
    error_text[418] = "Attribute not found [418]";
    error_text[419] = "Resident attribute [419]";
    error_text[420] = "Not resident attribute [420]";
    error_text[421] = "Invalid super block [421]";
    error_text[422] = "Invalid super block signature [422]";
    error_text[423] = "Invalid block size [423]";
    error_text[424] = "Unsupported revision level [424]";
    error_text[425] = "Invalid inode size [425]";
    error_text[426] = "Inode not found [426]";
    error_text[500] = "Unexpected message [500]";
    error_text[501] = "URL is too long [501]";
    error_text[502] = "Query string is too long [502]";
    error_text[503] = "No address [503]";
    error_text[504] = "No binding [504]";
    error_text[505] = "Not on link [505]";
    error_text[506] = "Use multicast [506]";
    error_text[507] = "NAK received [507]";
    error_text[508] = "Exception received [508]";
    error_text[509] = "No carrier [509]";
    error_text[510] = "Invalid level [510]";
    error_text[511] = "Wrong state [511]";
    error_text[512] = "End of stream [512]";
    error_text[513] = "Link down [513]";
    error_text[514] = "Invalid option length [514]";
    error_text[515] = "Operation in progress [515]";
    error_text[516] = "No acknowledgment received [516]";
    error_text[517] = "Invalid metadata [517]";
    error_text[518] = "Not configured [518]";
    error_text[519] = "Already configured [519]";
    error_text[520] = "Name resolution failed [520]";
    error_text[521] = "No route to destination [521]";
    error_text[522] = "Write failed [522]";
    error_text[523] = "Read failed [523]";
    error_text[524] = "Upload failed [524]";
    error_text[525] = "Read-only access [525]";
    error_text[526] = "Invalid signature [526]";
    error_text[527] = "Invalid ticket [527]";
    error_text[528] = "No ticket [528]";
    error_text[529] = "Bad record MAC [529]";
    error_text[530] = "Record overflow [530]";
    error_text[531] = "Handshake failed [531]";
    error_text[532] = "No certificate [532]";
    error_text[533] = "Bad certificate [533]";
    error_text[534] = "Unsupported certificate [534]";
    error_text[535] = "Unknown certificate [535]";
    error_text[536] = "Certificate expired [536]";
    error_text[537] = "Certificate revoked [537]";
    error_text[538] = "Unknown certificate authority [538]";
    error_text[539] = "Decoding failed [539]";
    error_text[540] = "Decryption failed [540]";
    error_text[541] = "Illegal parameter [541]";
    error_text[542] = "Missing extension [542]";
    error_text[543] = "Unsupported extension [543]";
    error_text[544] = "Inappropriate fallback [544]";
    error_text[545] = "No application protocol [545]";
    error_text[546] = "More data required [546]";
    error_text[547] = "TLS not supported [547]";
    error_text[548] = "PRNG not ready [548]";
    error_text[549] = "Service closing [549]";
    error_text[550] = "Invalid timestamp [550]";
    error_text[551] = "No DNS server [551]";
    error_text[552] = "Object not found [552]";
    error_text[553] = "Instance not found [553]";
    error_text[554] = "Address not found [554]";
    error_text[555] = "Unknown identity [555]";
    error_text[556] = "Unknown engine ID [556]";
    error_text[557] = "Unknown user name [557]";
    error_text[558] = "Unknown identity [558]";
    error_text[559] = "Unknown engine ID [559]";
    error_text[560] = "Unknown user name [560]";
    error_text[561] = "Unknown context [561]";
    error_text[562] = "Unavailable context [562]";
    error_text[563] = "Unsupported security level [563]";
    error_text[564] = "Not in time window [564]";
    error_text[565] = "Authorization failed [565]";
    error_text[566] = "Invalid function code [566]";
    error_text[567] = "Device busy [567]";
    error_text[568] = "Request rejected [568]";
    error_text[569] = "Invalid channel [569]";
    error_text[570] = "Invalid group [570]";
    error_text[571] = "Unknown service [571]";
    error_text[572] = "Unknown request [572]";
    error_text[573] = "Flow control [573]";
    error_text[574] = "Invalid password [574]";
    error_text[575] = "Invalid handle [575]";
    error_text[576] = "Bad nonce [576]";
    error_text[577] = "Unexpected status [577]";
    error_text[578] = "Response too large [578]";
    error_text[579] = "Invalid session [579]";
    error_text[580] = "Ticket expired [580]";
    error_text[581] = "Invalid entry [581]";
    error_text[582] = "Table full [582]";
    error_text[583] = "End of table [583]";
    error_text[584] = "Already running [584]";
    error_text[585] = "Unknown key [585]";
    error_text[586] = "Unknown type [586]";
    error_text[587] = "Unsupported option [587]";
    error_text[588] = "Invalid SPI [588]";
    error_text[588] = "Retry [589]";
    error_text[590] = "Policy failure [590]";
    error_text[591] = "Invalid proposal [591]";
    error_text[592] = "Invalid selector [592]";
    error_text[593] = "Wrong nonce [593]";
    error_text[594] = "Wrong issuer [594]";
    error_text[595] = "Response expired [595]";
    error_text[596] = "CRL expired [596]";
    error_text[597] = "No match [597]";
    error_text[598] = "Partial match [598]";
}

const char *httpstatus2text(error_t error)
{
    switch (error)
    {
    case 100:
        return "Continue";
    case 101:
        return "Switching Protocols";
    case 200:
        return "OK";
    case 201:
        return "Created";
    case 202:
        return "Accepted";
    case 203:
        return "Non-Authoritative Information";
    case 204:
        return "No Content";
    case 205:
        return "Reset Content";
    case 206:
        return "Partial Content";
    case 300:
        return "Multiple Choices";
    case 301:
        return "Moved Permanently";
    case 302:
        return "Found";
    case 303:
        return "See Other";
    case 304:
        return "Not Modified";
    case 305:
        return "Use Proxy";
    case 307:
        return "Temporary Redirect";
    case 308:
        return "Permanent Redirect";
    case 400:
        return "Bad Request";
    case 401:
        return "Unauthorized";
    case 402:
        return "Payment Required";
    case 403:
        return "Forbidden";
    case 404:
        return "Not Found";
    case 405:
        return "Method Not Allowed";
    case 406:
        return "Not Acceptable";
    case 407:
        return "Proxy Authentication Required";
    case 408:
        return "Request Timeout";
    case 409:
        return "Conflict";
    case 410:
        return "Gone";
    case 411:
        return "Length Required";
    case 412:
        return "Precondition Failed";
    case 413:
        return "Payload Too Large";
    case 414:
        return "URI Too Long";
    case 415:
        return "Unsupported Media Type";
    case 416:
        return "Range Not Satisfiable";
    case 417:
        return "Expectation Failed";
    case 418:
        return "I'm a teapot";
    case 426:
        return "Upgrade Required";
    case 500:
        return "Internal Server Error";
    case 501:
        return "Not Implemented";
    case 502:
        return "Bad Gateway";
    case 503:
        return "Service Unavailable";
    case 504:
        return "Gateway Timeout";
    case 505:
        return "HTTP Version Not Supported";
    default:
        return "Unknown HTTP Status Code";
    }
}
