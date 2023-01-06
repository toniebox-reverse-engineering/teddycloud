/**
 * @file whirlpool.c
 * @brief Whirlpool hash function
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2022 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneCRYPTO Open.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * @section Description
 *
 * Whirlpool is a hash function that operates on messages less than 2^256 bits
 * in length, and produces a message digest of 512 bits
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.2.0
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "hash/whirlpool.h"

//Check crypto library configuration
#if (WHIRLPOOL_SUPPORT == ENABLED)

//Round function
#define RHO(b, a, n, c) \
{ \
   b = t[(a[n] >> 56) & 0xFF]; \
   b ^= ROR64(t[(a[(n + 7) % 8] >> 48) & 0xFF], 8); \
   b ^= ROR64(t[(a[(n + 6) % 8] >> 40) & 0xFF], 16); \
   b ^= ROR64(t[(a[(n + 5) % 8] >> 32) & 0xFF], 24); \
   b ^= ROR64(t[(a[(n + 4) % 8] >> 24) & 0xFF], 32); \
   b ^= ROR64(t[(a[(n + 3) % 8] >> 16) & 0xFF], 40); \
   b ^= ROR64(t[(a[(n + 2) % 8] >> 8) & 0xFF], 48); \
   b ^= ROR64(t[a[(n + 1) % 8] & 0xFF], 56); \
   b ^= c; \
}

//Whirlpool padding
static const uint8_t padding[64] =
{
   0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

//Whirlpool constants
static const uint64_t rc[10] =
{
   0x1823C6E887B8014F,
   0x36A6D2F5796F9152,
   0x60BC9B8EA30C7B35,
   0x1DE0D7C22E4BFE57,
   0x157737E59FF04ADA,
   0x58C9290AB1A06B85,
   0xBD5D10F4CB3E0567,
   0xE427418BA77D95D8,
   0xFBEE7C66DD17479E,
   0xCA2DBF07AD5A8333
};

//Whirlpool look-up table
static const uint64_t t[256] =
{
   0x18186018C07830D8, 0x23238C2305AF4626, 0xC6C63FC67EF991B8, 0xE8E887E8136FCDFB,
   0x878726874CA113CB, 0xB8B8DAB8A9626D11, 0x0101040108050209, 0x4F4F214F426E9E0D,
   0x3636D836ADEE6C9B, 0xA6A6A2A6590451FF, 0xD2D26FD2DEBDB90C, 0xF5F5F3F5FB06F70E,
   0x7979F979EF80F296, 0x6F6FA16F5FCEDE30, 0x91917E91FCEF3F6D, 0x52525552AA07A4F8,
   0x60609D6027FDC047, 0xBCBCCABC89766535, 0x9B9B569BACCD2B37, 0x8E8E028E048C018A,
   0xA3A3B6A371155BD2, 0x0C0C300C603C186C, 0x7B7BF17BFF8AF684, 0x3535D435B5E16A80,
   0x1D1D741DE8693AF5, 0xE0E0A7E05347DDB3, 0xD7D77BD7F6ACB321, 0xC2C22FC25EED999C,
   0x2E2EB82E6D965C43, 0x4B4B314B627A9629, 0xFEFEDFFEA321E15D, 0x575741578216AED5,
   0x15155415A8412ABD, 0x7777C1779FB6EEE8, 0x3737DC37A5EB6E92, 0xE5E5B3E57B56D79E,
   0x9F9F469F8CD92313, 0xF0F0E7F0D317FD23, 0x4A4A354A6A7F9420, 0xDADA4FDA9E95A944,
   0x58587D58FA25B0A2, 0xC9C903C906CA8FCF, 0x2929A429558D527C, 0x0A0A280A5022145A,
   0xB1B1FEB1E14F7F50, 0xA0A0BAA0691A5DC9, 0x6B6BB16B7FDAD614, 0x85852E855CAB17D9,
   0xBDBDCEBD8173673C, 0x5D5D695DD234BA8F, 0x1010401080502090, 0xF4F4F7F4F303F507,
   0xCBCB0BCB16C08BDD, 0x3E3EF83EEDC67CD3, 0x0505140528110A2D, 0x676781671FE6CE78,
   0xE4E4B7E47353D597, 0x27279C2725BB4E02, 0x4141194132588273, 0x8B8B168B2C9D0BA7,
   0xA7A7A6A7510153F6, 0x7D7DE97DCF94FAB2, 0x95956E95DCFB3749, 0xD8D847D88E9FAD56,
   0xFBFBCBFB8B30EB70, 0xEEEE9FEE2371C1CD, 0x7C7CED7CC791F8BB, 0x6666856617E3CC71,
   0xDDDD53DDA68EA77B, 0x17175C17B84B2EAF, 0x4747014702468E45, 0x9E9E429E84DC211A,
   0xCACA0FCA1EC589D4, 0x2D2DB42D75995A58, 0xBFBFC6BF9179632E, 0x07071C07381B0E3F,
   0xADAD8EAD012347AC, 0x5A5A755AEA2FB4B0, 0x838336836CB51BEF, 0x3333CC3385FF66B6,
   0x636391633FF2C65C, 0x02020802100A0412, 0xAAAA92AA39384993, 0x7171D971AFA8E2DE,
   0xC8C807C80ECF8DC6, 0x19196419C87D32D1, 0x494939497270923B, 0xD9D943D9869AAF5F,
   0xF2F2EFF2C31DF931, 0xE3E3ABE34B48DBA8, 0x5B5B715BE22AB6B9, 0x88881A8834920DBC,
   0x9A9A529AA4C8293E, 0x262698262DBE4C0B, 0x3232C8328DFA64BF, 0xB0B0FAB0E94A7D59,
   0xE9E983E91B6ACFF2, 0x0F0F3C0F78331E77, 0xD5D573D5E6A6B733, 0x80803A8074BA1DF4,
   0xBEBEC2BE997C6127, 0xCDCD13CD26DE87EB, 0x3434D034BDE46889, 0x48483D487A759032,
   0xFFFFDBFFAB24E354, 0x7A7AF57AF78FF48D, 0x90907A90F4EA3D64, 0x5F5F615FC23EBE9D,
   0x202080201DA0403D, 0x6868BD6867D5D00F, 0x1A1A681AD07234CA, 0xAEAE82AE192C41B7,
   0xB4B4EAB4C95E757D, 0x54544D549A19A8CE, 0x93937693ECE53B7F, 0x222288220DAA442F,
   0x64648D6407E9C863, 0xF1F1E3F1DB12FF2A, 0x7373D173BFA2E6CC, 0x12124812905A2482,
   0x40401D403A5D807A, 0x0808200840281048, 0xC3C32BC356E89B95, 0xECEC97EC337BC5DF,
   0xDBDB4BDB9690AB4D, 0xA1A1BEA1611F5FC0, 0x8D8D0E8D1C830791, 0x3D3DF43DF5C97AC8,
   0x97976697CCF1335B, 0x0000000000000000, 0xCFCF1BCF36D483F9, 0x2B2BAC2B4587566E,
   0x7676C57697B3ECE1, 0x8282328264B019E6, 0xD6D67FD6FEA9B128, 0x1B1B6C1BD87736C3,
   0xB5B5EEB5C15B7774, 0xAFAF86AF112943BE, 0x6A6AB56A77DFD41D, 0x50505D50BA0DA0EA,
   0x45450945124C8A57, 0xF3F3EBF3CB18FB38, 0x3030C0309DF060AD, 0xEFEF9BEF2B74C3C4,
   0x3F3FFC3FE5C37EDA, 0x55554955921CAAC7, 0xA2A2B2A2791059DB, 0xEAEA8FEA0365C9E9,
   0x656589650FECCA6A, 0xBABAD2BAB9686903, 0x2F2FBC2F65935E4A, 0xC0C027C04EE79D8E,
   0xDEDE5FDEBE81A160, 0x1C1C701CE06C38FC, 0xFDFDD3FDBB2EE746, 0x4D4D294D52649A1F,
   0x92927292E4E03976, 0x7575C9758FBCEAFA, 0x06061806301E0C36, 0x8A8A128A249809AE,
   0xB2B2F2B2F940794B, 0xE6E6BFE66359D185, 0x0E0E380E70361C7E, 0x1F1F7C1FF8633EE7,
   0x6262956237F7C455, 0xD4D477D4EEA3B53A, 0xA8A89AA829324D81, 0x96966296C4F43152,
   0xF9F9C3F99B3AEF62, 0xC5C533C566F697A3, 0x2525942535B14A10, 0x59597959F220B2AB,
   0x84842A8454AE15D0, 0x7272D572B7A7E4C5, 0x3939E439D5DD72EC, 0x4C4C2D4C5A619816,
   0x5E5E655ECA3BBC94, 0x7878FD78E785F09F, 0x3838E038DDD870E5, 0x8C8C0A8C14860598,
   0xD1D163D1C6B2BF17, 0xA5A5AEA5410B57E4, 0xE2E2AFE2434DD9A1, 0x616199612FF8C24E,
   0xB3B3F6B3F1457B42, 0x2121842115A54234, 0x9C9C4A9C94D62508, 0x1E1E781EF0663CEE,
   0x4343114322528661, 0xC7C73BC776FC93B1, 0xFCFCD7FCB32BE54F, 0x0404100420140824,
   0x51515951B208A2E3, 0x99995E99BCC72F25, 0x6D6DA96D4FC4DA22, 0x0D0D340D68391A65,
   0xFAFACFFA8335E979, 0xDFDF5BDFB684A369, 0x7E7EE57ED79BFCA9, 0x242490243DB44819,
   0x3B3BEC3BC5D776FE, 0xABAB96AB313D4B9A, 0xCECE1FCE3ED181F0, 0x1111441188552299,
   0x8F8F068F0C890383, 0x4E4E254E4A6B9C04, 0xB7B7E6B7D1517366, 0xEBEB8BEB0B60CBE0,
   0x3C3CF03CFDCC78C1, 0x81813E817CBF1FFD, 0x94946A94D4FE3540, 0xF7F7FBF7EB0CF31C,
   0xB9B9DEB9A1676F18, 0x13134C13985F268B, 0x2C2CB02C7D9C5851, 0xD3D36BD3D6B8BB05,
   0xE7E7BBE76B5CD38C, 0x6E6EA56E57CBDC39, 0xC4C437C46EF395AA, 0x03030C03180F061B,
   0x565645568A13ACDC, 0x44440D441A49885E, 0x7F7FE17FDF9EFEA0, 0xA9A99EA921374F88,
   0x2A2AA82A4D825467, 0xBBBBD6BBB16D6B0A, 0xC1C123C146E29F87, 0x53535153A202A6F1,
   0xDCDC57DCAE8BA572, 0x0B0B2C0B58271653, 0x9D9D4E9D9CD32701, 0x6C6CAD6C47C1D82B,
   0x3131C43195F562A4, 0x7474CD7487B9E8F3, 0xF6F6FFF6E309F115, 0x464605460A438C4C,
   0xACAC8AAC092645A5, 0x89891E893C970FB5, 0x14145014A04428B4, 0xE1E1A3E15B42DFBA,
   0x16165816B04E2CA6, 0x3A3AE83ACDD274F7, 0x6969B9696FD0D206, 0x09092409482D1241,
   0x7070DD70A7ADE0D7, 0xB6B6E2B6D954716F, 0xD0D067D0CEB7BD1E, 0xEDED93ED3B7EC7D6,
   0xCCCC17CC2EDB85E2, 0x424215422A578468, 0x98985A98B4C22D2C, 0xA4A4AAA4490E55ED,
   0x2828A0285D885075, 0x5C5C6D5CDA31B886, 0xF8F8C7F8933FED6B, 0x8686228644A411C2
};

//Whirlpool object identifier (1.0.10118.3.0.55)
const uint8_t whirlpoolOid[6] = {0x28, 0xCF, 0x06, 0x03, 0x00, 0x37};

//Common interface for hash algorithms
const HashAlgo whirlpoolHashAlgo =
{
   "Whirlpool",
   whirlpoolOid,
   sizeof(whirlpoolOid),
   sizeof(WhirlpoolContext),
   WHIRLPOOL_BLOCK_SIZE,
   WHIRLPOOL_DIGEST_SIZE,
   WHIRLPOOL_MIN_PAD_SIZE,
   TRUE,
   (HashAlgoCompute) whirlpoolCompute,
   (HashAlgoInit) whirlpoolInit,
   (HashAlgoUpdate) whirlpoolUpdate,
   (HashAlgoFinal) whirlpoolFinal,
   NULL
};


/**
 * @brief Digest a message using Whirlpool
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

error_t whirlpoolCompute(const void *data, size_t length, uint8_t *digest)
{
   error_t error;
   WhirlpoolContext *context;

   //Allocate a memory buffer to hold the Whirlpool context
   context = cryptoAllocMem(sizeof(WhirlpoolContext));

   //Successful memory allocation?
   if(context != NULL)
   {
      //Initialize the Whirlpool context
      whirlpoolInit(context);
      //Digest the message
      whirlpoolUpdate(context, data, length);
      //Finalize the Whirlpool message digest
      whirlpoolFinal(context, digest);

      //Free previously allocated memory
      cryptoFreeMem(context);

      //Successful processing
      error = NO_ERROR;
   }
   else
   {
      //Failed to allocate memory
      error = ERROR_OUT_OF_MEMORY;
   }

   //Return status code
   return error;
}


/**
 * @brief Initialize Whirlpool message digest context
 * @param[in] context Pointer to the Whirlpool context to initialize
 **/

void whirlpoolInit(WhirlpoolContext *context)
{
   uint_t i;

   //Set initial hash value
   for(i = 0; i < 8; i++)
   {
      context->h[i] = 0;
   }

   //Number of bytes in the buffer
   context->size = 0;
   //Total length of the message
   context->totalSize = 0;
}


/**
 * @brief Update the Whirlpool context with a portion of the message being hashed
 * @param[in] context Pointer to the Whirlpool context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

void whirlpoolUpdate(WhirlpoolContext *context, const void *data, size_t length)
{
   size_t n;

   //Process the incoming data
   while(length > 0)
   {
      //The buffer can hold at most 64 bytes
      n = MIN(length, 64 - context->size);

      //Copy the data to the buffer
      osMemcpy(context->buffer + context->size, data, n);

      //Update the Whirlpool context
      context->size += n;
      context->totalSize += n;
      //Advance the data pointer
      data = (uint8_t *) data + n;
      //Remaining bytes to process
      length -= n;

      //Process message in 8-word blocks
      if(context->size == 64)
      {
         //Transform the 8-word block
         whirlpoolProcessBlock(context);
         //Empty the buffer
         context->size = 0;
      }
   }
}


/**
 * @brief Finish the Whirlpool message digest
 * @param[in] context Pointer to the Whirlpool context
 * @param[out] digest Calculated digest (optional parameter)
 **/

void whirlpoolFinal(WhirlpoolContext *context, uint8_t *digest)
{
   uint_t i;
   size_t paddingSize;
   uint64_t totalSize;

   //Length of the original message (before padding)
   totalSize = context->totalSize * 8;

   //Pad the message so that its length is congruent to 32 modulo 64
   if(context->size < 32)
      paddingSize = 32 - context->size;
   else
      paddingSize = 64 + 32 - context->size;

   //Append padding
   whirlpoolUpdate(context, padding, paddingSize);

   //Append the length of the original message
   context->x[4] = 0;
   context->x[5] = 0;
   context->x[6] = 0;
   context->x[7] = htobe64(totalSize);

   //Calculate the message digest
   whirlpoolProcessBlock(context);

   //Convert from host byte order to big-endian byte order
   for(i = 0; i < 8; i++)
   {
      context->h[i] = htobe64(context->h[i]);
   }

   //Copy the resulting digest
   if(digest != NULL)
   {
      osMemcpy(digest, context->digest, WHIRLPOOL_DIGEST_SIZE);
   }
}


/**
 * @brief Process message in 16-word blocks
 * @param[in] context Pointer to the Whirlpool context
 **/

void whirlpoolProcessBlock(WhirlpoolContext *context)
{
   uint_t i;

   uint64_t *x = context->x;
   uint64_t *k = context->k;
   uint64_t *l = context->l;
   uint64_t *state = context->state;

   //Convert from big-endian byte order to host byte order
   for(i = 0; i < 8; i++)
   {
      x[i] = betoh64(x[i]);
   }

   k[0] = context->h[0];
   k[1] = context->h[1];
   k[2] = context->h[2];
   k[3] = context->h[3];
   k[4] = context->h[4];
   k[5] = context->h[5];
   k[6] = context->h[6];
   k[7] = context->h[7];

   state[0] = x[0] ^ k[0];
   state[1] = x[1] ^ k[1];
   state[2] = x[2] ^ k[2];
   state[3] = x[3] ^ k[3];
   state[4] = x[4] ^ k[4];
   state[5] = x[5] ^ k[5];
   state[6] = x[6] ^ k[6];
   state[7] = x[7] ^ k[7];

   //Iterate over all rounds
   for(i = 0; i < 10; i++)
   {
      //Key schedule
      RHO(l[0], k, 0, rc[i]);
      RHO(l[1], k, 1, 0);
      RHO(l[2], k, 2, 0);
      RHO(l[3], k, 3, 0);
      RHO(l[4], k, 4, 0);
      RHO(l[5], k, 5, 0);
      RHO(l[6], k, 6, 0);
      RHO(l[7], k, 7, 0);

      k[0] = l[0];
      k[1] = l[1];
      k[2] = l[2];
      k[3] = l[3];
      k[4] = l[4];
      k[5] = l[5];
      k[6] = l[6];
      k[7] = l[7];

      //Apply the round function
      RHO(l[0], state, 0, k[0]);
      RHO(l[1], state, 1, k[1]);
      RHO(l[2], state, 2, k[2]);
      RHO(l[3], state, 3, k[3]);
      RHO(l[4], state, 4, k[4]);
      RHO(l[5], state, 5, k[5]);
      RHO(l[6], state, 6, k[6]);
      RHO(l[7], state, 7, k[7]);

      state[0] = l[0];
      state[1] = l[1];
      state[2] = l[2];
      state[3] = l[3];
      state[4] = l[4];
      state[5] = l[5];
      state[6] = l[6];
      state[7] = l[7];
   }

   //Update the hash value
   context->h[0] ^= state[0] ^ x[0];
   context->h[1] ^= state[1] ^ x[1];
   context->h[2] ^= state[2] ^ x[2];
   context->h[3] ^= state[3] ^ x[3];
   context->h[4] ^= state[4] ^ x[4];
   context->h[5] ^= state[5] ^ x[5];
   context->h[6] ^= state[6] ^ x[6];
   context->h[7] ^= state[7] ^ x[7];
}

#endif
