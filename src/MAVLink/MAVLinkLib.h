/****************************************************************************
 *
 * (c) 2009-2024 QGROUNDCONTROL PROJECT <http://www.qgroundcontrol.org>
 *
 * QGroundControl is licensed according to the terms in the file
 * COPYING.md in the root of the source code directory.
 *
 ****************************************************************************/

#pragma once

#include <stdint.h>

#define HAVE_MAVLINK_CHANNEL_T
#ifdef HAVE_MAVLINK_CHANNEL_T
typedef enum : uint8_t {
    MAVLINK_COMM_0,
    MAVLINK_COMM_1,
    MAVLINK_COMM_2,
    MAVLINK_COMM_3,
    MAVLINK_COMM_4,
    MAVLINK_COMM_5,
    MAVLINK_COMM_6,
    MAVLINK_COMM_7,
    MAVLINK_COMM_8,
    MAVLINK_COMM_9,
    MAVLINK_COMM_10,
    MAVLINK_COMM_11,
    MAVLINK_COMM_12,
    MAVLINK_COMM_13,
    MAVLINK_COMM_14,
    MAVLINK_COMM_15
} mavlink_channel_t;
#endif

#define MAVLINK_COMM_NUM_BUFFERS 16
#define MAVLINK_MAX_SIGNING_STREAMS MAVLINK_COMM_NUM_BUFFERS


//␣-------------------------------------------------------
// Setting compile options related with MESL_CRYPTO.
//␣-------------------------------------------------------

#define MESL_CRYPTO
//#define MESL_MAVLINK_PARSE_FIX
#define MESL_MAVLINK_DEBUG



#include <mavlink_types.h>

#define MAVLINK_EXTERNAL_RX_STATUS
#ifdef MAVLINK_EXTERNAL_RX_STATUS
    extern mavlink_status_t m_mavlink_status[MAVLINK_COMM_NUM_BUFFERS];
#endif

#define MAVLINK_GET_CHANNEL_STATUS
#ifdef MAVLINK_GET_CHANNEL_STATUS
    extern mavlink_status_t* mavlink_get_channel_status(uint8_t chan);
#endif

// #define MAVLINK_NO_SIGN_PACKET
// #define MAVLINK_NO_SIGNATURE_CHECK
#define MAVLINK_USE_MESSAGE_INFO

#include <stddef.h>

// Ignore warnings from mavlink headers for both GCC/Clang and MSVC
#ifdef __GNUC__
#   if __GNUC__ > 8
#       pragma GCC diagnostic push
#       pragma GCC diagnostic ignored "-Waddress-of-packed-member"
#   else
#       pragma GCC diagnostic push
#       pragma GCC diagnostic ignored "-Wall"
#   endif
#else
#   pragma warning(push, 0)
#endif

#include <mavlink.h>



// -------------------------------------------------------
// Include external crypto library
// -------------------------------------------------------

#ifdef MESL_CRYPTO

// Include 'mesl crypto library', of PX4 autopilot.
// 'mesl crypto library' has been included at QGC,
//   with just source-file-copy method, for now.

#include "mc.h"

// Make global variable that 'mesl_crypto_library' use.
// For PX4, 'key_flag' is on 'se' driver.
// But QGC doesn't have 'se' driver now, so just add this.
//
// To, 'QGCMAVLink.cc'
// int key_flag = 0;

// Declare global variable that 'mesl crypto library' use.
// This is required,
//   because of current implementation of 'mesl crypto library',
//   has some limitation for AES128_CTR.
//     AES128_CTR has non thread-safety implementation,
//       so this source code calls internal function directly to solve this,
//       and that required 'AES_key' value.

extern byte AES_key[MAX_AES_KEY_IDX][16];

#endif // #ifdef MESL_CRYPTO



// -------------------------------------------------------
// Declare or implement, for MESL_CRYPTO related things.
//   NOTE: 'MAVLINK_HELPER' is 'static inline' by default.
// -------------------------------------------------------

#ifdef MAVLINK_USE_CXX_NAMESPACE
namespace mavlink {
#endif

#ifdef MESL_MAVLINK_DEBUG
void mavlink_mesl_crypto_rxpl_debug(const char* pl, int len);
#endif // #ifdef MESL_MAVLINK_DEBUG

#ifdef MESL_CRYPTO

// @brief  Function to decide if MAVLink payload should be encrypted.
//         Program that use MAVLink should implement this function.
// @param  'len': payload length (can be 0).
// @return 'MESL_CRYPTO_METHOD_XXX' (true),
//           if MAVLink payload should be encrypted.
//         Zero otherwise.
MAVLINK_HELPER uint8_t mavlink_mesl_crypto_condition(
		mavlink_status_t* status,
		uint32_t msgid,
		uint8_t system_id,
		uint8_t component_id,
		const char *payload,
		uint8_t len
		)
{
	// Use same crypto option, from rx MAVLink frame.
	return status->mesl_crypto_method_rx;
}

// @brief  Function to encrypt MAVLink payload.
//         Program that use MAVLink should implement this function.
// @param  'crypto_method': method for encryption,
//           value should be 'MESL_CRYPTO_METHOD_XXX'.
// @param  'len': payload length (can be 0).
// @return Payload length after encryption.
// @note   "input_len == 0 && output_len == 0",
//           will be considered as non-encryption.
//         But, "input len != 0 && output_len == 0",
//           or "output_len < 0 || output_len > maxlen",
//           will be considered as error,
//           MAVLink frame will be sent with zero payload length,
//           and receiving side can report error,
//           because the length is zero but encryption iflag is set.
MAVLINK_HELPER int32_t mavlink_mesl_encrypt(
		uint8_t crypto_method,
		const char *src,
		char *dst,
		uint8_t len,
		uint8_t maxlen
		)
{
	if (crypto_method == MESL_CRYPTO_METHOD_AES128) {
		AES aes_ctr;
		aes_ctr.ctr_initialize();
		memcpy(
				dst,
				src,
				len);
		aes_ctr.ctr_encrypt(
				// Because of wrong parameter or wrong implementation,
				//   of 'mesl crypto library', just pass NULL.
				(byte*)0,
				(int)len,
				// Because of wrong parameter or wrong implementation,
				//   of 'mesl crypto library',
				//   pass source data to here,
				//   and get en/de/crypted data from here.
				(byte*)dst,
				AES_key[0],
				128
				);
		return (int32_t)len;
	}
	if (crypto_method == MESL_CRYPTO_METHOD_USER7) {
		// User defined encryption:
		//   XOR with key '0xab', for test.
		memcpy(
				dst,
				src,
				len);
		for (uint8_t i = (uint8_t)0; i < len; i++) {
			dst[i] ^= 0xab;
		}
		return (int32_t)len;
	}
	// qCWarning(QGCMAVLinkLog) <<
	//   "MESL_CRYPTO: invalid crypto method requested";
	return (int32_t)-1;
}

// @brief  Function to decrypt MAVLink payload.
//         Program that use MAVLink should implement this function.
// @param  'crypto_method': method for decryption,
//           value can be 'MESL_CRYPTO_METHOD_XXX'.
//         For invalid 'crypto_method',
//           this function should return '-1'.
// @param  'len': payload length.
//         If 'len' is zero,
//           this function should return '-1'.
// @return Payload length after decryption (zero is valid result).
//         If "output_len < 0 || output_len > maxlen",
//           will be considered as error,
//           one example is for invalue 'crypto_method'.
MAVLINK_HELPER int32_t mavlink_mesl_decrypt(
		uint8_t crypto_method,
		const char *src,
		char *dst,
		uint8_t len,
		uint8_t maxlen
		)
{
	if (crypto_method == MESL_CRYPTO_METHOD_AES128) {
		AES aes_ctr;
#ifdef MESL_MAVLINK_DEBUG
mavlink_mesl_crypto_rxpl_debug(src, (int)len);
#endif // #ifdef MESL_MAVLINK_DEBUG
		aes_ctr.ctr_initialize();
		memcpy(
				dst,
				src,
				len);
		aes_ctr.ctr_encrypt(
				// Because of wrong parameter or wrong implementation,
				//   of 'mesl crypto library', just pass NULL.
				(byte*)0,
				(int)len,
				// Because of wrong parameter or wrong implementation,
				//   of 'mesl crypto library',
				//   pass source data to here,
				//   and get en/de/crypted data from here.
				(byte*)dst,
				AES_key[0],
				128
				);
		return (int32_t)len;
	}
	if (crypto_method == MESL_CRYPTO_METHOD_USER7) {
		// User defined encryption:
		//   XOR with key '0xab', for test.
		memcpy(
				dst,
				src,
				len);
		for (uint8_t i = (uint8_t)0; i < len; i++) {
			dst[i] ^= 0xab;
		}
		return (int32_t)len;
	}
	return (int32_t)-1;
}

#endif // #ifdef MESL_CRYPTO

#ifdef MESL_MAVLINK_DEBUG

// @brief  Function for debug MAVLink frame parsing result.'
//           This function is for non-static non-inline function.
void mavlink_mesl_parse_result_f(
		const mavlink_message_t* rxmsg,
		const mavlink_status_t* status
		);

// @brief  Function for debug MAVLink frame parsing result.'
MAVLINK_HELPER void mavlink_mesl_parse_result(
		const mavlink_message_t* rxmsg,
		const mavlink_status_t* status
		)
{
	mavlink_mesl_parse_result_f(rxmsg, status);
}

#endif // #ifdef MESL_MAVLINK_DEBUG

#ifdef MAVLINK_USE_CXX_NAMESPACE
} // namespace mavlink
#endif



#ifdef __GNUC__
#	pragma GCC diagnostic pop
#else
#	pragma warning(pop, 0)
#endif
