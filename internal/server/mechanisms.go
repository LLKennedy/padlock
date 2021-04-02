package server

import (
	"github.com/LLKennedy/padlock/api/padlockpb"
	"github.com/miekg/pkcs11"
)

// MechanismPBtoP11 converts mechanism enums
func MechanismPBtoP11(mech padlockpb.MechanismType) uint {
	converted := 0xFEFEFEFE // invalid for everything
	switch mech {
	case padlockpb.MechanismType_CKM_RSA_PKCS_KEY_PAIR_GEN:
		converted = pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN
	case padlockpb.MechanismType_CKM_RSA_PKCS:
		converted = pkcs11.CKM_RSA_PKCS
	case padlockpb.MechanismType_CKM_RSA_9796:
		converted = pkcs11.CKM_RSA_9796
	case padlockpb.MechanismType_CKM_RSA_X_509:
		converted = pkcs11.CKM_RSA_X_509
	case padlockpb.MechanismType_CKM_MD2_RSA_PKCS:
		converted = pkcs11.CKM_MD2_RSA_PKCS
	case padlockpb.MechanismType_CKM_MD5_RSA_PKCS:
		converted = pkcs11.CKM_MD5_RSA_PKCS
	case padlockpb.MechanismType_CKM_SHA1_RSA_PKCS:
		converted = pkcs11.CKM_SHA1_RSA_PKCS
	case padlockpb.MechanismType_CKM_RIPEMD128_RSA_PKCS:
		converted = pkcs11.CKM_RIPEMD128_RSA_PKCS
	case padlockpb.MechanismType_CKM_RIPEMD160_RSA_PKCS:
		converted = pkcs11.CKM_RIPEMD160_RSA_PKCS
	case padlockpb.MechanismType_CKM_RSA_PKCS_OAEP:
		converted = pkcs11.CKM_RSA_PKCS_OAEP
	case padlockpb.MechanismType_CKM_RSA_X9_31_KEY_PAIR_GEN:
		converted = pkcs11.CKM_RSA_X9_31_KEY_PAIR_GEN
	case padlockpb.MechanismType_CKM_RSA_X9_31:
		converted = pkcs11.CKM_RSA_X9_31
	case padlockpb.MechanismType_CKM_SHA1_RSA_X9_31:
		converted = pkcs11.CKM_SHA1_RSA_X9_31
	case padlockpb.MechanismType_CKM_RSA_PKCS_PSS:
		converted = pkcs11.CKM_RSA_PKCS_PSS
	case padlockpb.MechanismType_CKM_SHA1_RSA_PKCS_PSS:
		converted = pkcs11.CKM_SHA1_RSA_PKCS_PSS
	case padlockpb.MechanismType_CKM_DSA_KEY_PAIR_GEN:
		converted = pkcs11.CKM_DSA_KEY_PAIR_GEN
	case padlockpb.MechanismType_CKM_DSA:
		converted = pkcs11.CKM_DSA
	case padlockpb.MechanismType_CKM_DSA_SHA1:
		converted = pkcs11.CKM_DSA_SHA1
	case padlockpb.MechanismType_CKM_DSA_FIPS_G_GEN:
		converted = pkcs11.CKM_DSA_FIPS_G_GEN
	case padlockpb.MechanismType_CKM_DSA_SHA224:
		converted = pkcs11.CKM_DSA_SHA224
	case padlockpb.MechanismType_CKM_DSA_SHA256:
		converted = pkcs11.CKM_DSA_SHA256
	case padlockpb.MechanismType_CKM_DSA_SHA384:
		converted = pkcs11.CKM_DSA_SHA384
	case padlockpb.MechanismType_CKM_DSA_SHA512:
		converted = pkcs11.CKM_DSA_SHA512
	case padlockpb.MechanismType_CKM_DSA_SHA3_224:
		converted = pkcs11.CKM_DSA_SHA3_224
	case padlockpb.MechanismType_CKM_DSA_SHA3_256:
		converted = pkcs11.CKM_DSA_SHA3_256
	case padlockpb.MechanismType_CKM_DSA_SHA3_384:
		converted = pkcs11.CKM_DSA_SHA3_384
	case padlockpb.MechanismType_CKM_DSA_SHA3_512:
		converted = pkcs11.CKM_DSA_SHA3_512
	case padlockpb.MechanismType_CKM_DH_PKCS_KEY_PAIR_GEN:
		converted = pkcs11.CKM_DH_PKCS_KEY_PAIR_GEN
	case padlockpb.MechanismType_CKM_DH_PKCS_DERIVE:
		converted = pkcs11.CKM_DH_PKCS_DERIVE
	case padlockpb.MechanismType_CKM_X9_42_DH_KEY_PAIR_GEN:
		converted = pkcs11.CKM_X9_42_DH_KEY_PAIR_GEN
	case padlockpb.MechanismType_CKM_X9_42_DH_DERIVE:
		converted = pkcs11.CKM_X9_42_DH_DERIVE
	case padlockpb.MechanismType_CKM_X9_42_DH_HYBRID_DERIVE:
		converted = pkcs11.CKM_X9_42_DH_HYBRID_DERIVE
	case padlockpb.MechanismType_CKM_X9_42_MQV_DERIVE:
		converted = pkcs11.CKM_X9_42_MQV_DERIVE
	case padlockpb.MechanismType_CKM_SHA256_RSA_PKCS:
		converted = pkcs11.CKM_SHA256_RSA_PKCS
	case padlockpb.MechanismType_CKM_SHA384_RSA_PKCS:
		converted = pkcs11.CKM_SHA384_RSA_PKCS
	case padlockpb.MechanismType_CKM_SHA512_RSA_PKCS:
		converted = pkcs11.CKM_SHA512_RSA_PKCS
	case padlockpb.MechanismType_CKM_SHA256_RSA_PKCS_PSS:
		converted = pkcs11.CKM_SHA256_RSA_PKCS_PSS
	case padlockpb.MechanismType_CKM_SHA384_RSA_PKCS_PSS:
		converted = pkcs11.CKM_SHA384_RSA_PKCS_PSS
	case padlockpb.MechanismType_CKM_SHA512_RSA_PKCS_PSS:
		converted = pkcs11.CKM_SHA512_RSA_PKCS_PSS
	case padlockpb.MechanismType_CKM_SHA224_RSA_PKCS:
		converted = pkcs11.CKM_SHA224_RSA_PKCS
	case padlockpb.MechanismType_CKM_SHA224_RSA_PKCS_PSS:
		converted = pkcs11.CKM_SHA224_RSA_PKCS_PSS
	case padlockpb.MechanismType_CKM_SHA512_224:
		converted = pkcs11.CKM_SHA512_224
	case padlockpb.MechanismType_CKM_SHA512_224_HMAC:
		converted = pkcs11.CKM_SHA512_224_HMAC
	case padlockpb.MechanismType_CKM_SHA512_224_HMAC_GENERAL:
		converted = pkcs11.CKM_SHA512_224_HMAC_GENERAL
	case padlockpb.MechanismType_CKM_SHA512_224_KEY_DERIVATION:
		converted = pkcs11.CKM_SHA512_224_KEY_DERIVATION
	case padlockpb.MechanismType_CKM_SHA512_256:
		converted = pkcs11.CKM_SHA512_256
	case padlockpb.MechanismType_CKM_SHA512_256_HMAC:
		converted = pkcs11.CKM_SHA512_256_HMAC
	case padlockpb.MechanismType_CKM_SHA512_256_HMAC_GENERAL:
		converted = pkcs11.CKM_SHA512_256_HMAC_GENERAL
	case padlockpb.MechanismType_CKM_SHA512_256_KEY_DERIVATION:
		converted = pkcs11.CKM_SHA512_256_KEY_DERIVATION
	case padlockpb.MechanismType_CKM_SHA512_T:
		converted = pkcs11.CKM_SHA512_T
	case padlockpb.MechanismType_CKM_SHA512_T_HMAC:
		converted = pkcs11.CKM_SHA512_T_HMAC
	case padlockpb.MechanismType_CKM_SHA512_T_HMAC_GENERAL:
		converted = pkcs11.CKM_SHA512_T_HMAC_GENERAL
	case padlockpb.MechanismType_CKM_SHA512_T_KEY_DERIVATION:
		converted = pkcs11.CKM_SHA512_T_KEY_DERIVATION
	case padlockpb.MechanismType_CKM_SHA3_256_RSA_PKCS:
		converted = pkcs11.CKM_SHA3_256_RSA_PKCS
	case padlockpb.MechanismType_CKM_SHA3_384_RSA_PKCS:
		converted = pkcs11.CKM_SHA3_384_RSA_PKCS
	case padlockpb.MechanismType_CKM_SHA3_512_RSA_PKCS:
		converted = pkcs11.CKM_SHA3_512_RSA_PKCS
	case padlockpb.MechanismType_CKM_SHA3_256_RSA_PKCS_PSS:
		converted = pkcs11.CKM_SHA3_256_RSA_PKCS_PSS
	case padlockpb.MechanismType_CKM_SHA3_384_RSA_PKCS_PSS:
		converted = pkcs11.CKM_SHA3_384_RSA_PKCS_PSS
	case padlockpb.MechanismType_CKM_SHA3_512_RSA_PKCS_PSS:
		converted = pkcs11.CKM_SHA3_512_RSA_PKCS_PSS
	case padlockpb.MechanismType_CKM_SHA3_224_RSA_PKCS:
		converted = pkcs11.CKM_SHA3_224_RSA_PKCS
	case padlockpb.MechanismType_CKM_SHA3_224_RSA_PKCS_PSS:
		converted = pkcs11.CKM_SHA3_224_RSA_PKCS_PSS
	case padlockpb.MechanismType_CKM_RC2_KEY_GEN:
		converted = pkcs11.CKM_RC2_KEY_GEN
	case padlockpb.MechanismType_CKM_RC2_ECB:
		converted = pkcs11.CKM_RC2_ECB
	case padlockpb.MechanismType_CKM_RC2_CBC:
		converted = pkcs11.CKM_RC2_CBC
	case padlockpb.MechanismType_CKM_RC2_MAC:
		converted = pkcs11.CKM_RC2_MAC
	case padlockpb.MechanismType_CKM_RC2_MAC_GENERAL:
		converted = pkcs11.CKM_RC2_MAC_GENERAL
	case padlockpb.MechanismType_CKM_RC2_CBC_PAD:
		converted = pkcs11.CKM_RC2_CBC_PAD
	case padlockpb.MechanismType_CKM_RC4_KEY_GEN:
		converted = pkcs11.CKM_RC4_KEY_GEN
	case padlockpb.MechanismType_CKM_RC4:
		converted = pkcs11.CKM_RC4
	case padlockpb.MechanismType_CKM_DES_KEY_GEN:
		converted = pkcs11.CKM_DES_KEY_GEN
	case padlockpb.MechanismType_CKM_DES_ECB:
		converted = pkcs11.CKM_DES_ECB
	case padlockpb.MechanismType_CKM_DES_CBC:
		converted = pkcs11.CKM_DES_CBC
	case padlockpb.MechanismType_CKM_DES_MAC:
		converted = pkcs11.CKM_DES_MAC
	case padlockpb.MechanismType_CKM_DES_MAC_GENERAL:
		converted = pkcs11.CKM_DES_MAC_GENERAL
	case padlockpb.MechanismType_CKM_DES_CBC_PAD:
		converted = pkcs11.CKM_DES_CBC_PAD
	case padlockpb.MechanismType_CKM_DES2_KEY_GEN:
		converted = pkcs11.CKM_DES2_KEY_GEN
	case padlockpb.MechanismType_CKM_DES3_KEY_GEN:
		converted = pkcs11.CKM_DES3_KEY_GEN
	case padlockpb.MechanismType_CKM_DES3_ECB:
		converted = pkcs11.CKM_DES3_ECB
	case padlockpb.MechanismType_CKM_DES3_CBC:
		converted = pkcs11.CKM_DES3_CBC
	case padlockpb.MechanismType_CKM_DES3_MAC:
		converted = pkcs11.CKM_DES3_MAC
	case padlockpb.MechanismType_CKM_DES3_MAC_GENERAL:
		converted = pkcs11.CKM_DES3_MAC_GENERAL
	case padlockpb.MechanismType_CKM_DES3_CBC_PAD:
		converted = pkcs11.CKM_DES3_CBC_PAD
	case padlockpb.MechanismType_CKM_DES3_CMAC_GENERAL:
		converted = pkcs11.CKM_DES3_CMAC_GENERAL
	case padlockpb.MechanismType_CKM_DES3_CMAC:
		converted = pkcs11.CKM_DES3_CMAC
	case padlockpb.MechanismType_CKM_CDMF_KEY_GEN:
		converted = pkcs11.CKM_CDMF_KEY_GEN
	case padlockpb.MechanismType_CKM_CDMF_ECB:
		converted = pkcs11.CKM_CDMF_ECB
	case padlockpb.MechanismType_CKM_CDMF_CBC:
		converted = pkcs11.CKM_CDMF_CBC
	case padlockpb.MechanismType_CKM_CDMF_MAC:
		converted = pkcs11.CKM_CDMF_MAC
	case padlockpb.MechanismType_CKM_CDMF_MAC_GENERAL:
		converted = pkcs11.CKM_CDMF_MAC_GENERAL
	case padlockpb.MechanismType_CKM_CDMF_CBC_PAD:
		converted = pkcs11.CKM_CDMF_CBC_PAD
	case padlockpb.MechanismType_CKM_DES_OFB64:
		converted = pkcs11.CKM_DES_OFB64
	case padlockpb.MechanismType_CKM_DES_OFB8:
		converted = pkcs11.CKM_DES_OFB8
	case padlockpb.MechanismType_CKM_DES_CFB64:
		converted = pkcs11.CKM_DES_CFB64
	case padlockpb.MechanismType_CKM_DES_CFB8:
		converted = pkcs11.CKM_DES_CFB8
	case padlockpb.MechanismType_CKM_MD2:
		converted = pkcs11.CKM_MD2
	case padlockpb.MechanismType_CKM_MD2_HMAC:
		converted = pkcs11.CKM_MD2_HMAC
	case padlockpb.MechanismType_CKM_MD2_HMAC_GENERAL:
		converted = pkcs11.CKM_MD2_HMAC_GENERAL
	case padlockpb.MechanismType_CKM_MD5:
		converted = pkcs11.CKM_MD5
	case padlockpb.MechanismType_CKM_MD5_HMAC:
		converted = pkcs11.CKM_MD5_HMAC
	case padlockpb.MechanismType_CKM_MD5_HMAC_GENERAL:
		converted = pkcs11.CKM_MD5_HMAC_GENERAL
	case padlockpb.MechanismType_CKM_SHA_1:
		converted = pkcs11.CKM_SHA_1
	case padlockpb.MechanismType_CKM_SHA_1_HMAC:
		converted = pkcs11.CKM_SHA_1_HMAC
	case padlockpb.MechanismType_CKM_SHA_1_HMAC_GENERAL:
		converted = pkcs11.CKM_SHA_1_HMAC_GENERAL
	case padlockpb.MechanismType_CKM_RIPEMD128:
		converted = pkcs11.CKM_RIPEMD128
	case padlockpb.MechanismType_CKM_RIPEMD128_HMAC:
		converted = pkcs11.CKM_RIPEMD128_HMAC
	case padlockpb.MechanismType_CKM_RIPEMD128_HMAC_GENERAL:
		converted = pkcs11.CKM_RIPEMD128_HMAC_GENERAL
	case padlockpb.MechanismType_CKM_RIPEMD160:
		converted = pkcs11.CKM_RIPEMD160
	case padlockpb.MechanismType_CKM_RIPEMD160_HMAC:
		converted = pkcs11.CKM_RIPEMD160_HMAC
	case padlockpb.MechanismType_CKM_RIPEMD160_HMAC_GENERAL:
		converted = pkcs11.CKM_RIPEMD160_HMAC_GENERAL
	case padlockpb.MechanismType_CKM_SHA256:
		converted = pkcs11.CKM_SHA256
	case padlockpb.MechanismType_CKM_SHA256_HMAC:
		converted = pkcs11.CKM_SHA256_HMAC
	case padlockpb.MechanismType_CKM_SHA256_HMAC_GENERAL:
		converted = pkcs11.CKM_SHA256_HMAC_GENERAL
	case padlockpb.MechanismType_CKM_SHA224:
		converted = pkcs11.CKM_SHA224
	case padlockpb.MechanismType_CKM_SHA224_HMAC:
		converted = pkcs11.CKM_SHA224_HMAC
	case padlockpb.MechanismType_CKM_SHA224_HMAC_GENERAL:
		converted = pkcs11.CKM_SHA224_HMAC_GENERAL
	case padlockpb.MechanismType_CKM_SHA384:
		converted = pkcs11.CKM_SHA384
	case padlockpb.MechanismType_CKM_SHA384_HMAC:
		converted = pkcs11.CKM_SHA384_HMAC
	case padlockpb.MechanismType_CKM_SHA384_HMAC_GENERAL:
		converted = pkcs11.CKM_SHA384_HMAC_GENERAL
	case padlockpb.MechanismType_CKM_SHA512:
		converted = pkcs11.CKM_SHA512
	case padlockpb.MechanismType_CKM_SHA512_HMAC:
		converted = pkcs11.CKM_SHA512_HMAC
	case padlockpb.MechanismType_CKM_SHA512_HMAC_GENERAL:
		converted = pkcs11.CKM_SHA512_HMAC_GENERAL
	case padlockpb.MechanismType_CKM_SECURID_KEY_GEN:
		converted = pkcs11.CKM_SECURID_KEY_GEN
	case padlockpb.MechanismType_CKM_SECURID:
		converted = pkcs11.CKM_SECURID
	case padlockpb.MechanismType_CKM_HOTP_KEY_GEN:
		converted = pkcs11.CKM_HOTP_KEY_GEN
	case padlockpb.MechanismType_CKM_HOTP:
		converted = pkcs11.CKM_HOTP
	case padlockpb.MechanismType_CKM_ACTI:
		converted = pkcs11.CKM_ACTI
	case padlockpb.MechanismType_CKM_ACTI_KEY_GEN:
		converted = pkcs11.CKM_ACTI_KEY_GEN
	case padlockpb.MechanismType_CKM_SHA3_256:
		converted = pkcs11.CKM_SHA3_256
	case padlockpb.MechanismType_CKM_SHA3_256_HMAC:
		converted = pkcs11.CKM_SHA3_256_HMAC
	case padlockpb.MechanismType_CKM_SHA3_256_HMAC_GENERAL:
		converted = pkcs11.CKM_SHA3_256_HMAC_GENERAL
	case padlockpb.MechanismType_CKM_SHA3_256_KEY_GEN:
		converted = pkcs11.CKM_SHA3_256_KEY_GEN
	case padlockpb.MechanismType_CKM_SHA3_224:
		converted = pkcs11.CKM_SHA3_224
	case padlockpb.MechanismType_CKM_SHA3_224_HMAC:
		converted = pkcs11.CKM_SHA3_224_HMAC
	case padlockpb.MechanismType_CKM_SHA3_224_HMAC_GENERAL:
		converted = pkcs11.CKM_SHA3_224_HMAC_GENERAL
	case padlockpb.MechanismType_CKM_SHA3_224_KEY_GEN:
		converted = pkcs11.CKM_SHA3_224_KEY_GEN
	case padlockpb.MechanismType_CKM_SHA3_384:
		converted = pkcs11.CKM_SHA3_384
	case padlockpb.MechanismType_CKM_SHA3_384_HMAC:
		converted = pkcs11.CKM_SHA3_384_HMAC
	case padlockpb.MechanismType_CKM_SHA3_384_HMAC_GENERAL:
		converted = pkcs11.CKM_SHA3_384_HMAC_GENERAL
	case padlockpb.MechanismType_CKM_SHA3_384_KEY_GEN:
		converted = pkcs11.CKM_SHA3_384_KEY_GEN
	case padlockpb.MechanismType_CKM_SHA3_512:
		converted = pkcs11.CKM_SHA3_512
	case padlockpb.MechanismType_CKM_SHA3_512_HMAC:
		converted = pkcs11.CKM_SHA3_512_HMAC
	case padlockpb.MechanismType_CKM_SHA3_512_HMAC_GENERAL:
		converted = pkcs11.CKM_SHA3_512_HMAC_GENERAL
	case padlockpb.MechanismType_CKM_SHA3_512_KEY_GEN:
		converted = pkcs11.CKM_SHA3_512_KEY_GEN
	case padlockpb.MechanismType_CKM_CAST_KEY_GEN:
		converted = pkcs11.CKM_CAST_KEY_GEN
	case padlockpb.MechanismType_CKM_CAST_ECB:
		converted = pkcs11.CKM_CAST_ECB
	case padlockpb.MechanismType_CKM_CAST_CBC:
		converted = pkcs11.CKM_CAST_CBC
	case padlockpb.MechanismType_CKM_CAST_MAC:
		converted = pkcs11.CKM_CAST_MAC
	case padlockpb.MechanismType_CKM_CAST_MAC_GENERAL:
		converted = pkcs11.CKM_CAST_MAC_GENERAL
	case padlockpb.MechanismType_CKM_CAST_CBC_PAD:
		converted = pkcs11.CKM_CAST_CBC_PAD
	case padlockpb.MechanismType_CKM_CAST3_KEY_GEN:
		converted = pkcs11.CKM_CAST3_KEY_GEN
	case padlockpb.MechanismType_CKM_CAST3_ECB:
		converted = pkcs11.CKM_CAST3_ECB
	case padlockpb.MechanismType_CKM_CAST3_CBC:
		converted = pkcs11.CKM_CAST3_CBC
	case padlockpb.MechanismType_CKM_CAST3_MAC:
		converted = pkcs11.CKM_CAST3_MAC
	case padlockpb.MechanismType_CKM_CAST3_MAC_GENERAL:
		converted = pkcs11.CKM_CAST3_MAC_GENERAL
	case padlockpb.MechanismType_CKM_CAST3_CBC_PAD:
		converted = pkcs11.CKM_CAST3_CBC_PAD
	case padlockpb.MechanismType_CKM_CAST5_KEY_GEN:
		converted = pkcs11.CKM_CAST5_KEY_GEN
	case padlockpb.MechanismType_CKM_CAST128_KEY_GEN:
		converted = pkcs11.CKM_CAST128_KEY_GEN
	case padlockpb.MechanismType_CKM_CAST5_ECB:
		converted = pkcs11.CKM_CAST5_ECB
	case padlockpb.MechanismType_CKM_CAST128_ECB:
		converted = pkcs11.CKM_CAST128_ECB
	case padlockpb.MechanismType_CKM_CAST5_CBC:
		converted = pkcs11.CKM_CAST5_CBC
	case padlockpb.MechanismType_CKM_CAST128_CBC:
		converted = pkcs11.CKM_CAST128_CBC
	case padlockpb.MechanismType_CKM_CAST5_MAC:
		converted = pkcs11.CKM_CAST5_MAC
	case padlockpb.MechanismType_CKM_CAST128_MAC:
		converted = pkcs11.CKM_CAST128_MAC
	case padlockpb.MechanismType_CKM_CAST5_MAC_GENERAL:
		converted = pkcs11.CKM_CAST5_MAC_GENERAL
	case padlockpb.MechanismType_CKM_CAST128_MAC_GENERAL:
		converted = pkcs11.CKM_CAST128_MAC_GENERAL
	case padlockpb.MechanismType_CKM_CAST5_CBC_PAD:
		converted = pkcs11.CKM_CAST5_CBC_PAD
	case padlockpb.MechanismType_CKM_CAST128_CBC_PAD:
		converted = pkcs11.CKM_CAST128_CBC_PAD
	case padlockpb.MechanismType_CKM_RC5_KEY_GEN:
		converted = pkcs11.CKM_RC5_KEY_GEN
	case padlockpb.MechanismType_CKM_RC5_ECB:
		converted = pkcs11.CKM_RC5_ECB
	case padlockpb.MechanismType_CKM_RC5_CBC:
		converted = pkcs11.CKM_RC5_CBC
	case padlockpb.MechanismType_CKM_RC5_MAC:
		converted = pkcs11.CKM_RC5_MAC
	case padlockpb.MechanismType_CKM_RC5_MAC_GENERAL:
		converted = pkcs11.CKM_RC5_MAC_GENERAL
	case padlockpb.MechanismType_CKM_RC5_CBC_PAD:
		converted = pkcs11.CKM_RC5_CBC_PAD
	case padlockpb.MechanismType_CKM_IDEA_KEY_GEN:
		converted = pkcs11.CKM_IDEA_KEY_GEN
	case padlockpb.MechanismType_CKM_IDEA_ECB:
		converted = pkcs11.CKM_IDEA_ECB
	case padlockpb.MechanismType_CKM_IDEA_CBC:
		converted = pkcs11.CKM_IDEA_CBC
	case padlockpb.MechanismType_CKM_IDEA_MAC:
		converted = pkcs11.CKM_IDEA_MAC
	case padlockpb.MechanismType_CKM_IDEA_MAC_GENERAL:
		converted = pkcs11.CKM_IDEA_MAC_GENERAL
	case padlockpb.MechanismType_CKM_IDEA_CBC_PAD:
		converted = pkcs11.CKM_IDEA_CBC_PAD
	case padlockpb.MechanismType_CKM_GENERIC_SECRET_KEY_GEN:
		converted = pkcs11.CKM_GENERIC_SECRET_KEY_GEN
	case padlockpb.MechanismType_CKM_CONCATENATE_BASE_AND_KEY:
		converted = pkcs11.CKM_CONCATENATE_BASE_AND_KEY
	case padlockpb.MechanismType_CKM_CONCATENATE_BASE_AND_DATA:
		converted = pkcs11.CKM_CONCATENATE_BASE_AND_DATA
	case padlockpb.MechanismType_CKM_CONCATENATE_DATA_AND_BASE:
		converted = pkcs11.CKM_CONCATENATE_DATA_AND_BASE
	case padlockpb.MechanismType_CKM_XOR_BASE_AND_DATA:
		converted = pkcs11.CKM_XOR_BASE_AND_DATA
	case padlockpb.MechanismType_CKM_EXTRACT_KEY_FROM_KEY:
		converted = pkcs11.CKM_EXTRACT_KEY_FROM_KEY
	case padlockpb.MechanismType_CKM_SSL3_PRE_MASTER_KEY_GEN:
		converted = pkcs11.CKM_SSL3_PRE_MASTER_KEY_GEN
	case padlockpb.MechanismType_CKM_SSL3_MASTER_KEY_DERIVE:
		converted = pkcs11.CKM_SSL3_MASTER_KEY_DERIVE
	case padlockpb.MechanismType_CKM_SSL3_KEY_AND_MAC_DERIVE:
		converted = pkcs11.CKM_SSL3_KEY_AND_MAC_DERIVE
	case padlockpb.MechanismType_CKM_SSL3_MASTER_KEY_DERIVE_DH:
		converted = pkcs11.CKM_SSL3_MASTER_KEY_DERIVE_DH
	case padlockpb.MechanismType_CKM_TLS_PRE_MASTER_KEY_GEN:
		converted = pkcs11.CKM_TLS_PRE_MASTER_KEY_GEN
	case padlockpb.MechanismType_CKM_TLS_MASTER_KEY_DERIVE:
		converted = pkcs11.CKM_TLS_MASTER_KEY_DERIVE
	case padlockpb.MechanismType_CKM_TLS_KEY_AND_MAC_DERIVE:
		converted = pkcs11.CKM_TLS_KEY_AND_MAC_DERIVE
	case padlockpb.MechanismType_CKM_TLS_MASTER_KEY_DERIVE_DH:
		converted = pkcs11.CKM_TLS_MASTER_KEY_DERIVE_DH
	case padlockpb.MechanismType_CKM_TLS_PRF:
		converted = pkcs11.CKM_TLS_PRF
	case padlockpb.MechanismType_CKM_SSL3_MD5_MAC:
		converted = pkcs11.CKM_SSL3_MD5_MAC
	case padlockpb.MechanismType_CKM_SSL3_SHA1_MAC:
		converted = pkcs11.CKM_SSL3_SHA1_MAC
	case padlockpb.MechanismType_CKM_MD5_KEY_DERIVATION:
		converted = pkcs11.CKM_MD5_KEY_DERIVATION
	case padlockpb.MechanismType_CKM_MD2_KEY_DERIVATION:
		converted = pkcs11.CKM_MD2_KEY_DERIVATION
	case padlockpb.MechanismType_CKM_SHA1_KEY_DERIVATION:
		converted = pkcs11.CKM_SHA1_KEY_DERIVATION
	case padlockpb.MechanismType_CKM_SHA256_KEY_DERIVATION:
		converted = pkcs11.CKM_SHA256_KEY_DERIVATION
	case padlockpb.MechanismType_CKM_SHA384_KEY_DERIVATION:
		converted = pkcs11.CKM_SHA384_KEY_DERIVATION
	case padlockpb.MechanismType_CKM_SHA512_KEY_DERIVATION:
		converted = pkcs11.CKM_SHA512_KEY_DERIVATION
	case padlockpb.MechanismType_CKM_SHA224_KEY_DERIVATION:
		converted = pkcs11.CKM_SHA224_KEY_DERIVATION
	case padlockpb.MechanismType_CKM_SHA3_256_KEY_DERIVE:
		converted = pkcs11.CKM_SHA3_256_KEY_DERIVE
	case padlockpb.MechanismType_CKM_SHA3_224_KEY_DERIVE:
		converted = pkcs11.CKM_SHA3_224_KEY_DERIVE
	case padlockpb.MechanismType_CKM_SHA3_384_KEY_DERIVE:
		converted = pkcs11.CKM_SHA3_384_KEY_DERIVE
	case padlockpb.MechanismType_CKM_SHA3_512_KEY_DERIVE:
		converted = pkcs11.CKM_SHA3_512_KEY_DERIVE
	case padlockpb.MechanismType_CKM_SHAKE_128_KEY_DERIVE:
		converted = pkcs11.CKM_SHAKE_128_KEY_DERIVE
	case padlockpb.MechanismType_CKM_SHAKE_256_KEY_DERIVE:
		converted = pkcs11.CKM_SHAKE_256_KEY_DERIVE
	case padlockpb.MechanismType_CKM_PBE_MD2_DES_CBC:
		converted = pkcs11.CKM_PBE_MD2_DES_CBC
	case padlockpb.MechanismType_CKM_PBE_MD5_DES_CBC:
		converted = pkcs11.CKM_PBE_MD5_DES_CBC
	case padlockpb.MechanismType_CKM_PBE_MD5_CAST_CBC:
		converted = pkcs11.CKM_PBE_MD5_CAST_CBC
	case padlockpb.MechanismType_CKM_PBE_MD5_CAST3_CBC:
		converted = pkcs11.CKM_PBE_MD5_CAST3_CBC
	case padlockpb.MechanismType_CKM_PBE_MD5_CAST5_CBC:
		converted = pkcs11.CKM_PBE_MD5_CAST5_CBC
	case padlockpb.MechanismType_CKM_PBE_MD5_CAST128_CBC:
		converted = pkcs11.CKM_PBE_MD5_CAST128_CBC
	case padlockpb.MechanismType_CKM_PBE_SHA1_CAST5_CBC:
		converted = pkcs11.CKM_PBE_SHA1_CAST5_CBC
	case padlockpb.MechanismType_CKM_PBE_SHA1_CAST128_CBC:
		converted = pkcs11.CKM_PBE_SHA1_CAST128_CBC
	case padlockpb.MechanismType_CKM_PBE_SHA1_RC4_128:
		converted = pkcs11.CKM_PBE_SHA1_RC4_128
	case padlockpb.MechanismType_CKM_PBE_SHA1_RC4_40:
		converted = pkcs11.CKM_PBE_SHA1_RC4_40
	case padlockpb.MechanismType_CKM_PBE_SHA1_DES3_EDE_CBC:
		converted = pkcs11.CKM_PBE_SHA1_DES3_EDE_CBC
	case padlockpb.MechanismType_CKM_PBE_SHA1_DES2_EDE_CBC:
		converted = pkcs11.CKM_PBE_SHA1_DES2_EDE_CBC
	case padlockpb.MechanismType_CKM_PBE_SHA1_RC2_128_CBC:
		converted = pkcs11.CKM_PBE_SHA1_RC2_128_CBC
	case padlockpb.MechanismType_CKM_PBE_SHA1_RC2_40_CBC:
		converted = pkcs11.CKM_PBE_SHA1_RC2_40_CBC
	case padlockpb.MechanismType_CKM_PKCS5_PBKD2:
		converted = pkcs11.CKM_PKCS5_PBKD2
	case padlockpb.MechanismType_CKM_PBA_SHA1_WITH_SHA1_HMAC:
		converted = pkcs11.CKM_PBA_SHA1_WITH_SHA1_HMAC
	case padlockpb.MechanismType_CKM_WTLS_PRE_MASTER_KEY_GEN:
		converted = pkcs11.CKM_WTLS_PRE_MASTER_KEY_GEN
	case padlockpb.MechanismType_CKM_WTLS_MASTER_KEY_DERIVE:
		converted = pkcs11.CKM_WTLS_MASTER_KEY_DERIVE
	case padlockpb.MechanismType_CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC:
		converted = pkcs11.CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC
	case padlockpb.MechanismType_CKM_WTLS_PRF:
		converted = pkcs11.CKM_WTLS_PRF
	case padlockpb.MechanismType_CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE:
		converted = pkcs11.CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE
	case padlockpb.MechanismType_CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE:
		converted = pkcs11.CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE
	case padlockpb.MechanismType_CKM_TLS10_MAC_SERVER:
		converted = pkcs11.CKM_TLS10_MAC_SERVER
	case padlockpb.MechanismType_CKM_TLS10_MAC_CLIENT:
		converted = pkcs11.CKM_TLS10_MAC_CLIENT
	case padlockpb.MechanismType_CKM_TLS12_MAC:
		converted = pkcs11.CKM_TLS12_MAC
	case padlockpb.MechanismType_CKM_TLS12_KDF:
		converted = pkcs11.CKM_TLS12_KDF
	case padlockpb.MechanismType_CKM_TLS12_MASTER_KEY_DERIVE:
		converted = pkcs11.CKM_TLS12_MASTER_KEY_DERIVE
	case padlockpb.MechanismType_CKM_TLS12_KEY_AND_MAC_DERIVE:
		converted = pkcs11.CKM_TLS12_KEY_AND_MAC_DERIVE
	case padlockpb.MechanismType_CKM_TLS12_MASTER_KEY_DERIVE_DH:
		converted = pkcs11.CKM_TLS12_MASTER_KEY_DERIVE_DH
	case padlockpb.MechanismType_CKM_TLS12_KEY_SAFE_DERIVE:
		converted = pkcs11.CKM_TLS12_KEY_SAFE_DERIVE
	case padlockpb.MechanismType_CKM_TLS_MAC:
		converted = pkcs11.CKM_TLS_MAC
	case padlockpb.MechanismType_CKM_TLS_KDF:
		converted = pkcs11.CKM_TLS_KDF
	case padlockpb.MechanismType_CKM_KEY_WRAP_LYNKS:
		converted = pkcs11.CKM_KEY_WRAP_LYNKS
	case padlockpb.MechanismType_CKM_KEY_WRAP_SET_OAEP:
		converted = pkcs11.CKM_KEY_WRAP_SET_OAEP
	case padlockpb.MechanismType_CKM_CMS_SIG:
		converted = pkcs11.CKM_CMS_SIG
	case padlockpb.MechanismType_CKM_KIP_DERIVE:
		converted = pkcs11.CKM_KIP_DERIVE
	case padlockpb.MechanismType_CKM_KIP_WRAP:
		converted = pkcs11.CKM_KIP_WRAP
	case padlockpb.MechanismType_CKM_KIP_MAC:
		converted = pkcs11.CKM_KIP_MAC
	case padlockpb.MechanismType_CKM_CAMELLIA_KEY_GEN:
		converted = pkcs11.CKM_CAMELLIA_KEY_GEN
	case padlockpb.MechanismType_CKM_CAMELLIA_ECB:
		converted = pkcs11.CKM_CAMELLIA_ECB
	case padlockpb.MechanismType_CKM_CAMELLIA_CBC:
		converted = pkcs11.CKM_CAMELLIA_CBC
	case padlockpb.MechanismType_CKM_CAMELLIA_MAC:
		converted = pkcs11.CKM_CAMELLIA_MAC
	case padlockpb.MechanismType_CKM_CAMELLIA_MAC_GENERAL:
		converted = pkcs11.CKM_CAMELLIA_MAC_GENERAL
	case padlockpb.MechanismType_CKM_CAMELLIA_CBC_PAD:
		converted = pkcs11.CKM_CAMELLIA_CBC_PAD
	case padlockpb.MechanismType_CKM_CAMELLIA_ECB_ENCRYPT_DATA:
		converted = pkcs11.CKM_CAMELLIA_ECB_ENCRYPT_DATA
	case padlockpb.MechanismType_CKM_CAMELLIA_CBC_ENCRYPT_DATA:
		converted = pkcs11.CKM_CAMELLIA_CBC_ENCRYPT_DATA
	case padlockpb.MechanismType_CKM_CAMELLIA_CTR:
		converted = pkcs11.CKM_CAMELLIA_CTR
	case padlockpb.MechanismType_CKM_ARIA_KEY_GEN:
		converted = pkcs11.CKM_ARIA_KEY_GEN
	case padlockpb.MechanismType_CKM_ARIA_ECB:
		converted = pkcs11.CKM_ARIA_ECB
	case padlockpb.MechanismType_CKM_ARIA_CBC:
		converted = pkcs11.CKM_ARIA_CBC
	case padlockpb.MechanismType_CKM_ARIA_MAC:
		converted = pkcs11.CKM_ARIA_MAC
	case padlockpb.MechanismType_CKM_ARIA_MAC_GENERAL:
		converted = pkcs11.CKM_ARIA_MAC_GENERAL
	case padlockpb.MechanismType_CKM_ARIA_CBC_PAD:
		converted = pkcs11.CKM_ARIA_CBC_PAD
	case padlockpb.MechanismType_CKM_ARIA_ECB_ENCRYPT_DATA:
		converted = pkcs11.CKM_ARIA_ECB_ENCRYPT_DATA
	case padlockpb.MechanismType_CKM_ARIA_CBC_ENCRYPT_DATA:
		converted = pkcs11.CKM_ARIA_CBC_ENCRYPT_DATA
	case padlockpb.MechanismType_CKM_SEED_KEY_GEN:
		converted = pkcs11.CKM_SEED_KEY_GEN
	case padlockpb.MechanismType_CKM_SEED_ECB:
		converted = pkcs11.CKM_SEED_ECB
	case padlockpb.MechanismType_CKM_SEED_CBC:
		converted = pkcs11.CKM_SEED_CBC
	case padlockpb.MechanismType_CKM_SEED_MAC:
		converted = pkcs11.CKM_SEED_MAC
	case padlockpb.MechanismType_CKM_SEED_MAC_GENERAL:
		converted = pkcs11.CKM_SEED_MAC_GENERAL
	case padlockpb.MechanismType_CKM_SEED_CBC_PAD:
		converted = pkcs11.CKM_SEED_CBC_PAD
	case padlockpb.MechanismType_CKM_SEED_ECB_ENCRYPT_DATA:
		converted = pkcs11.CKM_SEED_ECB_ENCRYPT_DATA
	case padlockpb.MechanismType_CKM_SEED_CBC_ENCRYPT_DATA:
		converted = pkcs11.CKM_SEED_CBC_ENCRYPT_DATA
	case padlockpb.MechanismType_CKM_SKIPJACK_KEY_GEN:
		converted = pkcs11.CKM_SKIPJACK_KEY_GEN
	case padlockpb.MechanismType_CKM_SKIPJACK_ECB64:
		converted = pkcs11.CKM_SKIPJACK_ECB64
	case padlockpb.MechanismType_CKM_SKIPJACK_CBC64:
		converted = pkcs11.CKM_SKIPJACK_CBC64
	case padlockpb.MechanismType_CKM_SKIPJACK_OFB64:
		converted = pkcs11.CKM_SKIPJACK_OFB64
	case padlockpb.MechanismType_CKM_SKIPJACK_CFB64:
		converted = pkcs11.CKM_SKIPJACK_CFB64
	case padlockpb.MechanismType_CKM_SKIPJACK_CFB32:
		converted = pkcs11.CKM_SKIPJACK_CFB32
	case padlockpb.MechanismType_CKM_SKIPJACK_CFB16:
		converted = pkcs11.CKM_SKIPJACK_CFB16
	case padlockpb.MechanismType_CKM_SKIPJACK_CFB8:
		converted = pkcs11.CKM_SKIPJACK_CFB8
	case padlockpb.MechanismType_CKM_SKIPJACK_WRAP:
		converted = pkcs11.CKM_SKIPJACK_WRAP
	case padlockpb.MechanismType_CKM_SKIPJACK_PRIVATE_WRAP:
		converted = pkcs11.CKM_SKIPJACK_PRIVATE_WRAP
	case padlockpb.MechanismType_CKM_SKIPJACK_RELAYX:
		converted = pkcs11.CKM_SKIPJACK_RELAYX
	case padlockpb.MechanismType_CKM_KEA_KEY_PAIR_GEN:
		converted = pkcs11.CKM_KEA_KEY_PAIR_GEN
	case padlockpb.MechanismType_CKM_KEA_KEY_DERIVE:
		converted = pkcs11.CKM_KEA_KEY_DERIVE
	case padlockpb.MechanismType_CKM_KEA_DERIVE:
		converted = pkcs11.CKM_KEA_DERIVE
	case padlockpb.MechanismType_CKM_FORTEZZA_TIMESTAMP:
		converted = pkcs11.CKM_FORTEZZA_TIMESTAMP
	case padlockpb.MechanismType_CKM_BATON_KEY_GEN:
		converted = pkcs11.CKM_BATON_KEY_GEN
	case padlockpb.MechanismType_CKM_BATON_ECB128:
		converted = pkcs11.CKM_BATON_ECB128
	case padlockpb.MechanismType_CKM_BATON_ECB96:
		converted = pkcs11.CKM_BATON_ECB96
	case padlockpb.MechanismType_CKM_BATON_CBC128:
		converted = pkcs11.CKM_BATON_CBC128
	case padlockpb.MechanismType_CKM_BATON_COUNTER:
		converted = pkcs11.CKM_BATON_COUNTER
	case padlockpb.MechanismType_CKM_BATON_SHUFFLE:
		converted = pkcs11.CKM_BATON_SHUFFLE
	case padlockpb.MechanismType_CKM_BATON_WRAP:
		converted = pkcs11.CKM_BATON_WRAP
	case padlockpb.MechanismType_CKM_ECDSA_KEY_PAIR_GEN:
		converted = pkcs11.CKM_ECDSA_KEY_PAIR_GEN
	case padlockpb.MechanismType_CKM_EC_KEY_PAIR_GEN:
		converted = pkcs11.CKM_EC_KEY_PAIR_GEN
	case padlockpb.MechanismType_CKM_ECDSA:
		converted = pkcs11.CKM_ECDSA
	case padlockpb.MechanismType_CKM_ECDSA_SHA1:
		converted = pkcs11.CKM_ECDSA_SHA1
	case padlockpb.MechanismType_CKM_ECDSA_SHA224:
		converted = pkcs11.CKM_ECDSA_SHA224
	case padlockpb.MechanismType_CKM_ECDSA_SHA256:
		converted = pkcs11.CKM_ECDSA_SHA256
	case padlockpb.MechanismType_CKM_ECDSA_SHA384:
		converted = pkcs11.CKM_ECDSA_SHA384
	case padlockpb.MechanismType_CKM_ECDSA_SHA512:
		converted = pkcs11.CKM_ECDSA_SHA512
	case padlockpb.MechanismType_CKM_ECDH1_DERIVE:
		converted = pkcs11.CKM_ECDH1_DERIVE
	case padlockpb.MechanismType_CKM_ECDH1_COFACTOR_DERIVE:
		converted = pkcs11.CKM_ECDH1_COFACTOR_DERIVE
	case padlockpb.MechanismType_CKM_ECMQV_DERIVE:
		converted = pkcs11.CKM_ECMQV_DERIVE
	case padlockpb.MechanismType_CKM_ECDH_AES_KEY_WRAP:
		converted = pkcs11.CKM_ECDH_AES_KEY_WRAP
	case padlockpb.MechanismType_CKM_RSA_AES_KEY_WRAP:
		converted = pkcs11.CKM_RSA_AES_KEY_WRAP
	case padlockpb.MechanismType_CKM_JUNIPER_KEY_GEN:
		converted = pkcs11.CKM_JUNIPER_KEY_GEN
	case padlockpb.MechanismType_CKM_JUNIPER_ECB128:
		converted = pkcs11.CKM_JUNIPER_ECB128
	case padlockpb.MechanismType_CKM_JUNIPER_CBC128:
		converted = pkcs11.CKM_JUNIPER_CBC128
	case padlockpb.MechanismType_CKM_JUNIPER_COUNTER:
		converted = pkcs11.CKM_JUNIPER_COUNTER
	case padlockpb.MechanismType_CKM_JUNIPER_SHUFFLE:
		converted = pkcs11.CKM_JUNIPER_SHUFFLE
	case padlockpb.MechanismType_CKM_JUNIPER_WRAP:
		converted = pkcs11.CKM_JUNIPER_WRAP
	case padlockpb.MechanismType_CKM_FASTHASH:
		converted = pkcs11.CKM_FASTHASH
	case padlockpb.MechanismType_CKM_AES_KEY_GEN:
		converted = pkcs11.CKM_AES_KEY_GEN
	case padlockpb.MechanismType_CKM_AES_ECB:
		converted = pkcs11.CKM_AES_ECB
	case padlockpb.MechanismType_CKM_AES_CBC:
		converted = pkcs11.CKM_AES_CBC
	case padlockpb.MechanismType_CKM_AES_MAC:
		converted = pkcs11.CKM_AES_MAC
	case padlockpb.MechanismType_CKM_AES_MAC_GENERAL:
		converted = pkcs11.CKM_AES_MAC_GENERAL
	case padlockpb.MechanismType_CKM_AES_CBC_PAD:
		converted = pkcs11.CKM_AES_CBC_PAD
	case padlockpb.MechanismType_CKM_AES_CTR:
		converted = pkcs11.CKM_AES_CTR
	case padlockpb.MechanismType_CKM_AES_GCM:
		converted = pkcs11.CKM_AES_GCM
	case padlockpb.MechanismType_CKM_AES_CCM:
		converted = pkcs11.CKM_AES_CCM
	case padlockpb.MechanismType_CKM_AES_CMAC_GENERAL:
		converted = pkcs11.CKM_AES_CMAC_GENERAL
	case padlockpb.MechanismType_CKM_AES_CMAC:
		converted = pkcs11.CKM_AES_CMAC
	case padlockpb.MechanismType_CKM_AES_CTS:
		converted = pkcs11.CKM_AES_CTS
	case padlockpb.MechanismType_CKM_AES_XCBC_MAC:
		converted = pkcs11.CKM_AES_XCBC_MAC
	case padlockpb.MechanismType_CKM_AES_XCBC_MAC_96:
		converted = pkcs11.CKM_AES_XCBC_MAC_96
	case padlockpb.MechanismType_CKM_AES_GMAC:
		converted = pkcs11.CKM_AES_GMAC
	case padlockpb.MechanismType_CKM_BLOWFISH_KEY_GEN:
		converted = pkcs11.CKM_BLOWFISH_KEY_GEN
	case padlockpb.MechanismType_CKM_BLOWFISH_CBC:
		converted = pkcs11.CKM_BLOWFISH_CBC
	case padlockpb.MechanismType_CKM_TWOFISH_KEY_GEN:
		converted = pkcs11.CKM_TWOFISH_KEY_GEN
	case padlockpb.MechanismType_CKM_TWOFISH_CBC:
		converted = pkcs11.CKM_TWOFISH_CBC
	case padlockpb.MechanismType_CKM_BLOWFISH_CBC_PAD:
		converted = pkcs11.CKM_BLOWFISH_CBC_PAD
	case padlockpb.MechanismType_CKM_TWOFISH_CBC_PAD:
		converted = pkcs11.CKM_TWOFISH_CBC_PAD
	case padlockpb.MechanismType_CKM_DES_ECB_ENCRYPT_DATA:
		converted = pkcs11.CKM_DES_ECB_ENCRYPT_DATA
	case padlockpb.MechanismType_CKM_DES_CBC_ENCRYPT_DATA:
		converted = pkcs11.CKM_DES_CBC_ENCRYPT_DATA
	case padlockpb.MechanismType_CKM_DES3_ECB_ENCRYPT_DATA:
		converted = pkcs11.CKM_DES3_ECB_ENCRYPT_DATA
	case padlockpb.MechanismType_CKM_DES3_CBC_ENCRYPT_DATA:
		converted = pkcs11.CKM_DES3_CBC_ENCRYPT_DATA
	case padlockpb.MechanismType_CKM_AES_ECB_ENCRYPT_DATA:
		converted = pkcs11.CKM_AES_ECB_ENCRYPT_DATA
	case padlockpb.MechanismType_CKM_AES_CBC_ENCRYPT_DATA:
		converted = pkcs11.CKM_AES_CBC_ENCRYPT_DATA
	case padlockpb.MechanismType_CKM_GOSTR3410_KEY_PAIR_GEN:
		converted = pkcs11.CKM_GOSTR3410_KEY_PAIR_GEN
	case padlockpb.MechanismType_CKM_GOSTR3410:
		converted = pkcs11.CKM_GOSTR3410
	case padlockpb.MechanismType_CKM_GOSTR3410_WITH_GOSTR3411:
		converted = pkcs11.CKM_GOSTR3410_WITH_GOSTR3411
	case padlockpb.MechanismType_CKM_GOSTR3410_KEY_WRAP:
		converted = pkcs11.CKM_GOSTR3410_KEY_WRAP
	case padlockpb.MechanismType_CKM_GOSTR3410_DERIVE:
		converted = pkcs11.CKM_GOSTR3410_DERIVE
	case padlockpb.MechanismType_CKM_GOSTR3411:
		converted = pkcs11.CKM_GOSTR3411
	case padlockpb.MechanismType_CKM_GOSTR3411_HMAC:
		converted = pkcs11.CKM_GOSTR3411_HMAC
	case padlockpb.MechanismType_CKM_GOST28147_KEY_GEN:
		converted = pkcs11.CKM_GOST28147_KEY_GEN
	case padlockpb.MechanismType_CKM_GOST28147_ECB:
		converted = pkcs11.CKM_GOST28147_ECB
	case padlockpb.MechanismType_CKM_GOST28147:
		converted = pkcs11.CKM_GOST28147
	case padlockpb.MechanismType_CKM_GOST28147_MAC:
		converted = pkcs11.CKM_GOST28147_MAC
	case padlockpb.MechanismType_CKM_GOST28147_KEY_WRAP:
		converted = pkcs11.CKM_GOST28147_KEY_WRAP
	case padlockpb.MechanismType_CKM_DSA_PARAMETER_GEN:
		converted = pkcs11.CKM_DSA_PARAMETER_GEN
	case padlockpb.MechanismType_CKM_DH_PKCS_PARAMETER_GEN:
		converted = pkcs11.CKM_DH_PKCS_PARAMETER_GEN
	case padlockpb.MechanismType_CKM_X9_42_DH_PARAMETER_GEN:
		converted = pkcs11.CKM_X9_42_DH_PARAMETER_GEN
	case padlockpb.MechanismType_CKM_DSA_PROBABLISTIC_PARAMETER_GEN:
		converted = pkcs11.CKM_DSA_PROBABLISTIC_PARAMETER_GEN
	case padlockpb.MechanismType_CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN:
		converted = pkcs11.CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN
	case padlockpb.MechanismType_CKM_AES_OFB:
		converted = pkcs11.CKM_AES_OFB
	case padlockpb.MechanismType_CKM_AES_CFB64:
		converted = pkcs11.CKM_AES_CFB64
	case padlockpb.MechanismType_CKM_AES_CFB8:
		converted = pkcs11.CKM_AES_CFB8
	case padlockpb.MechanismType_CKM_AES_CFB128:
		converted = pkcs11.CKM_AES_CFB128
	case padlockpb.MechanismType_CKM_AES_CFB1:
		converted = pkcs11.CKM_AES_CFB1
	case padlockpb.MechanismType_CKM_AES_KEY_WRAP:
		converted = pkcs11.CKM_AES_KEY_WRAP
	case padlockpb.MechanismType_CKM_AES_KEY_WRAP_PAD:
		converted = pkcs11.CKM_AES_KEY_WRAP_PAD
	case padlockpb.MechanismType_CKM_RSA_PKCS_TPM_1_1:
		converted = pkcs11.CKM_RSA_PKCS_TPM_1_1
	case padlockpb.MechanismType_CKM_RSA_PKCS_OAEP_TPM_1_1:
		converted = pkcs11.CKM_RSA_PKCS_OAEP_TPM_1_1
	case padlockpb.MechanismType_CKM_VENDOR_DEFINED:
		converted = pkcs11.CKM_VENDOR_DEFINED
	}
	return uint(converted)
}

// MechanismP11toPB converts mechanism enums
func MechanismP11toPB(mech uint) padlockpb.MechanismType {
	converted := padlockpb.MechanismType_CKM_UNDEFINED_UNKNOWN // invalid for everything
	switch mech {
	case pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN:
		converted = padlockpb.MechanismType_CKM_RSA_PKCS_KEY_PAIR_GEN
	case pkcs11.CKM_RSA_PKCS:
		converted = padlockpb.MechanismType_CKM_RSA_PKCS
	case pkcs11.CKM_RSA_9796:
		converted = padlockpb.MechanismType_CKM_RSA_9796
	case pkcs11.CKM_RSA_X_509:
		converted = padlockpb.MechanismType_CKM_RSA_X_509
	case pkcs11.CKM_MD2_RSA_PKCS:
		converted = padlockpb.MechanismType_CKM_MD2_RSA_PKCS
	case pkcs11.CKM_MD5_RSA_PKCS:
		converted = padlockpb.MechanismType_CKM_MD5_RSA_PKCS
	case pkcs11.CKM_SHA1_RSA_PKCS:
		converted = padlockpb.MechanismType_CKM_SHA1_RSA_PKCS
	case pkcs11.CKM_RIPEMD128_RSA_PKCS:
		converted = padlockpb.MechanismType_CKM_RIPEMD128_RSA_PKCS
	case pkcs11.CKM_RIPEMD160_RSA_PKCS:
		converted = padlockpb.MechanismType_CKM_RIPEMD160_RSA_PKCS
	case pkcs11.CKM_RSA_PKCS_OAEP:
		converted = padlockpb.MechanismType_CKM_RSA_PKCS_OAEP
	case pkcs11.CKM_RSA_X9_31_KEY_PAIR_GEN:
		converted = padlockpb.MechanismType_CKM_RSA_X9_31_KEY_PAIR_GEN
	case pkcs11.CKM_RSA_X9_31:
		converted = padlockpb.MechanismType_CKM_RSA_X9_31
	case pkcs11.CKM_SHA1_RSA_X9_31:
		converted = padlockpb.MechanismType_CKM_SHA1_RSA_X9_31
	case pkcs11.CKM_RSA_PKCS_PSS:
		converted = padlockpb.MechanismType_CKM_RSA_PKCS_PSS
	case pkcs11.CKM_SHA1_RSA_PKCS_PSS:
		converted = padlockpb.MechanismType_CKM_SHA1_RSA_PKCS_PSS
	case pkcs11.CKM_DSA_KEY_PAIR_GEN:
		converted = padlockpb.MechanismType_CKM_DSA_KEY_PAIR_GEN
	case pkcs11.CKM_DSA:
		converted = padlockpb.MechanismType_CKM_DSA
	case pkcs11.CKM_DSA_SHA1:
		converted = padlockpb.MechanismType_CKM_DSA_SHA1
	case pkcs11.CKM_DSA_FIPS_G_GEN:
		converted = padlockpb.MechanismType_CKM_DSA_FIPS_G_GEN
	case pkcs11.CKM_DSA_SHA224:
		converted = padlockpb.MechanismType_CKM_DSA_SHA224
	case pkcs11.CKM_DSA_SHA256:
		converted = padlockpb.MechanismType_CKM_DSA_SHA256
	case pkcs11.CKM_DSA_SHA384:
		converted = padlockpb.MechanismType_CKM_DSA_SHA384
	case pkcs11.CKM_DSA_SHA512:
		converted = padlockpb.MechanismType_CKM_DSA_SHA512
	case pkcs11.CKM_DSA_SHA3_224:
		converted = padlockpb.MechanismType_CKM_DSA_SHA3_224
	case pkcs11.CKM_DSA_SHA3_256:
		converted = padlockpb.MechanismType_CKM_DSA_SHA3_256
	case pkcs11.CKM_DSA_SHA3_384:
		converted = padlockpb.MechanismType_CKM_DSA_SHA3_384
	case pkcs11.CKM_DSA_SHA3_512:
		converted = padlockpb.MechanismType_CKM_DSA_SHA3_512
	case pkcs11.CKM_DH_PKCS_KEY_PAIR_GEN:
		converted = padlockpb.MechanismType_CKM_DH_PKCS_KEY_PAIR_GEN
	case pkcs11.CKM_DH_PKCS_DERIVE:
		converted = padlockpb.MechanismType_CKM_DH_PKCS_DERIVE
	case pkcs11.CKM_X9_42_DH_KEY_PAIR_GEN:
		converted = padlockpb.MechanismType_CKM_X9_42_DH_KEY_PAIR_GEN
	case pkcs11.CKM_X9_42_DH_DERIVE:
		converted = padlockpb.MechanismType_CKM_X9_42_DH_DERIVE
	case pkcs11.CKM_X9_42_DH_HYBRID_DERIVE:
		converted = padlockpb.MechanismType_CKM_X9_42_DH_HYBRID_DERIVE
	case pkcs11.CKM_X9_42_MQV_DERIVE:
		converted = padlockpb.MechanismType_CKM_X9_42_MQV_DERIVE
	case pkcs11.CKM_SHA256_RSA_PKCS:
		converted = padlockpb.MechanismType_CKM_SHA256_RSA_PKCS
	case pkcs11.CKM_SHA384_RSA_PKCS:
		converted = padlockpb.MechanismType_CKM_SHA384_RSA_PKCS
	case pkcs11.CKM_SHA512_RSA_PKCS:
		converted = padlockpb.MechanismType_CKM_SHA512_RSA_PKCS
	case pkcs11.CKM_SHA256_RSA_PKCS_PSS:
		converted = padlockpb.MechanismType_CKM_SHA256_RSA_PKCS_PSS
	case pkcs11.CKM_SHA384_RSA_PKCS_PSS:
		converted = padlockpb.MechanismType_CKM_SHA384_RSA_PKCS_PSS
	case pkcs11.CKM_SHA512_RSA_PKCS_PSS:
		converted = padlockpb.MechanismType_CKM_SHA512_RSA_PKCS_PSS
	case pkcs11.CKM_SHA224_RSA_PKCS:
		converted = padlockpb.MechanismType_CKM_SHA224_RSA_PKCS
	case pkcs11.CKM_SHA224_RSA_PKCS_PSS:
		converted = padlockpb.MechanismType_CKM_SHA224_RSA_PKCS_PSS
	case pkcs11.CKM_SHA512_224:
		converted = padlockpb.MechanismType_CKM_SHA512_224
	case pkcs11.CKM_SHA512_224_HMAC:
		converted = padlockpb.MechanismType_CKM_SHA512_224_HMAC
	case pkcs11.CKM_SHA512_224_HMAC_GENERAL:
		converted = padlockpb.MechanismType_CKM_SHA512_224_HMAC_GENERAL
	case pkcs11.CKM_SHA512_224_KEY_DERIVATION:
		converted = padlockpb.MechanismType_CKM_SHA512_224_KEY_DERIVATION
	case pkcs11.CKM_SHA512_256:
		converted = padlockpb.MechanismType_CKM_SHA512_256
	case pkcs11.CKM_SHA512_256_HMAC:
		converted = padlockpb.MechanismType_CKM_SHA512_256_HMAC
	case pkcs11.CKM_SHA512_256_HMAC_GENERAL:
		converted = padlockpb.MechanismType_CKM_SHA512_256_HMAC_GENERAL
	case pkcs11.CKM_SHA512_256_KEY_DERIVATION:
		converted = padlockpb.MechanismType_CKM_SHA512_256_KEY_DERIVATION
	case pkcs11.CKM_SHA512_T:
		converted = padlockpb.MechanismType_CKM_SHA512_T
	case pkcs11.CKM_SHA512_T_HMAC:
		converted = padlockpb.MechanismType_CKM_SHA512_T_HMAC
	case pkcs11.CKM_SHA512_T_HMAC_GENERAL:
		converted = padlockpb.MechanismType_CKM_SHA512_T_HMAC_GENERAL
	case pkcs11.CKM_SHA512_T_KEY_DERIVATION:
		converted = padlockpb.MechanismType_CKM_SHA512_T_KEY_DERIVATION
	case pkcs11.CKM_SHA3_256_RSA_PKCS:
		converted = padlockpb.MechanismType_CKM_SHA3_256_RSA_PKCS
	case pkcs11.CKM_SHA3_384_RSA_PKCS:
		converted = padlockpb.MechanismType_CKM_SHA3_384_RSA_PKCS
	case pkcs11.CKM_SHA3_512_RSA_PKCS:
		converted = padlockpb.MechanismType_CKM_SHA3_512_RSA_PKCS
	case pkcs11.CKM_SHA3_256_RSA_PKCS_PSS:
		converted = padlockpb.MechanismType_CKM_SHA3_256_RSA_PKCS_PSS
	case pkcs11.CKM_SHA3_384_RSA_PKCS_PSS:
		converted = padlockpb.MechanismType_CKM_SHA3_384_RSA_PKCS_PSS
	case pkcs11.CKM_SHA3_512_RSA_PKCS_PSS:
		converted = padlockpb.MechanismType_CKM_SHA3_512_RSA_PKCS_PSS
	case pkcs11.CKM_SHA3_224_RSA_PKCS:
		converted = padlockpb.MechanismType_CKM_SHA3_224_RSA_PKCS
	case pkcs11.CKM_SHA3_224_RSA_PKCS_PSS:
		converted = padlockpb.MechanismType_CKM_SHA3_224_RSA_PKCS_PSS
	case pkcs11.CKM_RC2_KEY_GEN:
		converted = padlockpb.MechanismType_CKM_RC2_KEY_GEN
	case pkcs11.CKM_RC2_ECB:
		converted = padlockpb.MechanismType_CKM_RC2_ECB
	case pkcs11.CKM_RC2_CBC:
		converted = padlockpb.MechanismType_CKM_RC2_CBC
	case pkcs11.CKM_RC2_MAC:
		converted = padlockpb.MechanismType_CKM_RC2_MAC
	case pkcs11.CKM_RC2_MAC_GENERAL:
		converted = padlockpb.MechanismType_CKM_RC2_MAC_GENERAL
	case pkcs11.CKM_RC2_CBC_PAD:
		converted = padlockpb.MechanismType_CKM_RC2_CBC_PAD
	case pkcs11.CKM_RC4_KEY_GEN:
		converted = padlockpb.MechanismType_CKM_RC4_KEY_GEN
	case pkcs11.CKM_RC4:
		converted = padlockpb.MechanismType_CKM_RC4
	case pkcs11.CKM_DES_KEY_GEN:
		converted = padlockpb.MechanismType_CKM_DES_KEY_GEN
	case pkcs11.CKM_DES_ECB:
		converted = padlockpb.MechanismType_CKM_DES_ECB
	case pkcs11.CKM_DES_CBC:
		converted = padlockpb.MechanismType_CKM_DES_CBC
	case pkcs11.CKM_DES_MAC:
		converted = padlockpb.MechanismType_CKM_DES_MAC
	case pkcs11.CKM_DES_MAC_GENERAL:
		converted = padlockpb.MechanismType_CKM_DES_MAC_GENERAL
	case pkcs11.CKM_DES_CBC_PAD:
		converted = padlockpb.MechanismType_CKM_DES_CBC_PAD
	case pkcs11.CKM_DES2_KEY_GEN:
		converted = padlockpb.MechanismType_CKM_DES2_KEY_GEN
	case pkcs11.CKM_DES3_KEY_GEN:
		converted = padlockpb.MechanismType_CKM_DES3_KEY_GEN
	case pkcs11.CKM_DES3_ECB:
		converted = padlockpb.MechanismType_CKM_DES3_ECB
	case pkcs11.CKM_DES3_CBC:
		converted = padlockpb.MechanismType_CKM_DES3_CBC
	case pkcs11.CKM_DES3_MAC:
		converted = padlockpb.MechanismType_CKM_DES3_MAC
	case pkcs11.CKM_DES3_MAC_GENERAL:
		converted = padlockpb.MechanismType_CKM_DES3_MAC_GENERAL
	case pkcs11.CKM_DES3_CBC_PAD:
		converted = padlockpb.MechanismType_CKM_DES3_CBC_PAD
	case pkcs11.CKM_DES3_CMAC_GENERAL:
		converted = padlockpb.MechanismType_CKM_DES3_CMAC_GENERAL
	case pkcs11.CKM_DES3_CMAC:
		converted = padlockpb.MechanismType_CKM_DES3_CMAC
	case pkcs11.CKM_CDMF_KEY_GEN:
		converted = padlockpb.MechanismType_CKM_CDMF_KEY_GEN
	case pkcs11.CKM_CDMF_ECB:
		converted = padlockpb.MechanismType_CKM_CDMF_ECB
	case pkcs11.CKM_CDMF_CBC:
		converted = padlockpb.MechanismType_CKM_CDMF_CBC
	case pkcs11.CKM_CDMF_MAC:
		converted = padlockpb.MechanismType_CKM_CDMF_MAC
	case pkcs11.CKM_CDMF_MAC_GENERAL:
		converted = padlockpb.MechanismType_CKM_CDMF_MAC_GENERAL
	case pkcs11.CKM_CDMF_CBC_PAD:
		converted = padlockpb.MechanismType_CKM_CDMF_CBC_PAD
	case pkcs11.CKM_DES_OFB64:
		converted = padlockpb.MechanismType_CKM_DES_OFB64
	case pkcs11.CKM_DES_OFB8:
		converted = padlockpb.MechanismType_CKM_DES_OFB8
	case pkcs11.CKM_DES_CFB64:
		converted = padlockpb.MechanismType_CKM_DES_CFB64
	case pkcs11.CKM_DES_CFB8:
		converted = padlockpb.MechanismType_CKM_DES_CFB8
	case pkcs11.CKM_MD2:
		converted = padlockpb.MechanismType_CKM_MD2
	case pkcs11.CKM_MD2_HMAC:
		converted = padlockpb.MechanismType_CKM_MD2_HMAC
	case pkcs11.CKM_MD2_HMAC_GENERAL:
		converted = padlockpb.MechanismType_CKM_MD2_HMAC_GENERAL
	case pkcs11.CKM_MD5:
		converted = padlockpb.MechanismType_CKM_MD5
	case pkcs11.CKM_MD5_HMAC:
		converted = padlockpb.MechanismType_CKM_MD5_HMAC
	case pkcs11.CKM_MD5_HMAC_GENERAL:
		converted = padlockpb.MechanismType_CKM_MD5_HMAC_GENERAL
	case pkcs11.CKM_SHA_1:
		converted = padlockpb.MechanismType_CKM_SHA_1
	case pkcs11.CKM_SHA_1_HMAC:
		converted = padlockpb.MechanismType_CKM_SHA_1_HMAC
	case pkcs11.CKM_SHA_1_HMAC_GENERAL:
		converted = padlockpb.MechanismType_CKM_SHA_1_HMAC_GENERAL
	case pkcs11.CKM_RIPEMD128:
		converted = padlockpb.MechanismType_CKM_RIPEMD128
	case pkcs11.CKM_RIPEMD128_HMAC:
		converted = padlockpb.MechanismType_CKM_RIPEMD128_HMAC
	case pkcs11.CKM_RIPEMD128_HMAC_GENERAL:
		converted = padlockpb.MechanismType_CKM_RIPEMD128_HMAC_GENERAL
	case pkcs11.CKM_RIPEMD160:
		converted = padlockpb.MechanismType_CKM_RIPEMD160
	case pkcs11.CKM_RIPEMD160_HMAC:
		converted = padlockpb.MechanismType_CKM_RIPEMD160_HMAC
	case pkcs11.CKM_RIPEMD160_HMAC_GENERAL:
		converted = padlockpb.MechanismType_CKM_RIPEMD160_HMAC_GENERAL
	case pkcs11.CKM_SHA256:
		converted = padlockpb.MechanismType_CKM_SHA256
	case pkcs11.CKM_SHA256_HMAC:
		converted = padlockpb.MechanismType_CKM_SHA256_HMAC
	case pkcs11.CKM_SHA256_HMAC_GENERAL:
		converted = padlockpb.MechanismType_CKM_SHA256_HMAC_GENERAL
	case pkcs11.CKM_SHA224:
		converted = padlockpb.MechanismType_CKM_SHA224
	case pkcs11.CKM_SHA224_HMAC:
		converted = padlockpb.MechanismType_CKM_SHA224_HMAC
	case pkcs11.CKM_SHA224_HMAC_GENERAL:
		converted = padlockpb.MechanismType_CKM_SHA224_HMAC_GENERAL
	case pkcs11.CKM_SHA384:
		converted = padlockpb.MechanismType_CKM_SHA384
	case pkcs11.CKM_SHA384_HMAC:
		converted = padlockpb.MechanismType_CKM_SHA384_HMAC
	case pkcs11.CKM_SHA384_HMAC_GENERAL:
		converted = padlockpb.MechanismType_CKM_SHA384_HMAC_GENERAL
	case pkcs11.CKM_SHA512:
		converted = padlockpb.MechanismType_CKM_SHA512
	case pkcs11.CKM_SHA512_HMAC:
		converted = padlockpb.MechanismType_CKM_SHA512_HMAC
	case pkcs11.CKM_SHA512_HMAC_GENERAL:
		converted = padlockpb.MechanismType_CKM_SHA512_HMAC_GENERAL
	case pkcs11.CKM_SECURID_KEY_GEN:
		converted = padlockpb.MechanismType_CKM_SECURID_KEY_GEN
	case pkcs11.CKM_SECURID:
		converted = padlockpb.MechanismType_CKM_SECURID
	case pkcs11.CKM_HOTP_KEY_GEN:
		converted = padlockpb.MechanismType_CKM_HOTP_KEY_GEN
	case pkcs11.CKM_HOTP:
		converted = padlockpb.MechanismType_CKM_HOTP
	case pkcs11.CKM_ACTI:
		converted = padlockpb.MechanismType_CKM_ACTI
	case pkcs11.CKM_ACTI_KEY_GEN:
		converted = padlockpb.MechanismType_CKM_ACTI_KEY_GEN
	case pkcs11.CKM_SHA3_256:
		converted = padlockpb.MechanismType_CKM_SHA3_256
	case pkcs11.CKM_SHA3_256_HMAC:
		converted = padlockpb.MechanismType_CKM_SHA3_256_HMAC
	case pkcs11.CKM_SHA3_256_HMAC_GENERAL:
		converted = padlockpb.MechanismType_CKM_SHA3_256_HMAC_GENERAL
	case pkcs11.CKM_SHA3_256_KEY_GEN:
		converted = padlockpb.MechanismType_CKM_SHA3_256_KEY_GEN
	case pkcs11.CKM_SHA3_224:
		converted = padlockpb.MechanismType_CKM_SHA3_224
	case pkcs11.CKM_SHA3_224_HMAC:
		converted = padlockpb.MechanismType_CKM_SHA3_224_HMAC
	case pkcs11.CKM_SHA3_224_HMAC_GENERAL:
		converted = padlockpb.MechanismType_CKM_SHA3_224_HMAC_GENERAL
	case pkcs11.CKM_SHA3_224_KEY_GEN:
		converted = padlockpb.MechanismType_CKM_SHA3_224_KEY_GEN
	case pkcs11.CKM_SHA3_384:
		converted = padlockpb.MechanismType_CKM_SHA3_384
	case pkcs11.CKM_SHA3_384_HMAC:
		converted = padlockpb.MechanismType_CKM_SHA3_384_HMAC
	case pkcs11.CKM_SHA3_384_HMAC_GENERAL:
		converted = padlockpb.MechanismType_CKM_SHA3_384_HMAC_GENERAL
	case pkcs11.CKM_SHA3_384_KEY_GEN:
		converted = padlockpb.MechanismType_CKM_SHA3_384_KEY_GEN
	case pkcs11.CKM_SHA3_512:
		converted = padlockpb.MechanismType_CKM_SHA3_512
	case pkcs11.CKM_SHA3_512_HMAC:
		converted = padlockpb.MechanismType_CKM_SHA3_512_HMAC
	case pkcs11.CKM_SHA3_512_HMAC_GENERAL:
		converted = padlockpb.MechanismType_CKM_SHA3_512_HMAC_GENERAL
	case pkcs11.CKM_SHA3_512_KEY_GEN:
		converted = padlockpb.MechanismType_CKM_SHA3_512_KEY_GEN
	case pkcs11.CKM_CAST_KEY_GEN:
		converted = padlockpb.MechanismType_CKM_CAST_KEY_GEN
	case pkcs11.CKM_CAST_ECB:
		converted = padlockpb.MechanismType_CKM_CAST_ECB
	case pkcs11.CKM_CAST_CBC:
		converted = padlockpb.MechanismType_CKM_CAST_CBC
	case pkcs11.CKM_CAST_MAC:
		converted = padlockpb.MechanismType_CKM_CAST_MAC
	case pkcs11.CKM_CAST_MAC_GENERAL:
		converted = padlockpb.MechanismType_CKM_CAST_MAC_GENERAL
	case pkcs11.CKM_CAST_CBC_PAD:
		converted = padlockpb.MechanismType_CKM_CAST_CBC_PAD
	case pkcs11.CKM_CAST3_KEY_GEN:
		converted = padlockpb.MechanismType_CKM_CAST3_KEY_GEN
	case pkcs11.CKM_CAST3_ECB:
		converted = padlockpb.MechanismType_CKM_CAST3_ECB
	case pkcs11.CKM_CAST3_CBC:
		converted = padlockpb.MechanismType_CKM_CAST3_CBC
	case pkcs11.CKM_CAST3_MAC:
		converted = padlockpb.MechanismType_CKM_CAST3_MAC
	case pkcs11.CKM_CAST3_MAC_GENERAL:
		converted = padlockpb.MechanismType_CKM_CAST3_MAC_GENERAL
	case pkcs11.CKM_CAST3_CBC_PAD:
		converted = padlockpb.MechanismType_CKM_CAST3_CBC_PAD
	// case pkcs11.CKM_CAST5_KEY_GEN:
	// 	converted = padlockpb.MechanismType_CKM_CAST5_KEY_GEN
	case pkcs11.CKM_CAST128_KEY_GEN:
		converted = padlockpb.MechanismType_CKM_CAST128_KEY_GEN
	// case pkcs11.CKM_CAST5_ECB:
	// 	converted = padlockpb.MechanismType_CKM_CAST5_ECB
	case pkcs11.CKM_CAST128_ECB:
		converted = padlockpb.MechanismType_CKM_CAST128_ECB
	// case pkcs11.CKM_CAST5_CBC:
	// 	converted = padlockpb.MechanismType_CKM_CAST5_CBC
	case pkcs11.CKM_CAST128_CBC:
		converted = padlockpb.MechanismType_CKM_CAST128_CBC
	// case pkcs11.CKM_CAST5_MAC:
	// 	converted = padlockpb.MechanismType_CKM_CAST5_MAC
	case pkcs11.CKM_CAST128_MAC:
		converted = padlockpb.MechanismType_CKM_CAST128_MAC
	// case pkcs11.CKM_CAST5_MAC_GENERAL:
	// 	converted = padlockpb.MechanismType_CKM_CAST5_MAC_GENERAL
	case pkcs11.CKM_CAST128_MAC_GENERAL:
		converted = padlockpb.MechanismType_CKM_CAST128_MAC_GENERAL
	// case pkcs11.CKM_CAST5_CBC_PAD:
	// 	converted = padlockpb.MechanismType_CKM_CAST5_CBC_PAD
	case pkcs11.CKM_CAST128_CBC_PAD:
		converted = padlockpb.MechanismType_CKM_CAST128_CBC_PAD
	case pkcs11.CKM_RC5_KEY_GEN:
		converted = padlockpb.MechanismType_CKM_RC5_KEY_GEN
	case pkcs11.CKM_RC5_ECB:
		converted = padlockpb.MechanismType_CKM_RC5_ECB
	case pkcs11.CKM_RC5_CBC:
		converted = padlockpb.MechanismType_CKM_RC5_CBC
	case pkcs11.CKM_RC5_MAC:
		converted = padlockpb.MechanismType_CKM_RC5_MAC
	case pkcs11.CKM_RC5_MAC_GENERAL:
		converted = padlockpb.MechanismType_CKM_RC5_MAC_GENERAL
	case pkcs11.CKM_RC5_CBC_PAD:
		converted = padlockpb.MechanismType_CKM_RC5_CBC_PAD
	case pkcs11.CKM_IDEA_KEY_GEN:
		converted = padlockpb.MechanismType_CKM_IDEA_KEY_GEN
	case pkcs11.CKM_IDEA_ECB:
		converted = padlockpb.MechanismType_CKM_IDEA_ECB
	case pkcs11.CKM_IDEA_CBC:
		converted = padlockpb.MechanismType_CKM_IDEA_CBC
	case pkcs11.CKM_IDEA_MAC:
		converted = padlockpb.MechanismType_CKM_IDEA_MAC
	case pkcs11.CKM_IDEA_MAC_GENERAL:
		converted = padlockpb.MechanismType_CKM_IDEA_MAC_GENERAL
	case pkcs11.CKM_IDEA_CBC_PAD:
		converted = padlockpb.MechanismType_CKM_IDEA_CBC_PAD
	case pkcs11.CKM_GENERIC_SECRET_KEY_GEN:
		converted = padlockpb.MechanismType_CKM_GENERIC_SECRET_KEY_GEN
	case pkcs11.CKM_CONCATENATE_BASE_AND_KEY:
		converted = padlockpb.MechanismType_CKM_CONCATENATE_BASE_AND_KEY
	case pkcs11.CKM_CONCATENATE_BASE_AND_DATA:
		converted = padlockpb.MechanismType_CKM_CONCATENATE_BASE_AND_DATA
	case pkcs11.CKM_CONCATENATE_DATA_AND_BASE:
		converted = padlockpb.MechanismType_CKM_CONCATENATE_DATA_AND_BASE
	case pkcs11.CKM_XOR_BASE_AND_DATA:
		converted = padlockpb.MechanismType_CKM_XOR_BASE_AND_DATA
	case pkcs11.CKM_EXTRACT_KEY_FROM_KEY:
		converted = padlockpb.MechanismType_CKM_EXTRACT_KEY_FROM_KEY
	case pkcs11.CKM_SSL3_PRE_MASTER_KEY_GEN:
		converted = padlockpb.MechanismType_CKM_SSL3_PRE_MASTER_KEY_GEN
	case pkcs11.CKM_SSL3_MASTER_KEY_DERIVE:
		converted = padlockpb.MechanismType_CKM_SSL3_MASTER_KEY_DERIVE
	case pkcs11.CKM_SSL3_KEY_AND_MAC_DERIVE:
		converted = padlockpb.MechanismType_CKM_SSL3_KEY_AND_MAC_DERIVE
	case pkcs11.CKM_SSL3_MASTER_KEY_DERIVE_DH:
		converted = padlockpb.MechanismType_CKM_SSL3_MASTER_KEY_DERIVE_DH
	case pkcs11.CKM_TLS_PRE_MASTER_KEY_GEN:
		converted = padlockpb.MechanismType_CKM_TLS_PRE_MASTER_KEY_GEN
	case pkcs11.CKM_TLS_MASTER_KEY_DERIVE:
		converted = padlockpb.MechanismType_CKM_TLS_MASTER_KEY_DERIVE
	case pkcs11.CKM_TLS_KEY_AND_MAC_DERIVE:
		converted = padlockpb.MechanismType_CKM_TLS_KEY_AND_MAC_DERIVE
	case pkcs11.CKM_TLS_MASTER_KEY_DERIVE_DH:
		converted = padlockpb.MechanismType_CKM_TLS_MASTER_KEY_DERIVE_DH
	case pkcs11.CKM_TLS_PRF:
		converted = padlockpb.MechanismType_CKM_TLS_PRF
	case pkcs11.CKM_SSL3_MD5_MAC:
		converted = padlockpb.MechanismType_CKM_SSL3_MD5_MAC
	case pkcs11.CKM_SSL3_SHA1_MAC:
		converted = padlockpb.MechanismType_CKM_SSL3_SHA1_MAC
	case pkcs11.CKM_MD5_KEY_DERIVATION:
		converted = padlockpb.MechanismType_CKM_MD5_KEY_DERIVATION
	case pkcs11.CKM_MD2_KEY_DERIVATION:
		converted = padlockpb.MechanismType_CKM_MD2_KEY_DERIVATION
	case pkcs11.CKM_SHA1_KEY_DERIVATION:
		converted = padlockpb.MechanismType_CKM_SHA1_KEY_DERIVATION
	case pkcs11.CKM_SHA256_KEY_DERIVATION:
		converted = padlockpb.MechanismType_CKM_SHA256_KEY_DERIVATION
	case pkcs11.CKM_SHA384_KEY_DERIVATION:
		converted = padlockpb.MechanismType_CKM_SHA384_KEY_DERIVATION
	case pkcs11.CKM_SHA512_KEY_DERIVATION:
		converted = padlockpb.MechanismType_CKM_SHA512_KEY_DERIVATION
	case pkcs11.CKM_SHA224_KEY_DERIVATION:
		converted = padlockpb.MechanismType_CKM_SHA224_KEY_DERIVATION
	case pkcs11.CKM_SHA3_256_KEY_DERIVE:
		converted = padlockpb.MechanismType_CKM_SHA3_256_KEY_DERIVE
	case pkcs11.CKM_SHA3_224_KEY_DERIVE:
		converted = padlockpb.MechanismType_CKM_SHA3_224_KEY_DERIVE
	case pkcs11.CKM_SHA3_384_KEY_DERIVE:
		converted = padlockpb.MechanismType_CKM_SHA3_384_KEY_DERIVE
	case pkcs11.CKM_SHA3_512_KEY_DERIVE:
		converted = padlockpb.MechanismType_CKM_SHA3_512_KEY_DERIVE
	case pkcs11.CKM_SHAKE_128_KEY_DERIVE:
		converted = padlockpb.MechanismType_CKM_SHAKE_128_KEY_DERIVE
	case pkcs11.CKM_SHAKE_256_KEY_DERIVE:
		converted = padlockpb.MechanismType_CKM_SHAKE_256_KEY_DERIVE
	case pkcs11.CKM_PBE_MD2_DES_CBC:
		converted = padlockpb.MechanismType_CKM_PBE_MD2_DES_CBC
	case pkcs11.CKM_PBE_MD5_DES_CBC:
		converted = padlockpb.MechanismType_CKM_PBE_MD5_DES_CBC
	case pkcs11.CKM_PBE_MD5_CAST_CBC:
		converted = padlockpb.MechanismType_CKM_PBE_MD5_CAST_CBC
	case pkcs11.CKM_PBE_MD5_CAST3_CBC:
		converted = padlockpb.MechanismType_CKM_PBE_MD5_CAST3_CBC
	// case pkcs11.CKM_PBE_MD5_CAST5_CBC:
	// 	converted = padlockpb.MechanismType_CKM_PBE_MD5_CAST5_CBC
	case pkcs11.CKM_PBE_MD5_CAST128_CBC:
		converted = padlockpb.MechanismType_CKM_PBE_MD5_CAST128_CBC
	// case pkcs11.CKM_PBE_SHA1_CAST5_CBC:
	// 	converted = padlockpb.MechanismType_CKM_PBE_SHA1_CAST5_CBC
	case pkcs11.CKM_PBE_SHA1_CAST128_CBC:
		converted = padlockpb.MechanismType_CKM_PBE_SHA1_CAST128_CBC
	case pkcs11.CKM_PBE_SHA1_RC4_128:
		converted = padlockpb.MechanismType_CKM_PBE_SHA1_RC4_128
	case pkcs11.CKM_PBE_SHA1_RC4_40:
		converted = padlockpb.MechanismType_CKM_PBE_SHA1_RC4_40
	case pkcs11.CKM_PBE_SHA1_DES3_EDE_CBC:
		converted = padlockpb.MechanismType_CKM_PBE_SHA1_DES3_EDE_CBC
	case pkcs11.CKM_PBE_SHA1_DES2_EDE_CBC:
		converted = padlockpb.MechanismType_CKM_PBE_SHA1_DES2_EDE_CBC
	case pkcs11.CKM_PBE_SHA1_RC2_128_CBC:
		converted = padlockpb.MechanismType_CKM_PBE_SHA1_RC2_128_CBC
	case pkcs11.CKM_PBE_SHA1_RC2_40_CBC:
		converted = padlockpb.MechanismType_CKM_PBE_SHA1_RC2_40_CBC
	case pkcs11.CKM_PKCS5_PBKD2:
		converted = padlockpb.MechanismType_CKM_PKCS5_PBKD2
	case pkcs11.CKM_PBA_SHA1_WITH_SHA1_HMAC:
		converted = padlockpb.MechanismType_CKM_PBA_SHA1_WITH_SHA1_HMAC
	case pkcs11.CKM_WTLS_PRE_MASTER_KEY_GEN:
		converted = padlockpb.MechanismType_CKM_WTLS_PRE_MASTER_KEY_GEN
	case pkcs11.CKM_WTLS_MASTER_KEY_DERIVE:
		converted = padlockpb.MechanismType_CKM_WTLS_MASTER_KEY_DERIVE
	case pkcs11.CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC:
		converted = padlockpb.MechanismType_CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC
	case pkcs11.CKM_WTLS_PRF:
		converted = padlockpb.MechanismType_CKM_WTLS_PRF
	case pkcs11.CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE:
		converted = padlockpb.MechanismType_CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE
	case pkcs11.CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE:
		converted = padlockpb.MechanismType_CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE
	case pkcs11.CKM_TLS10_MAC_SERVER:
		converted = padlockpb.MechanismType_CKM_TLS10_MAC_SERVER
	case pkcs11.CKM_TLS10_MAC_CLIENT:
		converted = padlockpb.MechanismType_CKM_TLS10_MAC_CLIENT
	case pkcs11.CKM_TLS12_MAC:
		converted = padlockpb.MechanismType_CKM_TLS12_MAC
	case pkcs11.CKM_TLS12_KDF:
		converted = padlockpb.MechanismType_CKM_TLS12_KDF
	case pkcs11.CKM_TLS12_MASTER_KEY_DERIVE:
		converted = padlockpb.MechanismType_CKM_TLS12_MASTER_KEY_DERIVE
	case pkcs11.CKM_TLS12_KEY_AND_MAC_DERIVE:
		converted = padlockpb.MechanismType_CKM_TLS12_KEY_AND_MAC_DERIVE
	case pkcs11.CKM_TLS12_MASTER_KEY_DERIVE_DH:
		converted = padlockpb.MechanismType_CKM_TLS12_MASTER_KEY_DERIVE_DH
	case pkcs11.CKM_TLS12_KEY_SAFE_DERIVE:
		converted = padlockpb.MechanismType_CKM_TLS12_KEY_SAFE_DERIVE
	case pkcs11.CKM_TLS_MAC:
		converted = padlockpb.MechanismType_CKM_TLS_MAC
	case pkcs11.CKM_TLS_KDF:
		converted = padlockpb.MechanismType_CKM_TLS_KDF
	case pkcs11.CKM_KEY_WRAP_LYNKS:
		converted = padlockpb.MechanismType_CKM_KEY_WRAP_LYNKS
	case pkcs11.CKM_KEY_WRAP_SET_OAEP:
		converted = padlockpb.MechanismType_CKM_KEY_WRAP_SET_OAEP
	case pkcs11.CKM_CMS_SIG:
		converted = padlockpb.MechanismType_CKM_CMS_SIG
	case pkcs11.CKM_KIP_DERIVE:
		converted = padlockpb.MechanismType_CKM_KIP_DERIVE
	case pkcs11.CKM_KIP_WRAP:
		converted = padlockpb.MechanismType_CKM_KIP_WRAP
	case pkcs11.CKM_KIP_MAC:
		converted = padlockpb.MechanismType_CKM_KIP_MAC
	case pkcs11.CKM_CAMELLIA_KEY_GEN:
		converted = padlockpb.MechanismType_CKM_CAMELLIA_KEY_GEN
	case pkcs11.CKM_CAMELLIA_ECB:
		converted = padlockpb.MechanismType_CKM_CAMELLIA_ECB
	case pkcs11.CKM_CAMELLIA_CBC:
		converted = padlockpb.MechanismType_CKM_CAMELLIA_CBC
	case pkcs11.CKM_CAMELLIA_MAC:
		converted = padlockpb.MechanismType_CKM_CAMELLIA_MAC
	case pkcs11.CKM_CAMELLIA_MAC_GENERAL:
		converted = padlockpb.MechanismType_CKM_CAMELLIA_MAC_GENERAL
	case pkcs11.CKM_CAMELLIA_CBC_PAD:
		converted = padlockpb.MechanismType_CKM_CAMELLIA_CBC_PAD
	case pkcs11.CKM_CAMELLIA_ECB_ENCRYPT_DATA:
		converted = padlockpb.MechanismType_CKM_CAMELLIA_ECB_ENCRYPT_DATA
	case pkcs11.CKM_CAMELLIA_CBC_ENCRYPT_DATA:
		converted = padlockpb.MechanismType_CKM_CAMELLIA_CBC_ENCRYPT_DATA
	case pkcs11.CKM_CAMELLIA_CTR:
		converted = padlockpb.MechanismType_CKM_CAMELLIA_CTR
	case pkcs11.CKM_ARIA_KEY_GEN:
		converted = padlockpb.MechanismType_CKM_ARIA_KEY_GEN
	case pkcs11.CKM_ARIA_ECB:
		converted = padlockpb.MechanismType_CKM_ARIA_ECB
	case pkcs11.CKM_ARIA_CBC:
		converted = padlockpb.MechanismType_CKM_ARIA_CBC
	case pkcs11.CKM_ARIA_MAC:
		converted = padlockpb.MechanismType_CKM_ARIA_MAC
	case pkcs11.CKM_ARIA_MAC_GENERAL:
		converted = padlockpb.MechanismType_CKM_ARIA_MAC_GENERAL
	case pkcs11.CKM_ARIA_CBC_PAD:
		converted = padlockpb.MechanismType_CKM_ARIA_CBC_PAD
	case pkcs11.CKM_ARIA_ECB_ENCRYPT_DATA:
		converted = padlockpb.MechanismType_CKM_ARIA_ECB_ENCRYPT_DATA
	case pkcs11.CKM_ARIA_CBC_ENCRYPT_DATA:
		converted = padlockpb.MechanismType_CKM_ARIA_CBC_ENCRYPT_DATA
	case pkcs11.CKM_SEED_KEY_GEN:
		converted = padlockpb.MechanismType_CKM_SEED_KEY_GEN
	case pkcs11.CKM_SEED_ECB:
		converted = padlockpb.MechanismType_CKM_SEED_ECB
	case pkcs11.CKM_SEED_CBC:
		converted = padlockpb.MechanismType_CKM_SEED_CBC
	case pkcs11.CKM_SEED_MAC:
		converted = padlockpb.MechanismType_CKM_SEED_MAC
	case pkcs11.CKM_SEED_MAC_GENERAL:
		converted = padlockpb.MechanismType_CKM_SEED_MAC_GENERAL
	case pkcs11.CKM_SEED_CBC_PAD:
		converted = padlockpb.MechanismType_CKM_SEED_CBC_PAD
	case pkcs11.CKM_SEED_ECB_ENCRYPT_DATA:
		converted = padlockpb.MechanismType_CKM_SEED_ECB_ENCRYPT_DATA
	case pkcs11.CKM_SEED_CBC_ENCRYPT_DATA:
		converted = padlockpb.MechanismType_CKM_SEED_CBC_ENCRYPT_DATA
	case pkcs11.CKM_SKIPJACK_KEY_GEN:
		converted = padlockpb.MechanismType_CKM_SKIPJACK_KEY_GEN
	case pkcs11.CKM_SKIPJACK_ECB64:
		converted = padlockpb.MechanismType_CKM_SKIPJACK_ECB64
	case pkcs11.CKM_SKIPJACK_CBC64:
		converted = padlockpb.MechanismType_CKM_SKIPJACK_CBC64
	case pkcs11.CKM_SKIPJACK_OFB64:
		converted = padlockpb.MechanismType_CKM_SKIPJACK_OFB64
	case pkcs11.CKM_SKIPJACK_CFB64:
		converted = padlockpb.MechanismType_CKM_SKIPJACK_CFB64
	case pkcs11.CKM_SKIPJACK_CFB32:
		converted = padlockpb.MechanismType_CKM_SKIPJACK_CFB32
	case pkcs11.CKM_SKIPJACK_CFB16:
		converted = padlockpb.MechanismType_CKM_SKIPJACK_CFB16
	case pkcs11.CKM_SKIPJACK_CFB8:
		converted = padlockpb.MechanismType_CKM_SKIPJACK_CFB8
	case pkcs11.CKM_SKIPJACK_WRAP:
		converted = padlockpb.MechanismType_CKM_SKIPJACK_WRAP
	case pkcs11.CKM_SKIPJACK_PRIVATE_WRAP:
		converted = padlockpb.MechanismType_CKM_SKIPJACK_PRIVATE_WRAP
	case pkcs11.CKM_SKIPJACK_RELAYX:
		converted = padlockpb.MechanismType_CKM_SKIPJACK_RELAYX
	case pkcs11.CKM_KEA_KEY_PAIR_GEN:
		converted = padlockpb.MechanismType_CKM_KEA_KEY_PAIR_GEN
	case pkcs11.CKM_KEA_KEY_DERIVE:
		converted = padlockpb.MechanismType_CKM_KEA_KEY_DERIVE
	case pkcs11.CKM_KEA_DERIVE:
		converted = padlockpb.MechanismType_CKM_KEA_DERIVE
	case pkcs11.CKM_FORTEZZA_TIMESTAMP:
		converted = padlockpb.MechanismType_CKM_FORTEZZA_TIMESTAMP
	case pkcs11.CKM_BATON_KEY_GEN:
		converted = padlockpb.MechanismType_CKM_BATON_KEY_GEN
	case pkcs11.CKM_BATON_ECB128:
		converted = padlockpb.MechanismType_CKM_BATON_ECB128
	case pkcs11.CKM_BATON_ECB96:
		converted = padlockpb.MechanismType_CKM_BATON_ECB96
	case pkcs11.CKM_BATON_CBC128:
		converted = padlockpb.MechanismType_CKM_BATON_CBC128
	case pkcs11.CKM_BATON_COUNTER:
		converted = padlockpb.MechanismType_CKM_BATON_COUNTER
	case pkcs11.CKM_BATON_SHUFFLE:
		converted = padlockpb.MechanismType_CKM_BATON_SHUFFLE
	case pkcs11.CKM_BATON_WRAP:
		converted = padlockpb.MechanismType_CKM_BATON_WRAP
	case pkcs11.CKM_ECDSA_KEY_PAIR_GEN:
		converted = padlockpb.MechanismType_CKM_ECDSA_KEY_PAIR_GEN
	// case pkcs11.CKM_EC_KEY_PAIR_GEN:
	// 	converted = padlockpb.MechanismType_CKM_EC_KEY_PAIR_GEN
	case pkcs11.CKM_ECDSA:
		converted = padlockpb.MechanismType_CKM_ECDSA
	case pkcs11.CKM_ECDSA_SHA1:
		converted = padlockpb.MechanismType_CKM_ECDSA_SHA1
	case pkcs11.CKM_ECDSA_SHA224:
		converted = padlockpb.MechanismType_CKM_ECDSA_SHA224
	case pkcs11.CKM_ECDSA_SHA256:
		converted = padlockpb.MechanismType_CKM_ECDSA_SHA256
	case pkcs11.CKM_ECDSA_SHA384:
		converted = padlockpb.MechanismType_CKM_ECDSA_SHA384
	case pkcs11.CKM_ECDSA_SHA512:
		converted = padlockpb.MechanismType_CKM_ECDSA_SHA512
	case pkcs11.CKM_ECDH1_DERIVE:
		converted = padlockpb.MechanismType_CKM_ECDH1_DERIVE
	case pkcs11.CKM_ECDH1_COFACTOR_DERIVE:
		converted = padlockpb.MechanismType_CKM_ECDH1_COFACTOR_DERIVE
	case pkcs11.CKM_ECMQV_DERIVE:
		converted = padlockpb.MechanismType_CKM_ECMQV_DERIVE
	case pkcs11.CKM_ECDH_AES_KEY_WRAP:
		converted = padlockpb.MechanismType_CKM_ECDH_AES_KEY_WRAP
	case pkcs11.CKM_RSA_AES_KEY_WRAP:
		converted = padlockpb.MechanismType_CKM_RSA_AES_KEY_WRAP
	case pkcs11.CKM_JUNIPER_KEY_GEN:
		converted = padlockpb.MechanismType_CKM_JUNIPER_KEY_GEN
	case pkcs11.CKM_JUNIPER_ECB128:
		converted = padlockpb.MechanismType_CKM_JUNIPER_ECB128
	case pkcs11.CKM_JUNIPER_CBC128:
		converted = padlockpb.MechanismType_CKM_JUNIPER_CBC128
	case pkcs11.CKM_JUNIPER_COUNTER:
		converted = padlockpb.MechanismType_CKM_JUNIPER_COUNTER
	case pkcs11.CKM_JUNIPER_SHUFFLE:
		converted = padlockpb.MechanismType_CKM_JUNIPER_SHUFFLE
	case pkcs11.CKM_JUNIPER_WRAP:
		converted = padlockpb.MechanismType_CKM_JUNIPER_WRAP
	case pkcs11.CKM_FASTHASH:
		converted = padlockpb.MechanismType_CKM_FASTHASH
	case pkcs11.CKM_AES_KEY_GEN:
		converted = padlockpb.MechanismType_CKM_AES_KEY_GEN
	case pkcs11.CKM_AES_ECB:
		converted = padlockpb.MechanismType_CKM_AES_ECB
	case pkcs11.CKM_AES_CBC:
		converted = padlockpb.MechanismType_CKM_AES_CBC
	case pkcs11.CKM_AES_MAC:
		converted = padlockpb.MechanismType_CKM_AES_MAC
	case pkcs11.CKM_AES_MAC_GENERAL:
		converted = padlockpb.MechanismType_CKM_AES_MAC_GENERAL
	case pkcs11.CKM_AES_CBC_PAD:
		converted = padlockpb.MechanismType_CKM_AES_CBC_PAD
	case pkcs11.CKM_AES_CTR:
		converted = padlockpb.MechanismType_CKM_AES_CTR
	case pkcs11.CKM_AES_GCM:
		converted = padlockpb.MechanismType_CKM_AES_GCM
	case pkcs11.CKM_AES_CCM:
		converted = padlockpb.MechanismType_CKM_AES_CCM
	case pkcs11.CKM_AES_CMAC_GENERAL:
		converted = padlockpb.MechanismType_CKM_AES_CMAC_GENERAL
	case pkcs11.CKM_AES_CMAC:
		converted = padlockpb.MechanismType_CKM_AES_CMAC
	case pkcs11.CKM_AES_CTS:
		converted = padlockpb.MechanismType_CKM_AES_CTS
	case pkcs11.CKM_AES_XCBC_MAC:
		converted = padlockpb.MechanismType_CKM_AES_XCBC_MAC
	case pkcs11.CKM_AES_XCBC_MAC_96:
		converted = padlockpb.MechanismType_CKM_AES_XCBC_MAC_96
	case pkcs11.CKM_AES_GMAC:
		converted = padlockpb.MechanismType_CKM_AES_GMAC
	case pkcs11.CKM_BLOWFISH_KEY_GEN:
		converted = padlockpb.MechanismType_CKM_BLOWFISH_KEY_GEN
	case pkcs11.CKM_BLOWFISH_CBC:
		converted = padlockpb.MechanismType_CKM_BLOWFISH_CBC
	case pkcs11.CKM_TWOFISH_KEY_GEN:
		converted = padlockpb.MechanismType_CKM_TWOFISH_KEY_GEN
	case pkcs11.CKM_TWOFISH_CBC:
		converted = padlockpb.MechanismType_CKM_TWOFISH_CBC
	case pkcs11.CKM_BLOWFISH_CBC_PAD:
		converted = padlockpb.MechanismType_CKM_BLOWFISH_CBC_PAD
	case pkcs11.CKM_TWOFISH_CBC_PAD:
		converted = padlockpb.MechanismType_CKM_TWOFISH_CBC_PAD
	case pkcs11.CKM_DES_ECB_ENCRYPT_DATA:
		converted = padlockpb.MechanismType_CKM_DES_ECB_ENCRYPT_DATA
	case pkcs11.CKM_DES_CBC_ENCRYPT_DATA:
		converted = padlockpb.MechanismType_CKM_DES_CBC_ENCRYPT_DATA
	case pkcs11.CKM_DES3_ECB_ENCRYPT_DATA:
		converted = padlockpb.MechanismType_CKM_DES3_ECB_ENCRYPT_DATA
	case pkcs11.CKM_DES3_CBC_ENCRYPT_DATA:
		converted = padlockpb.MechanismType_CKM_DES3_CBC_ENCRYPT_DATA
	case pkcs11.CKM_AES_ECB_ENCRYPT_DATA:
		converted = padlockpb.MechanismType_CKM_AES_ECB_ENCRYPT_DATA
	case pkcs11.CKM_AES_CBC_ENCRYPT_DATA:
		converted = padlockpb.MechanismType_CKM_AES_CBC_ENCRYPT_DATA
	case pkcs11.CKM_GOSTR3410_KEY_PAIR_GEN:
		converted = padlockpb.MechanismType_CKM_GOSTR3410_KEY_PAIR_GEN
	case pkcs11.CKM_GOSTR3410:
		converted = padlockpb.MechanismType_CKM_GOSTR3410
	case pkcs11.CKM_GOSTR3410_WITH_GOSTR3411:
		converted = padlockpb.MechanismType_CKM_GOSTR3410_WITH_GOSTR3411
	case pkcs11.CKM_GOSTR3410_KEY_WRAP:
		converted = padlockpb.MechanismType_CKM_GOSTR3410_KEY_WRAP
	case pkcs11.CKM_GOSTR3410_DERIVE:
		converted = padlockpb.MechanismType_CKM_GOSTR3410_DERIVE
	case pkcs11.CKM_GOSTR3411:
		converted = padlockpb.MechanismType_CKM_GOSTR3411
	case pkcs11.CKM_GOSTR3411_HMAC:
		converted = padlockpb.MechanismType_CKM_GOSTR3411_HMAC
	case pkcs11.CKM_GOST28147_KEY_GEN:
		converted = padlockpb.MechanismType_CKM_GOST28147_KEY_GEN
	case pkcs11.CKM_GOST28147_ECB:
		converted = padlockpb.MechanismType_CKM_GOST28147_ECB
	case pkcs11.CKM_GOST28147:
		converted = padlockpb.MechanismType_CKM_GOST28147
	case pkcs11.CKM_GOST28147_MAC:
		converted = padlockpb.MechanismType_CKM_GOST28147_MAC
	case pkcs11.CKM_GOST28147_KEY_WRAP:
		converted = padlockpb.MechanismType_CKM_GOST28147_KEY_WRAP
	case pkcs11.CKM_DSA_PARAMETER_GEN:
		converted = padlockpb.MechanismType_CKM_DSA_PARAMETER_GEN
	case pkcs11.CKM_DH_PKCS_PARAMETER_GEN:
		converted = padlockpb.MechanismType_CKM_DH_PKCS_PARAMETER_GEN
	case pkcs11.CKM_X9_42_DH_PARAMETER_GEN:
		converted = padlockpb.MechanismType_CKM_X9_42_DH_PARAMETER_GEN
	case pkcs11.CKM_DSA_PROBABLISTIC_PARAMETER_GEN:
		converted = padlockpb.MechanismType_CKM_DSA_PROBABLISTIC_PARAMETER_GEN
	case pkcs11.CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN:
		converted = padlockpb.MechanismType_CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN
	case pkcs11.CKM_AES_OFB:
		converted = padlockpb.MechanismType_CKM_AES_OFB
	case pkcs11.CKM_AES_CFB64:
		converted = padlockpb.MechanismType_CKM_AES_CFB64
	case pkcs11.CKM_AES_CFB8:
		converted = padlockpb.MechanismType_CKM_AES_CFB8
	case pkcs11.CKM_AES_CFB128:
		converted = padlockpb.MechanismType_CKM_AES_CFB128
	case pkcs11.CKM_AES_CFB1:
		converted = padlockpb.MechanismType_CKM_AES_CFB1
	case pkcs11.CKM_AES_KEY_WRAP:
		converted = padlockpb.MechanismType_CKM_AES_KEY_WRAP
	case pkcs11.CKM_AES_KEY_WRAP_PAD:
		converted = padlockpb.MechanismType_CKM_AES_KEY_WRAP_PAD
	case pkcs11.CKM_RSA_PKCS_TPM_1_1:
		converted = padlockpb.MechanismType_CKM_RSA_PKCS_TPM_1_1
	case pkcs11.CKM_RSA_PKCS_OAEP_TPM_1_1:
		converted = padlockpb.MechanismType_CKM_RSA_PKCS_OAEP_TPM_1_1
	case pkcs11.CKM_VENDOR_DEFINED:
		converted = padlockpb.MechanismType_CKM_VENDOR_DEFINED
	}
	return converted
}
