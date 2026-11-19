#ifndef AG_PRIVACY_H
#define AG_PRIVACY_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* No network, consent control, test mode or raw fallback. Caller supplies valid pointers and private host key.
   Returned UTF-8 byte buffer has out_len bytes, is not NUL terminated, and must be freed once. NULL fails closed. */
uint8_t *ag_privacy_sanitize_json(const uint8_t *input, int32_t input_len, const uint8_t *key, int32_t key_len,
 const uint8_t *scope, int32_t scope_len, const uint8_t *policy, int32_t policy_len, int32_t *out_len);
/* Reusable ABI v1. Host pins both public SPKI and current approved config SHA256 outside mutable bundle.
   IDs are process-local, not auth tokens. 0 creation failure; at most64live+pending; stale ID fails closed.
   Install choices are signed by trusted human-driven installer. mode:0strict,1credentials-only,2off;-1invalid.
   Non-strict results explicitly SafeForAgent=false, AuthorizedByHumanChoice=true; never confuse with strict privacy. */
int32_t ag_privacy_abi_version(void);
int64_t ag_privacy_create_verified(const uint8_t *directory,int32_t directory_len,const uint8_t *pinned_spki,int32_t spki_len,
 const uint8_t *key,int32_t key_len,const uint8_t *approved_config_sha256,int32_t digest_len);
int32_t ag_privacy_mode(int64_t handle);
uint8_t *ag_privacy_process_json(int64_t handle,const uint8_t *input,int32_t input_len,int32_t *out_len);
void ag_privacy_destroy(int64_t handle);
void ag_privacy_free(uint8_t *buffer);
#ifdef __cplusplus
}
#endif
#endif
