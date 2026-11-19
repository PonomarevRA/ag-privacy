"""Trusted host adapter. Keep this process, keys and raw capture inaccessible to agent tool execution."""
import ctypes
import json

class PrivacyBlocked(RuntimeError):
    pass

class AgPrivacy:
    """Stateless strict JSON ABI adapter; native library architecture must match Python, with no consent/control API."""
    def __init__(self, library_path):
        try:
            self._lib=ctypes.CDLL(str(library_path))
            self._sanitize=self._lib.ag_privacy_sanitize_json
            self._sanitize.argtypes=[ctypes.c_void_p,ctypes.c_int32]*4+[ctypes.POINTER(ctypes.c_int32)]
            self._sanitize.restype=ctypes.c_void_p
            self._lib.ag_privacy_free.argtypes=[ctypes.c_void_p]
            self._lib.ag_privacy_free.restype=None
        except Exception:
            raise PrivacyBlocked('privacy-processing-blocked') from None

    def sanitize_json(self, document, key, scope, policy):
        """Only sanitized output; free native result and scrub own key buffer even on errors. Caller owns original key/text lifetime."""
        pointer=None
        key_buffer=None
        try:
            doc_bytes=document.encode('utf-8')
            scope_bytes=scope.encode('utf-8')
            if len(doc_bytes)>262144 or not 32<=len(key)<=128 or not 1<=len(scope_bytes)<=512 or not 1<=len(policy)<=65536:
                raise PrivacyBlocked('privacy-processing-blocked')
            key_buffer=(ctypes.c_ubyte*len(key)).from_buffer_copy(key)
            buffers=[ctypes.create_string_buffer(doc_bytes),key_buffer,ctypes.create_string_buffer(scope_bytes),ctypes.create_string_buffer(policy)]
            lengths=[len(doc_bytes),len(key),len(scope_bytes),len(policy)]
            args=[]
            for buffer,length in zip(buffers,lengths):args.extend([buffer,length])
            length=ctypes.c_int32()
            pointer=self._sanitize(*args,ctypes.byref(length))
            if not pointer or not 0<length.value<=4194304:raise PrivacyBlocked('privacy-processing-blocked')
            result=json.loads(ctypes.string_at(pointer,length.value))
            if not result.get('Allowed') or not result.get('SafeForAgent'):raise PrivacyBlocked('privacy-processing-blocked')
            return result
        except Exception:
            raise PrivacyBlocked('privacy-processing-blocked') from None
        finally:
            if pointer:self._lib.ag_privacy_free(pointer)
            if key_buffer is not None:ctypes.memset(key_buffer,0,len(key_buffer))


class VerifiedAgPrivacy:
    """Reusable C ABI context with caller-pinned config digest and public key. Settings/files are never taken from an agent request."""
    def __init__(self, library_path, directory, key, pinned_spki, approved_config_sha256):
        self._handle=0
        key_buffer=None
        try:
            self._lib=ctypes.CDLL(str(library_path))
            version=self._lib.ag_privacy_abi_version
            version.argtypes=[];version.restype=ctypes.c_int32
            if version()!=1:raise PrivacyBlocked('privacy-processing-blocked')
            create=self._lib.ag_privacy_create_verified
            create.argtypes=[ctypes.c_void_p,ctypes.c_int32]*4;create.restype=ctypes.c_int64
            self._process=self._lib.ag_privacy_process_json
            self._process.argtypes=[ctypes.c_int64,ctypes.c_void_p,ctypes.c_int32,ctypes.POINTER(ctypes.c_int32)]
            self._process.restype=ctypes.c_void_p
            self._lib.ag_privacy_destroy.argtypes=[ctypes.c_int64];self._lib.ag_privacy_destroy.restype=None
            self._lib.ag_privacy_mode.argtypes=[ctypes.c_int64];self._lib.ag_privacy_mode.restype=ctypes.c_int32
            self._lib.ag_privacy_free.argtypes=[ctypes.c_void_p];self._lib.ag_privacy_free.restype=None
            path=str(directory).encode('utf-8')
            if not 1<=len(path)<=16384 or not 32<=len(key)<=128 or not 1<=len(pinned_spki)<=512 or len(approved_config_sha256)!=32:
                raise PrivacyBlocked('privacy-processing-blocked')
            key_buffer=(ctypes.c_ubyte*len(key)).from_buffer_copy(key)
            buffers=[ctypes.create_string_buffer(path),ctypes.create_string_buffer(pinned_spki),key_buffer,ctypes.create_string_buffer(approved_config_sha256)]
            lengths=[len(path),len(pinned_spki),len(key),32];arguments=[]
            for buffer,length in zip(buffers,lengths):arguments.extend([buffer,length])
            self._handle=create(*arguments)
            if not self._handle:raise PrivacyBlocked('privacy-processing-blocked')
            mode=self._lib.ag_privacy_mode(self._handle)
            if mode not in (0,1,2):raise PrivacyBlocked('privacy-processing-blocked')
            self.mode=('strict','credentials-only','off')[mode]
        except Exception:
            self.close()
            raise PrivacyBlocked('privacy-processing-blocked') from None
        finally:
            if key_buffer is not None:ctypes.memset(key_buffer,0,len(key_buffer))

    def sanitize_json(self, document):
        """No policy/mode/key arguments at request time. Non-strict release requires the already-verified human installation choice."""
        pointer=None
        try:
            data=document.encode('utf-8')
            if not self._handle or len(data)>262144:raise PrivacyBlocked('privacy-processing-blocked')
            buffer=ctypes.create_string_buffer(data);length=ctypes.c_int32()
            pointer=self._process(self._handle,buffer,len(data),ctypes.byref(length))
            if not pointer or not 0<length.value<=4194304:raise PrivacyBlocked('privacy-processing-blocked')
            result=json.loads(ctypes.string_at(pointer,length.value))
            if not result.get('Allowed') or result.get('ProtectionMode')!=self.mode:raise PrivacyBlocked('privacy-processing-blocked')
            if self.mode=='strict':
                if not result.get('SafeForAgent'):raise PrivacyBlocked('privacy-processing-blocked')
            elif not result.get('AuthorizedByHumanChoice') or result.get('SafeForAgent'):
                raise PrivacyBlocked('privacy-processing-blocked')
            return result
        except Exception:
            raise PrivacyBlocked('privacy-processing-blocked') from None
        finally:
            if pointer:self._lib.ag_privacy_free(pointer)

    def close(self):
        """Idempotent release. Host must close obsolete contexts before changing active installer trust pins."""
        handle=getattr(self,'_handle',0)
        self._handle=0
        if handle:self._lib.ag_privacy_destroy(handle)

    def __enter__(self):return self
    def __exit__(self,*args):self.close()
