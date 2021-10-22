use std::ffi::{CStr, CString};
use std::fmt;
use std::ptr;

use libc::{c_int, c_uint};

use ffi;
use foreign_types::ForeignType;

use crate::{cvt, cvt_p};

use crate::pkey::{PKey, Private, Public};

use crate::error::ErrorStack;

pub struct Engine(*mut ffi::ENGINE);

impl Engine {

    pub fn from_ptr(ptr: *mut ffi::ENGINE) -> Engine {
        Engine(ptr)
    }

    pub fn as_ptr(&self) -> *mut ffi::ENGINE {
        self.0
    }

    pub fn by_id(engine_id: &str) -> Result<Engine, ErrorStack> {
        let id = CString::new(engine_id).unwrap();

        unsafe { cvt_p(ffi::ENGINE_by_id(id.as_ptr())).map(Engine) }
    }

    pub fn get_id(&self) -> String {
        unsafe {
            let id = ffi::ENGINE_get_id(self.0);
            CStr::from_ptr(id).to_string_lossy().to_string()
        }
    }

    pub fn get_name(&self) -> String {
        unsafe {
            let name = ffi::ENGINE_get_name(self.0);
            CStr::from_ptr(name).to_string_lossy().to_string()
        }
    }

    pub fn set_default(&self, flags: EngineMethod) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::ENGINE_set_default(self.0, flags.0)).map(|_| ()) }
    }

    pub fn init(&self) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::ENGINE_init(self.0)).map(|_| ()) }
    }

    pub fn ctrl_cmd_string(
        &self,
        command: &str,
        arg: Option<&str>,
        cmd_optional: i32,
    ) -> Result<(), ErrorStack> {
        let cmd_name = CString::new(command).unwrap();

        let arg = arg.map(|value| CString::new(value).unwrap());
        let arg_ptr = arg.map_or(ptr::null(), |value| value.as_ptr());

        unsafe {
            cvt(ffi::ENGINE_ctrl_cmd_string(
                    self.0,
                    cmd_name.as_ptr(),
                    arg_ptr,
                    cmd_optional as c_int,
                ))
                .map(|_| ())
        }
    }

    pub fn load_private_key(&self, id: &str) -> Result<PKey<Private>, ErrorStack> {
        let key_id = CString::new(id).unwrap();

        let ui_method = ptr::null_mut();
        let callback_data = ptr::null_mut();

        unsafe {
            cvt_p(ffi::ENGINE_load_private_key(
                self.0,
                key_id.as_ptr(),
                ui_method,
                callback_data,
            ))
            .map(|p| PKey::from_ptr(p))
        }
    }

    pub fn load_public_key(&self, id: &str) -> Result<PKey<Public>, ErrorStack> {
        let key_id = CString::new(id).unwrap();

        let ui_method = ptr::null_mut();
        let callback_data = ptr::null_mut();

        unsafe {
            cvt_p(ffi::ENGINE_load_public_key(
                self.0,
                key_id.as_ptr(),
                ui_method,
                callback_data,
            ))
            .map(|p| PKey::from_ptr(p))
        }
    }

    pub fn finish(&self) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::ENGINE_finish(self.0)).map(|_| ()) }
    }

    pub fn free(&self) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::ENGINE_free(self.0)).map(|_| ()) }
    }
}

impl fmt::Debug for Engine {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(fmt, "Engine{{id: {}}}", self.get_id())
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.finish().unwrap();
        self.free().unwrap();
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct EngineMethod(c_uint);

impl EngineMethod {
    pub const NONE: EngineMethod = EngineMethod(ffi::ENGINE_METHOD_NONE);

    pub const RSA: EngineMethod = EngineMethod(ffi::ENGINE_METHOD_RSA);

    pub const DSA: EngineMethod = EngineMethod(ffi::ENGINE_METHOD_DSA);

    pub const DH: EngineMethod = EngineMethod(ffi::ENGINE_METHOD_DH);

    pub const RAND: EngineMethod = EngineMethod(ffi::ENGINE_METHOD_RAND);

    pub const CIPHERS: EngineMethod = EngineMethod(ffi::ENGINE_METHOD_CIPHERS);

    pub const DIGESTS: EngineMethod = EngineMethod(ffi::ENGINE_METHOD_DIGESTS);

    pub const PKEY_METHS: EngineMethod = EngineMethod(ffi::ENGINE_METHOD_PKEY_METHS);

    pub const PKEY_ASN1_METHS: EngineMethod = EngineMethod(ffi::ENGINE_METHOD_PKEY_ASN1_METHS);

    pub const PKEY_ASN1_EC: EngineMethod = EngineMethod(ffi::ENGINE_METHOD_EC);

    pub const ALL: EngineMethod = EngineMethod(ffi::ENGINE_METHOD_ALL);
}

#[cfg(test)]
mod tests {
    use super::{Engine, EngineMethod};

    #[test]
    fn test_engine_by_id() {
        ffi::init();

        const ENGINE_ID: &str = "rdrand";

        let engine_result = Engine::by_id(ENGINE_ID);
        assert!(engine_result.is_ok());

        let engine = engine_result.unwrap();
        assert_eq!(engine.get_id(), ENGINE_ID);

        println!("Engine name: {:?}", engine.get_name());

        let mut result = engine.init();
        assert!(result.is_ok());

        result = engine.set_default(EngineMethod::ALL);
        assert!(result.is_ok());
    }
}
