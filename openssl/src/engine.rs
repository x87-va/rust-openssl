use std::ffi::{CString, CStr};

use libc::{c_uint, c_int};

use ffi;

use {cvt_p, cvt};

use error::ErrorStack;

pub struct Engine(*mut ffi::ENGINE);

// impl Debug for Engine {

//     fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {

//     }
// }

impl Engine {

    pub fn by_id(engine_id: &str) -> Result<Engine, ErrorStack> {
        let id = CString::new(engine_id).unwrap();
        
        unsafe {
            ffi::init();

            cvt_p(ffi::ENGINE_by_id(id.as_ptr())).map(Engine)
        }
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

    pub fn set_default(&mut self, flags: EngineMethod) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::ENGINE_set_default(self.0, flags.0)).map(|_| ())
        }        
    }

    pub fn init(&mut self) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::ENGINE_init(self.0)).map(|_| ())
        }
    }

    pub fn ctrl_cmd_string(&mut self, command: &str, arg: &str, cmd_optional: i32) -> Result<(), ErrorStack> {
        let cmd_name = CString::new(command).unwrap();
        let cmd_arg = CString::new(arg).unwrap();

        unsafe {
            cvt(ffi::ENGINE_ctrl_cmd_string(self.0, cmd_name.as_ptr(), cmd_arg.as_ptr(), cmd_optional as c_int)).map(|_| ())
        }
    }   

    pub fn finish(&mut self) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::ENGINE_finish(self.0)).map(|_| ())
        }
    }

    pub fn free(&mut self) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::ENGINE_free(self.0)).map(|_| ())
        }
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
        const ENGINE_ID: &str = "rdrand";

        let result = Engine::by_id(ENGINE_ID);
        assert!(result.is_ok());

        let mut engine = result.unwrap();

        assert_eq!(engine.get_id(), ENGINE_ID);

        println!("Engine name: {:?}", engine.get_name());

        let mut result2 = engine.init();
        assert!(result2.is_ok());

        result2 = engine.set_default(EngineMethod::ALL);
        assert!(result2.is_ok());

        result2 = engine.finish();
        assert!(result2.is_ok());

        result2 = engine.free();
        assert!(result2.is_ok());
    }
}
