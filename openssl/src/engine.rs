use std::ffi::{CString, CStr};

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
        unsafe {
            ffi::init();

            let id = CString::new(engine_id).unwrap();
            cvt_p(ffi::ENGINE_by_id(id.as_ptr())).map(Engine)
        }
    }

    pub fn get_id(&self) -> String {
        unsafe {
            let id = ffi::ENGINE_get_id(self.0);
            CStr::from_ptr(id).to_string_lossy().to_string()
        }
    }

    pub fn free(&self) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::ENGINE_free(self.0)).map(|_| ())
        }
    }

}

#[cfg(test)]
mod tests {
    use super::Engine;

    #[test]
    fn test_engine_by_id() {
        let result = Engine::by_id("rdrand");
        assert!(result.is_ok());

        // let engine = result.unwrap();
        // let result2 = engine.free();
        // assert!(result2.is_ok());
    }
}
