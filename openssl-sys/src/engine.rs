use libc::*;

use *;

pub const ENGINE_METHOD_NONE: c_uint 			= 0x0000;
pub const ENGINE_METHOD_RSA: c_uint             = 0x0001;
pub const ENGINE_METHOD_DSA: c_uint             = 0x0002;
pub const ENGINE_METHOD_DH: c_uint              = 0x0004;
pub const ENGINE_METHOD_RAND: c_uint            = 0x0008;
pub const ENGINE_METHOD_CIPHERS: c_uint         = 0x0040;
pub const ENGINE_METHOD_DIGESTS: c_uint         = 0x0080;
pub const ENGINE_METHOD_PKEY_METHS: c_uint      = 0x0200;
pub const ENGINE_METHOD_PKEY_ASN1_METHS: c_uint = 0x0400;
pub const ENGINE_METHOD_EC: c_uint              = 0x0800;
pub const ENGINE_METHOD_ALL: c_uint 			= 0xFFFF;

extern "C" {
	
	pub fn ENGINE_by_id(id: *const c_char) -> *mut ENGINE;

	pub fn ENGINE_init(engine: *mut ENGINE) -> c_int;
	
	pub fn ENGINE_finish(engine: *mut ENGINE) -> c_int;
	
	pub fn ENGINE_free(engine: *mut ENGINE) -> c_int;

	pub fn ENGINE_get_id(engine: *const ENGINE) -> *const c_char;
	
	pub fn ENGINE_get_name(engine: *const ENGINE) -> *const c_char;
 
	pub fn ENGINE_set_default(engine: *mut ENGINE, flags: c_uint) -> c_int;

	pub fn ENGINE_ctrl_cmd_string(engine: *mut ENGINE, cmd_name: *const c_char, arg: *const c_char, cmd_optional: c_int) -> c_int;

	// pub fn ENGINE_load_private_key(engine: *mut ENGINE, key_id: *const c_char, ui_method: *mut UI_METHOD, callback_data: *mut c_void) -> *mut EVP_PKEY;

	// pub fn ENGINE_load_public_key(engine: *mut ENGINE, key_id: *const c_char, ui_method: *mut UI_METHOD, callback_data: *mut c_void) -> *mut EVP_PKEY;

}
