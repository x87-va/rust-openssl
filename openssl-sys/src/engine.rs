use libc::*;

use *;

extern "C" {
	
	pub fn ENGINE_by_id(id: *const c_char) -> *mut ENGINE;

	// pub fn ENGINE_init(engine: *mut ENGINE) -> c_int;
	
	// pub fn ENGINE_finish(engine: *mut ENGINE) -> c_int;
	
	pub fn ENGINE_free(engine: *mut ENGINE) -> c_int;

	pub fn ENGINE_get_id(engine: *const ENGINE) -> *const c_char;
	
	// pub fn ENGINE_get_name(engine: *mut ENGINE) -> *const c_char;
 
	// pub fn ENGINE_set_default(engine: *mut ENGINE, flags: c_uint) -> c_int;

	// pub fn ENGINE_ctrl_cmd_string(engine: *mut ENGINE, cmd_name: *const c_char, arg: *const c_char, cmd_optional: c_uint) -> c_int;

	// pub fn ENGINE_load_private_key(engine: *mut ENGINE, key_id: *const c_char, ui_method: *mut UI_METHOD, callback_data: *mut c_void) -> *mut EVP_PKEY;

	// pub fn ENGINE_load_public_key(engine: *mut ENGINE, key_id: *const c_char, ui_method: *mut UI_METHOD, callback_data: *mut c_void) -> *mut EVP_PKEY;

}
