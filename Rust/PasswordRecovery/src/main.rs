use std::path::Path;
use std::{env, process};
use std::collections::HashSet;
use std::io::{BufRead, BufReader};
use std::fs::{File, read_to_string};

use md5;
use md4::Md4;
use tiger::Tiger;
use whirlpool::Whirlpool;
use streebog::{Streebog256, Streebog512};
use sha2::{Sha224, Sha256, Sha384, Sha512, Digest};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};


fn main() {
    let algo_list = vec![
        "md4", "md5", "sha224", "sha256", "sha384", "sha512",
        "sha3_224", "sha3_256", "sha3_384", "sha3_512",
        "tiger", "whirlpool", "streebog256", "streebog512"
    ];

    let args = process_args(&algo_list);
    let algo = &args[1];
    let file_path = &args[2];
    let wordlist_path = &args[3];

    let hashes: HashSet<String> = read_to_string(file_path)
                                .unwrap()
                                .lines()
                                .map(String::from)
                                .collect();

    recover_password(algo, hashes, wordlist_path);
}

fn process_args(algo_list: &Vec<&str>) -> Vec<String> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 4 {
        println!("Usage:\n");
        println!("cargo run <algo> <file_path> <wordlist_path>");
        println!("./PasswordRecovery <algo> <file_path> <wordlist_path>");
        process::exit(1);
    }

    if !algo_list.contains(&args[1].as_str()) {
        eprintln!("Algorithm `{}` not supported.", &args[1]);
        process::exit(1);
    }

    for path in &args[2..=3] {
        validate_file(path);
    }
    
    return args
}

fn validate_file(path: &str) {
    if !Path::new(path).exists() {
        eprintln!("File not found: {}", path);
        process::exit(1);
    }

    if let Err(e) = File::open(path) {
        eprintln!("Error opening file: {} -- {}", path, e);
        process::exit(1);
    }
}

fn recover_password(algo: &str, mut hashes: HashSet<String>, wordlist_path: &str) {
    
    let wordlist = File::open(wordlist_path).unwrap();
    let reader = BufReader::new(wordlist);
    let mut attempts = 0;

    for line in reader.lines().flatten() {
        let line = line.trim();
        let password_hash = match algo {
            "md4" => format!("{:x}", Md4::digest(line.as_bytes())),
            "md5" => format!("{:x}", md5::compute(line.as_bytes())),
            "sha224" => format!("{:x}", Sha224::digest(line.as_bytes())),
            "sha256" => format!("{:x}", Sha256::digest(line.as_bytes())),
            "sha384" => format!("{:x}", Sha384::digest(line.as_bytes())),
            "sha512" => format!("{:x}", Sha512::digest(line.as_bytes())),
            "sha3_224" => format!("{:x}", Sha3_224::digest(line.as_bytes())),
            "sha3_256" => format!("{:x}", Sha3_256::digest(line.as_bytes())),
            "sha3_384" => format!("{:x}", Sha3_384::digest(line.as_bytes())),
            "sha3_512" => format!("{:x}", Sha3_512::digest(line.as_bytes())),
            "tiger" => format!("{:x}", Tiger::digest(line.as_bytes())),
            "whirlpool" => format!("{:x}", Whirlpool::digest(line.as_bytes())),
            "streebog256" => format!("{:x}", Streebog256::digest(line.as_bytes())),
            "streebog512" => format!("{:x}", Streebog512::digest(line.as_bytes())),
            _ => unreachable!(),
        };

        if hashes.remove(&password_hash) {
            println!("cracked::{} --- {} ",  password_hash, line);
        }

        attempts += 1;
        if hashes.is_empty() {
            break;
        }
    }

    for unrecovered in hashes.drain() {
        println!("{} --- Failed after {} attempts", unrecovered, attempts);
    }
}