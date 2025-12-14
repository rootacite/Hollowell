use anyhow::Result;
use anyhow::anyhow;
use std::io::ErrorKind;
use std::process::Command;
use std::{env, fs, io, path};

fn get_filename_without_extension<P: AsRef<path::Path>>(path: P) -> Result<String> {
    let path = path.as_ref();

    if !path.exists() {
        return Err(anyhow!("File does not exist: {:?}", path));
    }

    if !path.is_file() {
        return Err(anyhow!("Path is not a file: {:?}", path));
    }

    path.file_stem()
        .and_then(|stem| stem.to_str())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("Unable to extract filename from path: {:?}", path))
}

fn get_filepath<P: AsRef<path::Path>>(path: P) -> Result<String> {
    let p = path.as_ref();

    if !p.exists() {
        return Err(anyhow!(
            "Path '{}' does not exist or is inaccessible.",
            p.display()
        ));
    }

    match p.parent() {
        Some(parent_path) => match parent_path.to_str() {
            Some(s) => Ok(s.to_string()),
            None => Err(anyhow!(
                "Parent path '{}' contains invalid non-UTF-8 characters.",
                parent_path.display()
            )),
        },
        None => Err(anyhow!(
            "Path '{}' cannot retrieve parent directory.",
            p.display()
        )),
    }
}

fn compile_target(name: &str) -> Result<(), io::Error> {
    let input_file = format!("{}.c", name);
    let output_file = format!("{}.o", name);

    let output = Command::new("clang")
        .arg("-c")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .output();

    match output {
        Ok(output) => {
            if output.status.success() {
                // Command succeeded
                Ok(())
            } else {
                // Command executed but returned non-zero exit code (e.g., compile error)
                eprintln!("Clang compilation failed for {}.", name);
                eprintln!("Exit Code: {:?}", output.status.code());
                eprintln!("Stderr:\n{}", String::from_utf8_lossy(&output.stderr));
                Err(io::Error::new(
                    ErrorKind::Other,
                    format!(
                        "Clang compilation failed for {} with exit code: {:?}",
                        name,
                        output.status.code()
                    ),
                ))
            }
        }
        Err(e) => {
            // IO Error (e.g., clang not found)
            if e.kind() == ErrorKind::NotFound {
                eprintln!(
                    "Error: 'clang' executable not found. Ensure it is installed and in $PATH."
                );
            } else {
                eprintln!("IO error while executing command: {:?}", e);
            }
            Err(e)
        }
    }
}

pub fn parse_hex_to_u64(hex_str: &str) -> Result<u64, std::num::ParseIntError> {
    let processed_str = if hex_str.starts_with("0x") || hex_str.starts_with("0X") {
        &hex_str[2..]
    } else {
        hex_str
    };

    u64::from_str_radix(processed_str, 16)
}

fn main() -> Result<()> {
    let mut arg = env::args().into_iter().collect::<Vec<String>>();
    if arg.len() < 2 {
        return Err(anyhow!("No operation object."));
    }

    arg.remove(0);

    let first_input = &arg[0];
    let name = get_filename_without_extension(first_input)?;
    let output_path = format!("{}/{}.c", get_filepath(first_input)?, name);
    let mut c_code: String = "".to_string();

    c_code.push_str(
        r#"
struct ChunkInfo {
    unsigned char *data;
    unsigned long size;
    char* name;
    unsigned long vdata;
};"#,
    );

    let mut iter_fun = r#"
typedef struct ChunkInfo ChunkInfo_t;
typedef int(*chunk_callback)(const ChunkInfo_t*, void*);

int iter_chunks(chunk_callback cb, void* data)
{
    ChunkInfo_t chunks[] = {
"#
    .to_string();

    c_code.push_str("\n\n");

    for f in &arg {
        let symbol_name = get_filename_without_extension(&f)?;
        let bin_data = fs::read(f)?;

        c_code.push_str(&format!("static const unsigned char _{}[] = {}", symbol_name, "{"));

        for b in bin_data.iter() {
            c_code.push_str(&format!("{:#0x}, ", b));
        }

        c_code.push_str("}; \n");
        c_code.push_str(&format!(
            "static const unsigned long _{}_size = {:#0x}; \n",
            symbol_name,
            bin_data.len()
        ));

        c_code.push_str(&format!(
            "static const char* _{}_name = \"{}\"; \n",
            symbol_name, symbol_name
        ));
        c_code.push_str(&format!(
            "static const unsigned long _{}_vdata = {:#0x}; \n",
            symbol_name,
            parse_hex_to_u64(&symbol_name).unwrap_or_else(|_| 0)
        ));

        iter_fun.push_str(&format!(
            "{} .data = (unsigned char*)&_{}, .size = {:#0x}, .name = (char*)_{}_name, .vdata = {:#0x} {}",
            "        {",
            symbol_name,
            bin_data.len(),
            symbol_name,
            parse_hex_to_u64(&symbol_name).unwrap_or_else(|_| 0),
            "}, \n"
        ));
    }

    iter_fun.push_str(
        &r#"
    };
    int chunks_count = #$PLACEHOLDER$#;

    for (int i = 0; i < chunks_count; i += 1) {
        int r = cb(&chunks[i], data);
        if (r == 0) return 1;
    }

    return 0;
}
    "#
        .replace("#$PLACEHOLDER$#", &format!("{}", arg.len())),
    );
    c_code.push_str(&iter_fun);
    
    

    fs::write(&output_path, c_code.as_bytes())?;

    compile_target(&name)?;
    fs::remove_file(&output_path)?;

    Ok(())
}
