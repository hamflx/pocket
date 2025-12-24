use std::path::PathBuf;

use tracing::info;

fn credentials_dir() -> PathBuf {
    if let Some(dirs) = directories::ProjectDirs::from("dev", "hamflx", "pocket") {
        return dirs.config_dir().join("credentials");
    }

    PathBuf::from("credentials")
}

fn credentials_file_path(name: &str) -> PathBuf {
    credentials_dir().join(format!("{name}.bin"))
}

#[cfg(windows)]
fn protect_data(data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use std::ptr;
    use windows::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData,
    };
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{HLOCAL, LocalFree};

    unsafe {
        let mut in_blob = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut out_blob = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };

        CryptProtectData(
            &mut in_blob,
            PCWSTR::null(),
            Some(ptr::null()),
            Some(ptr::null_mut()),
            Some(ptr::null_mut()),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )?;

        let slice = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize);
        let result = slice.to_vec();

        let _ = LocalFree(Some(HLOCAL(out_blob.pbData as *mut _)));

        Ok(result)
    }
}

#[cfg(windows)]
fn unprotect_data(data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use std::ptr;
    use windows::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptUnprotectData,
    };
    use windows::core::PWSTR;
    use windows::Win32::Foundation::{HLOCAL, LocalFree};

    unsafe {
        let mut in_blob = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut out_blob = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };
        let mut descr: PWSTR = PWSTR::null();

        CryptUnprotectData(
            &mut in_blob,
            Some(&mut descr),
            Some(ptr::null()),
            Some(ptr::null_mut()),
            Some(ptr::null_mut()),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )?;

        if !descr.is_null() {
            let _ = LocalFree(Some(HLOCAL(descr.0 as _)));
        }

        let slice = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize);
        let result = slice.to_vec();

        let _ = LocalFree(Some(HLOCAL(out_blob.pbData as *mut _)));

        Ok(result)
    }
}

#[cfg(windows)]
pub fn store_encrypted_credentials(
    name: &str,
    access_key_id: &str,
    secret_access_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::fs;

    let plaintext = format!("{access_key_id}\n{secret_access_key}");
    let encrypted = protect_data(plaintext.as_bytes())?;

    let dir = credentials_dir();
    fs::create_dir_all(&dir)?;

    let path = credentials_file_path(name);
    fs::write(&path, encrypted)?;

    info!("Stored encrypted S3 credentials at {}", path.display());
    Ok(())
}

#[cfg(windows)]
pub fn load_encrypted_credentials(
    name: &str,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    use std::fs;

    let path = credentials_file_path(name);
    let encrypted = fs::read(&path)?;
    let decrypted = unprotect_data(&encrypted)?;
    let text = String::from_utf8(decrypted)?;

    let mut parts = text.splitn(2, '\n');
    let access_key_id = parts
        .next()
        .ok_or("missing access_key_id in decrypted credentials")?;
    let secret_access_key = parts
        .next()
        .ok_or("missing secret_access_key in decrypted credentials")?;

    Ok((access_key_id.to_string(), secret_access_key.to_string()))
}

#[cfg(not(windows))]
pub fn store_encrypted_credentials(
    _name: &str,
    _access_key_id: &str,
    _secret_access_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    Err("Encrypted credentials are only supported on Windows".into())
}

#[cfg(not(windows))]
pub fn load_encrypted_credentials(
    _name: &str,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    Err("Encrypted credentials are only supported on Windows".into())
}

