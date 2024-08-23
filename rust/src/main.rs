use chrono::Utc;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Cursor, Seek, SeekFrom};

use clap::{Arg, Command};

use iblfile::encryptors::{aes256, noencryption};
use iblfile::{
    autoencrypted::{quick_block_parser, AutoEncryptor},
    meta_format::Format,
    meta_format::Meta,
    version::PROTOCOL,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    //iblfile::autoencrypted::register_auto_encryptor(noencryption::NoEncryptionSource::new());
    //iblfile::register_auto_encryptor(aes256::AES256Source::new());

    iblfile::meta_format::register_format(
        "testcli",
        vec![Format {
            format: "test".to_string(),
            version: "1".to_string(),
            get_extended:
                |_section: &HashMap<String, Cursor<Vec<u8>>>,
                 _meta: &Meta|
                 -> Result<HashMap<String, serde_json::Value>, iblfile::Error> {
                    Ok(HashMap::new())
                },
        }],
    );

    let matches = Command::new("testcli")
        .subcommand(
            Command::new("new")
                .arg(Arg::new("filename").required(true))
                .arg(Arg::new("mode").required(true))
                .arg(Arg::new("args").required(true))
                .arg(Arg::new("password").required(false)),
        )
        .subcommand(
            Command::new("open")
                .arg(Arg::new("filename").required(true))
                .arg(Arg::new("password").required(false)),
        )
        .subcommand(Command::new("deduce").arg(Arg::new("filename").required(true)))
        .get_matches();

    if matches.subcommand().is_none() {
        println!("Invalid subcommand. Use 'new', 'open', or 'deduce'.");
        return Ok(());
    }

    let matches = matches.subcommand().unwrap();

    match matches {
        ("new", new_matches) => {
            let filename = new_matches.get_one::<String>("filename").unwrap();
            let mode = new_matches.get_one::<String>("mode").unwrap();
            let password = new_matches
                .get_one::<String>("password")
                .map(|s| s.to_string())
                .unwrap_or("".to_string());

            println!("filename: {}", filename);
            println!("password: {}", password);

            let ae_source: Box<dyn AutoEncryptor> = if password.is_empty() {
                Box::new(noencryption::NoEncryptionSource)
            } else if password.ends_with(".pem") {
                unimplemented!();
                //let f = std::fs::read(password)?;
                //Box::new(pem::PemEncryptedSource::new(f, None))
            } else {
                Box::new(aes256::AES256Source::new(password.trim().to_string()).unwrap())
            };

            let mut arg_map = HashMap::new();
            if let Some(args) = new_matches.get_many::<String>("args") {
                for arg in args {
                    let parts: Vec<&str> = arg.splitn(2, '=').collect();
                    if parts.len() == 2 {
                        arg_map.insert(parts[0].to_string(), parts[1].to_string());
                    } else {
                        eprintln!("Invalid argument: {}", arg);
                    }
                }
            }

            if mode == "fullfile" {
                let mut f = iblfile::autoencrypted::AutoEncryptedFileFullFile::new(ae_source);

                for (k, v) in arg_map.into_iter() {
                    f.write_section(v.into_bytes(), &k).unwrap();
                }

                let metadata = Meta {
                    created_at: Utc::now(),
                    protocol: PROTOCOL.to_string(),
                    r#type: "testcli.test".to_string(),
                    extra_metadata: None,
                    format_version: Some("1".to_string()),
                };

                f.write_json_section(&metadata, "meta").unwrap();

                let mut new_file = File::create(filename)?;
                f.write_output(&mut new_file).unwrap();
            } else {
                let mut f = iblfile::autoencrypted::AutoEncryptedFilePerSection::new(ae_source);

                for (k, v) in arg_map {
                    f.write_section(v.as_bytes(), &k).unwrap();
                }

                let metadata = Meta {
                    created_at: Utc::now(),
                    protocol: PROTOCOL.to_string(),
                    r#type: "testcli.test".to_string(),
                    extra_metadata: None,
                    format_version: Some("1".to_string()),
                };

                f.write_json_section(&metadata, "meta").unwrap();

                let mut new_file = File::create(filename)?;
                f.write_output(&mut new_file).unwrap();
            }
        }
        ("open", open_matches) => {
            let filename = open_matches.get_one::<String>("filename").unwrap();
            let password = open_matches
                .get_one::<String>("password")
                .map(|s| s.to_string())
                .unwrap_or("".to_string());

            println!("filename: {}", filename);
            println!("password: {}", password);

            let ae_source: Box<dyn AutoEncryptor> = if password.is_empty() {
                Box::new(noencryption::NoEncryptionSource)
            } else if password.ends_with(".pem") {
                unimplemented!();
                //let f = std::fs::read(password)?;
                //Box::new(pem::PemEncryptedSource::new(None, Some(f)))
            } else {
                Box::new(aes256::AES256Source::new(password.to_string()).unwrap())
            };

            let mut r = File::open(filename)?;

            let block = quick_block_parser(&mut r).unwrap();

            if block.encryptor != ae_source.id().as_bytes() {
                return Err(format!(
                    "Invalid encryptor, need {} got {}",
                    ae_source.id(),
                    String::from_utf8_lossy(&block.encryptor)
                )
                .into());
            }

            r.seek(SeekFrom::Start(0))?;

            let mut f =
                iblfile::autoencrypted::AutoEncryptedFileFullFile::open(&mut r, ae_source).unwrap();

            let sections = f.sections().unwrap();

            let section_keys = sections.keys().map(|k| k.to_string()).collect::<Vec<_>>();
            for key in section_keys.into_iter() {
                let data = f.get(&key).unwrap();
                println!("section: {}", key);
                println!("data: {}", String::from_utf8_lossy(data));
            }
        }
        ("deduce", _deduce_matches) => {
            unimplemented!();
            /*let filename = deduce_matches.value_of("filename").unwrap();

            println!("filename: {}", filename);

            let mut r = File::open(filename)?;

            let deduced = iblfile::deduce_type(&mut r, false)?;

            println!("deduced type: {}", deduced.type_);
            println!("deduced sections: {:?}", deduced.sections.keys().collect::<Vec<_>>());
            println!("deduced errors: {:?}", deduced.parse_errors);*/
        }
        _ => {
            println!("Invalid subcommand. Use 'new', 'open', or 'deduce'.");
        }
    }

    Ok(())
}
