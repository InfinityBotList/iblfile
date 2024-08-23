use crate::file_format::{read_tar_file, RawFile};
use serde_json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};

const AUTO_ENCRYPTED_FILE_MAGIC: &[u8] = b"iblaef";
const AUTO_ENCRYPTED_FILE_CHECKSUM_SIZE: usize = 32; // sha256
const AUTO_ENCRYPTED_FILE_ID_SIZE: usize = 16;

fn auto_encrypted_metadata_size() -> usize {
    AUTO_ENCRYPTED_FILE_MAGIC.len()
        + AUTO_ENCRYPTED_FILE_CHECKSUM_SIZE
        + AUTO_ENCRYPTED_FILE_ID_SIZE
}

pub trait AutoEncryptor {
    fn id(&self) -> String;
    fn encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>, crate::Error>;
    fn decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>, crate::Error>;
}

pub struct AutoEncryptorRegistry {
    registry: HashMap<String, Box<dyn AutoEncryptor>>,
}

impl AutoEncryptorRegistry {
    pub fn new() -> Self {
        Self {
            registry: HashMap::new(),
        }
    }

    pub fn register(&mut self, src: Box<dyn AutoEncryptor>) {
        let id = src.id();
        if id.len() != AUTO_ENCRYPTED_FILE_ID_SIZE {
            panic!("invalid id size for {}: {}", id, id.len());
        }
        self.registry.insert(id, src);
    }
}

impl Default for AutoEncryptorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

pub struct AutoEncryptedFileBlock {
    pub magic: Vec<u8>,
    pub checksum: Vec<u8>,
    pub encryptor: Vec<u8>,
    pub data: Vec<u8>,
}

impl AutoEncryptedFileBlock {
    pub fn validate(&self) -> Result<(), crate::Error> {
        if self.magic != AUTO_ENCRYPTED_FILE_MAGIC {
            return Err(format!("invalid magic: {:?}", self.magic).into());
        }

        let mut hasher = Sha256::new();
        hasher.update(&self.data);
        let checksum = hasher.finalize();

        if checksum.to_vec() != self.checksum {
            return Err(format!("invalid checksum: {:?}", self.checksum).into());
        }

        Ok(())
    }

    pub fn decrypt(&self, src: &mut dyn AutoEncryptor) -> Result<Vec<u8>, crate::Error> {
        if src.id() != String::from_utf8_lossy(&self.encryptor) {
            return Err(format!("invalid encryptor: {:?}", self.encryptor).into());
        }

        src.decrypt(&self.data)
    }

    /// Writes a block to a writer with checksum and magic
    pub fn write(&self, w: &mut dyn Write) -> Result<(), crate::Error> {
        w.write_all(&self.magic)?;
        w.write_all(&self.checksum)?;
        w.write_all(&self.encryptor)?;
        w.write_all(&self.data)?;
        Ok(())
    }
}

pub fn parse_auto_encrypted_file_block(
    block: &[u8],
) -> Result<AutoEncryptedFileBlock, crate::Error> {
    if block.len() < auto_encrypted_metadata_size() {
        return Err("block is too small".into());
    }

    let magic = block[0..AUTO_ENCRYPTED_FILE_MAGIC.len()].to_vec();
    let checksum = block[AUTO_ENCRYPTED_FILE_MAGIC.len()
        ..AUTO_ENCRYPTED_FILE_MAGIC.len() + AUTO_ENCRYPTED_FILE_CHECKSUM_SIZE]
        .to_vec();
    let encryptor = block[AUTO_ENCRYPTED_FILE_MAGIC.len() + AUTO_ENCRYPTED_FILE_CHECKSUM_SIZE
        ..AUTO_ENCRYPTED_FILE_MAGIC.len()
            + AUTO_ENCRYPTED_FILE_CHECKSUM_SIZE
            + AUTO_ENCRYPTED_FILE_ID_SIZE]
        .to_vec();
    let data = block[AUTO_ENCRYPTED_FILE_MAGIC.len()
        + AUTO_ENCRYPTED_FILE_CHECKSUM_SIZE
        + AUTO_ENCRYPTED_FILE_ID_SIZE..]
        .to_vec();

    Ok(AutoEncryptedFileBlock {
        magic,
        checksum,
        encryptor,
        data,
    })
}

pub fn new_auto_encrypted_file_block(
    data: &[u8],
    src: &mut dyn AutoEncryptor,
) -> Result<AutoEncryptedFileBlock, crate::Error> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let checksum = hasher.finalize();

    let enc_data = src.encrypt(data)?;

    Ok(AutoEncryptedFileBlock {
        magic: AUTO_ENCRYPTED_FILE_MAGIC.to_vec(),
        checksum: checksum.to_vec(),
        encryptor: src.id().into_bytes(),
        data: enc_data,
    })
}

pub struct AutoEncryptedFileFullFile {
    src: Box<dyn AutoEncryptor>,
    file: RawFile,
}

impl AutoEncryptedFileFullFile {
    pub fn new(src: Box<dyn AutoEncryptor>) -> Self {
        Self {
            src,
            file: RawFile {
                sections: HashMap::new(),
                size: 0,
            },
        }
    }

    pub fn open(r: &mut dyn Read, src: Box<dyn AutoEncryptor>) -> Result<Self, crate::Error> {
        let mut data = Vec::new();
        r.read_to_end(&mut data)?;

        let block = parse_auto_encrypted_file_block(&data)?;

        block.validate()?;

        let mut src = src;

        let decrypted_block = block.decrypt(&mut *src)?;

        let sections = read_tar_file(&*decrypted_block)?;

        Ok(Self {
            src,
            file: RawFile::from_sections(sections),
        })
    }

    pub fn sections(&self) -> Result<&HashMap<String, Vec<u8>>, crate::Error> {
        Ok(&self.file.sections)
    }

    pub fn get(&mut self, name: &str) -> Result<&Vec<u8>, crate::Error> {
        self.file
            .sections
            .get(name)
            .ok_or_else(|| format!("no section found for {}", name).into())
    }

    pub fn write_json_section<T: serde::Serialize>(
        &mut self,
        item: &T,
        name: &str,
    ) -> Result<(), crate::Error> {
        let buf = serde_json::to_vec(item)?;
        self.write_section(buf, name)
    }

    pub fn write_section(&mut self, buf: Vec<u8>, name: &str) -> Result<(), crate::Error> {
        self.file.write_section(buf, name)
    }

    pub fn write_output(&mut self, w: &mut dyn Write) -> Result<(), crate::Error> {
        let mut data_buf = Vec::new();
        self.file.write_output(&mut data_buf)?;

        let enc_data = self.src.encrypt(&data_buf)?;

        let mut hasher = Sha256::new();
        hasher.update(&enc_data);
        let checksum = hasher.finalize();

        let enc_block = AutoEncryptedFileBlock {
            magic: AUTO_ENCRYPTED_FILE_MAGIC.to_vec(),
            checksum: checksum.to_vec(),
            encryptor: self.src.id().into_bytes(),
            data: enc_data,
        };

        enc_block.write(w)
    }

    pub fn size(&self) -> usize {
        self.file.size()
    }
}

pub struct AutoEncryptedFilePerSection {
    file: RawFile,
    sections: HashMap<String, AutoEncryptedFileBlock>,
    src: Box<dyn AutoEncryptor>,
}

impl AutoEncryptedFilePerSection {
    pub fn new(src: Box<dyn AutoEncryptor>) -> Self {
        Self {
            file: RawFile {
                sections: HashMap::new(),
                size: 0,
            },
            sections: HashMap::new(),
            src,
        }
    }

    pub fn open(r: &mut dyn Read, src: Box<dyn AutoEncryptor>) -> Result<Self, crate::Error> {
        let mut data = Vec::new();
        r.read_to_end(&mut data)?;

        let sections = read_tar_file(&*data)?;

        let mut enc_sections = HashMap::new();

        for (k, v) in sections.iter() {
            let enc_section = parse_auto_encrypted_file_block(v)?;
            enc_sections.insert(k.to_string(), enc_section);
        }

        Ok(Self {
            file: RawFile::from_sections(sections),
            sections: enc_sections,
            src,
        })
    }

    pub fn raw_sections(&self) -> &HashMap<String, AutoEncryptedFileBlock> {
        &self.sections
    }

    pub fn get(&mut self, name: &str) -> Result<Vec<u8>, crate::Error> {
        let section = match self.sections.get(name) {
            Some(section) => section,
            None => return Err(format!("no section found for {}", name).into()),
        };
        section.validate()?;
        let decrypted = section.decrypt(&mut *self.src)?;
        Ok(decrypted)
    }

    pub fn write_json_section<T: serde::Serialize>(
        &mut self,
        item: &T,
        name: &str,
    ) -> Result<(), crate::Error> {
        let buf = serde_json::to_vec(item)?;
        self.write_section(&buf, name)
    }

    pub fn write_section(&mut self, buf: &[u8], name: &str) -> Result<(), crate::Error> {
        let enc_data = self.src.encrypt(buf)?;

        let mut hasher = Sha256::new();
        hasher.update(&enc_data);
        let checksum = hasher.finalize();

        let enc_block = AutoEncryptedFileBlock {
            magic: AUTO_ENCRYPTED_FILE_MAGIC.to_vec(),
            checksum: checksum.to_vec(),
            encryptor: self.src.id().into_bytes(),
            data: enc_data,
        };

        let mut enc_buf = Vec::new();
        enc_block.write(&mut enc_buf)?;

        self.sections.insert(name.to_string(), enc_block);
        self.file.write_section(enc_buf, name)?;
        Ok(())
    }

    pub fn write_output(&mut self, w: &mut dyn Write) -> Result<(), crate::Error> {
        let mut data_buf = Vec::new();
        self.file.write_output(&mut data_buf)?;

        w.write_all(&data_buf)?;

        Ok(())
    }
}

/*
// QuickBlockParser reads the first AutoEncryptedMetadataSize into a buffer and parses it
//
// Note that the block returned by this is *not* valid and is only meant for quick parsing of the encryptor
func QuickBlockParser(r io.ReadSeeker) (*AutoEncryptedFileBlock, error) {
    // Read the first AutoEncryptedMetadataSize into a buffer
    // This is the metadata section
    buf := make([]byte, AutoEncryptedMetadataSize())
    _, err := r.Read(buf)

    if err != nil {
        return nil, fmt.Errorf("error reading metadata: %w", err)
    }

    // This metadata will be 'corrupt', but we just need the encryptor
    meta, err := ParseAutoEncryptedFileBlock(buf)

    if err != nil {
        return nil, fmt.Errorf("error parsing metadata: %w", err)
    }

    // Seek back to start
    _, err = r.Seek(0, 0)

    if err != nil {
        return nil, fmt.Errorf("error seeking back to start of file: %w", err)
    }

    return meta, nil
}
 */

/// QuickBlockParser reads the first AutoEncryptedMetadataSize into a buffer and parses it
///
/// Note that the block returned by this is *not* valid and is only meant for quick parsing of the encryptor
pub fn quick_block_parser<T: Read + Seek>(
    r: &mut T,
) -> Result<AutoEncryptedFileBlock, crate::Error> {
    // Read the first AutoEncryptedMetadataSize into a buffer
    // This is the metadata section
    let mut buf = vec![0u8; auto_encrypted_metadata_size()];
    r.read_exact(&mut buf)?;

    // This metadata will be 'corrupt', but we just need the encryptor
    let meta = parse_auto_encrypted_file_block(&buf)?;

    // Seek back to start
    r.seek(SeekFrom::Start(0))?;

    Ok(meta)
}
