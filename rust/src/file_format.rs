use crate::meta_format::{get_format, Meta};
use crate::version::PROTOCOL;
use serde_json;
use std::collections::HashMap;
use std::io::{Read, Write};
use tar::{Archive, Builder, Header};

pub struct SourceParsed {
    pub data: HashMap<String, serde_json::Value>,
    pub table: String,
}

pub struct RawFile {
    pub sections: HashMap<String, Vec<u8>>,
    pub size: usize,
}

impl RawFile {
    pub fn new() -> Self {
        RawFile {
            sections: HashMap::new(),
            size: 0,
        }
    }

    pub fn from_sections(sections: HashMap<String, Vec<u8>>) -> Self {
        let size = sections.iter().fold(0, |acc, (_, v)| acc + v.len());
        RawFile { sections, size }
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn write_section(&mut self, buf: Vec<u8>, name: &str) -> Result<(), crate::Error> {
        self.size += buf.len(); // Update size
        self.sections.insert(name.to_string(), buf);
        Ok(())
    }

    pub fn write_output<W: Write>(&self, w: &mut W) -> Result<(), crate::Error> {
        let mut builder = Builder::new(w);

        for (name, buf) in self.sections.iter() {
            let mut header = Header::new_gnu();
            header.set_size(buf.len() as u64);
            header.set_path(name)?;
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, buf.as_slice())?;
        }

        builder.finish()?;
        Ok(())
    }
}

impl Default for RawFile {
    fn default() -> Self {
        Self::new()
    }
}

pub fn read_tar_file<R: Read>(tar_buf: R) -> Result<HashMap<String, Vec<u8>>, crate::Error> {
    let mut archive = Archive::new(tar_buf);
    let mut files = HashMap::new();

    for entry in archive.entries()? {
        let mut entry = entry?;
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf)?;
        files.insert(entry.path()?.to_string_lossy().into_owned(), buf);
    }

    Ok(files)
}

pub fn load_metadata(files: &HashMap<String, Vec<u8>>) -> Result<Meta, crate::Error> {
    if let Some(meta) = files.get("meta") {
        let metadata: Meta = serde_json::from_slice(meta)?;
        Ok(metadata)
    } else {
        Err("no metadata present".into())
    }
}

pub fn parse_metadata(files: &HashMap<String, Vec<u8>>) -> Result<Meta, crate::Error> {
    let meta = load_metadata(files)?;

    if meta.protocol != PROTOCOL {
        return Err(format!("invalid protocol: {}", meta.protocol).into());
    }

    let format = get_format(&meta.r#type)?;

    if meta.format_version.as_deref() != Some(format.version.as_str()) {
        return Err(format!(
            "this {} uses format version {:?}, but this iblfile version only supports version {}",
            meta.r#type, meta.format_version, format.version
        )
        .into());
    }

    Ok(meta)
}

pub fn map_keys<T>(m: &HashMap<String, T>) -> Vec<String> {
    m.keys().cloned().collect()
}
