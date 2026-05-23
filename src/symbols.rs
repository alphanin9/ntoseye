use crate::{
    backend::MemoryOps,
    error::{Error, Result},
    guest::{ModuleInfo, WinObject},
    host::KvmHandle,
    memory,
    types::{Dtb, PhysAddr, VirtAddr},
};
use dashmap::DashMap;
use fst::{Automaton, IntoStreamer, Set, SetBuilder, Streamer, automaton::Str};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use memmap2::Mmap;
use pdb2::{FallibleIterator, PrimitiveKind, TypeData, TypeFinder, TypeIndex};
use pelite::{
    image::{
        GUID, IMAGE_DEBUG_CV_INFO_PDB70, IMAGE_DEBUG_DIRECTORY, IMAGE_DEBUG_TYPE_CODEVIEW,
        IMAGE_DIRECTORY_ENTRY_DEBUG,
    },
    pe64::{Pe, debug::CodeView},
};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use spin::Mutex;
use std::{
    collections::HashMap,
    fs::File,
    mem::size_of,
    path::{Path, PathBuf},
    ptr,
    sync::{Arc, OnceLock},
};
use std::{fmt, io::Cursor};

// NOTE global is probably fine here?
pub static FORCE_DOWNLOADS: OnceLock<bool> = OnceLock::new();

#[derive(Default, Clone)]
pub struct SymbolIndex {
    set: Set<Vec<u8>>,
}

pub struct SymbolStore {
    pdbs: DashMap<u128, Mutex<pdb2::PDB<'static, Cursor<&'static [u8]>>>>,

    mmaps: DashMap<u128, Arc<Mmap>>,
    index: DashMap<u128, SymbolIndex>,
    index_types: DashMap<u128, SymbolIndex>,

    modules: DashMap<(Dtb, u64), LoadedModule>,
    module_status: DashMap<(Dtb, u64), ModuleSymbolStatus>,
    module_source: DashMap<(Dtb, u64), ModuleSymbolSource>,
}

fn guid_to_u128(guid: GUID) -> u128 {
    let mut bytes = [0u8; 16];
    bytes[0..4].copy_from_slice(&guid.Data1.to_be_bytes());
    bytes[4..6].copy_from_slice(&guid.Data2.to_be_bytes());
    bytes[6..8].copy_from_slice(&guid.Data3.to_be_bytes());
    bytes[8..16].copy_from_slice(&guid.Data4);
    u128::from_be_bytes(bytes)
}

pub fn get_cache_root() -> Option<PathBuf> {
    let config_dir = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var("SUDO_USER")
                .ok()
                .map(|user| PathBuf::from(format!("/home/{}/.config", user)))
                .or_else(|| {
                    std::env::var_os("HOME").map(|home| {
                        let mut path = PathBuf::from(home);
                        path.push(".config");
                        path
                    })
                })
        })?;

    let cache_root = config_dir.join("ntoseye");
    std::fs::create_dir_all(&cache_root).ok()?;
    Some(cache_root)
}

fn get_symbols_directory() -> Option<PathBuf> {
    let symbols_path = get_cache_root()?.join("symbols");
    std::fs::create_dir_all(&symbols_path).ok()?;
    Some(symbols_path)
}

fn get_images_directory() -> Option<PathBuf> {
    let images_path = get_cache_root()?.join("images");
    std::fs::create_dir_all(&images_path).ok()?;
    Some(images_path)
}

/// Information needed to download a PDB file
#[derive(Debug, Clone)]
pub struct DownloadJob {
    pub url: String,
    pub path: PathBuf,
    pub filename: String,
}

#[derive(Debug, Clone)]
pub enum ModuleSymbolStatus {
    Loaded,
    MissingDebugInfo,
    Skipped,
    Failed(#[allow(dead_code)] String),
}

impl ModuleSymbolStatus {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Loaded => "loaded",
            Self::MissingDebugInfo => "no-pdb",
            Self::Skipped => "skipped",
            Self::Failed(_) => "failed",
        }
    }
}

#[derive(Debug, Clone)]
pub enum ModuleSymbolSource {
    Memory,
    Image,
    Local,
}

impl ModuleSymbolSource {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::Image => "image",
            Self::Local => "local",
        }
    }
}

#[derive(Debug, Clone)]
pub enum ModuleSymbolDiscovery {
    Ready {
        job: DownloadJob,
        guid: u128,
        source: ModuleSymbolSource,
    },
    NeedsImage {
        image_job: DownloadJob,
    },
}

#[derive(Debug, Clone)]
pub struct ModuleSymbolLoad {
    pub job: DownloadJob,
    pub guid: u128,
    pub source: ModuleSymbolSource,
    pub module: ModuleInfo,
    pub dtb: Dtb,
}

impl ModuleSymbolLoad {
    pub fn new(
        job: DownloadJob,
        guid: u128,
        source: ModuleSymbolSource,
        module: ModuleInfo,
        dtb: Dtb,
    ) -> Self {
        Self {
            job,
            guid,
            source,
            module,
            dtb,
        }
    }

    fn loaded_module(&self) -> LoadedModule {
        LoadedModule {
            name: self.module.name.clone(),
            guid: self.guid,
            base_address: self.module.base_address,
            size: self.module.size,
            dtb: self.dtb,
        }
    }
}

impl DownloadJob {
    pub fn needs_download(&self) -> bool {
        !self.path.exists() || *FORCE_DOWNLOADS.get_or_init(|| false)
    }
}

fn format_progress_name(name: &str) -> String {
    const WIDTH: usize = 32;
    format!("{name:<WIDTH$}")
}

const DOWNLOAD_PROGRESS_TEMPLATE: &str = "{msg} [{bar:40}] {bytes}/{total_bytes} ({eta})";
const TASK_PROGRESS_TEMPLATE: &str = "{msg} [{bar:40}] {pos}/{len}";

fn download_progress_style() -> Result<ProgressStyle> {
    Ok(ProgressStyle::with_template(DOWNLOAD_PROGRESS_TEMPLATE)?.progress_chars("#-"))
}

fn task_progress_style() -> ProgressStyle {
    ProgressStyle::with_template(TASK_PROGRESS_TEMPLATE)
        .unwrap()
        .progress_chars("#-")
}

fn download_job(job: &DownloadJob, pb: ProgressBar) -> Result<()> {
    if !job.needs_download() {
        return Ok(());
    }

    let response = reqwest::blocking::get(&job.url)?;
    let response = response.error_for_status()?;
    let total_size = response.content_length().unwrap_or(0);

    pb.set_style(download_progress_style()?);
    pb.set_length(total_size);
    pb.set_message(format_progress_name(&job.filename));

    if let Some(parent) = job.path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = File::create(&job.path)?;
    let mut downloaded = pb.wrap_read(response);

    std::io::copy(&mut downloaded, &mut file)?;
    pb.finish_and_clear();

    Ok(())
}

pub fn download_jobs_parallel(jobs: Vec<DownloadJob>) -> Vec<Result<PathBuf>> {
    let mp = Arc::new(MultiProgress::new());

    jobs.into_par_iter()
        .map(|job| {
            if !job.needs_download() {
                return Ok(job.path);
            }

            let mp = Arc::clone(&mp);
            download_job(&job, mp.add(ProgressBar::new(0))).map(|_| job.path)
        })
        .collect::<Vec<_>>()
}

#[derive(Debug, Clone)]
pub enum ParsedType {
    Primitive(String),
    Struct(String),
    Union(String),
    Enum(String),
    Pointer(Box<ParsedType>),
    Array(Box<ParsedType>, u32),
    Bitfield {
        underlying: Box<ParsedType>,
        pos: u8,
        len: u8,
    },
    Function(Box<ParsedType>, Vec<ParsedType>),
    Unknown,
}

impl fmt::Display for ParsedType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParsedType::Primitive(s)
            | ParsedType::Struct(s)
            | ParsedType::Union(s)
            | ParsedType::Enum(s) => write!(f, "{}", s),
            // ParsedType::Pointer(inner) => write!(f, "{}*", inner),
            ParsedType::Pointer(inner) => {
                if let ParsedType::Function(ret_type, args) = &**inner {
                    write!(f, "{} (*)(", ret_type)?;
                    for (i, arg) in args.iter().enumerate() {
                        if i > 0 {
                            write!(f, ", ")?;
                        }
                        write!(f, "{}", arg)?;
                    }
                    write!(f, ")")
                } else {
                    write!(f, "{}*", inner)
                }
            }
            ParsedType::Array(inner, count) => write!(f, "{}[{}]", inner, count),
            ParsedType::Bitfield {
                underlying,
                pos,
                len,
            } => write!(f, "{} : {} @ bit {}", underlying, len, pos),
            ParsedType::Function(ret_type, args) => {
                write!(f, "{} (", ret_type)?;
                for (i, arg) in args.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", arg)?;
                }
                write!(f, ")")
            }
            ParsedType::Unknown => write!(f, "<?>"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FieldInfo {
    pub offset: u32,
    #[allow(dead_code)]
    pub size: u64,
    pub type_data: ParsedType,
}

#[derive(Debug, Clone)]
pub struct TypeInfo {
    pub name: String,
    pub size: usize,
    pub fields: HashMap<String, FieldInfo>,
}

impl TypeInfo {
    pub fn try_get_field_offset<S>(&self, field_name: S) -> Result<u64>
    where
        S: Into<String> + AsRef<str>,
    {
        self.fields
            .get(field_name.as_ref())
            .ok_or(Error::FieldNotFound(field_name.into()))
            .map(|f| f.offset as u64)
    }
}

/// A loaded module with its symbols and address range.
/// Used to track modules across both kernel and user address spaces.
#[derive(Debug, Clone)]
pub struct LoadedModule {
    pub name: String,
    pub guid: u128,
    pub base_address: VirtAddr,
    pub size: u32,
    pub dtb: Dtb,
}

impl LoadedModule {
    fn end_address(&self) -> VirtAddr {
        VirtAddr(self.base_address.0.saturating_add(self.size as u64))
    }

    fn contains_address(&self, address: VirtAddr) -> bool {
        address.0 >= self.base_address.0 && address.0 < self.end_address().0
    }
}

impl SymbolStore {
    fn module_key(dtb: Dtb, base_address: VirtAddr) -> (Dtb, u64) {
        (dtb, base_address.0)
    }

    pub fn new() -> Self {
        Self {
            pdbs: DashMap::new(),
            mmaps: DashMap::new(),
            index: DashMap::new(),
            index_types: DashMap::new(),
            modules: DashMap::new(),
            module_status: DashMap::new(),
            module_source: DashMap::new(),
        }
    }

    pub fn set_module_symbol_status(
        &self,
        dtb: Dtb,
        base_address: VirtAddr,
        status: ModuleSymbolStatus,
    ) {
        let key = Self::module_key(dtb, base_address);
        if !matches!(status, ModuleSymbolStatus::Loaded) {
            self.module_source.remove(&key);
        }
        self.module_status.insert(key, status);
    }

    pub fn module_symbol_status(
        &self,
        dtb: Dtb,
        base_address: VirtAddr,
    ) -> Option<ModuleSymbolStatus> {
        self.module_status
            .get(&Self::module_key(dtb, base_address))
            .map(|status| status.clone())
    }

    pub fn set_module_symbol_source(
        &self,
        dtb: Dtb,
        base_address: VirtAddr,
        source: ModuleSymbolSource,
    ) {
        self.module_source
            .insert(Self::module_key(dtb, base_address), source);
    }

    pub fn module_symbol_source(
        &self,
        dtb: Dtb,
        base_address: VirtAddr,
    ) -> Option<ModuleSymbolSource> {
        self.module_source
            .get(&Self::module_key(dtb, base_address))
            .map(|source| source.clone())
    }

    fn read_debug_directory_location<B: MemoryOps<PhysAddr>>(
        memory: &memory::AddressSpace<'_, B>,
        base_address: VirtAddr,
    ) -> Result<Option<(u32, u32)>> {
        let mut header_buf = [0u8; 0x1000];
        memory.read_bytes(base_address, &mut header_buf)?;
        let view = pelite::pe64::PeView::from_bytes(&header_buf)?;
        Ok(view
            .data_directory()
            .get(IMAGE_DIRECTORY_ENTRY_DEBUG)
            .map(|entry| (entry.VirtualAddress, entry.Size)))
    }

    fn read_debug_directory_entries<B: MemoryOps<PhysAddr>>(
        memory: &memory::AddressSpace<'_, B>,
        base_address: VirtAddr,
        debug_rva: u32,
        debug_size: u32,
    ) -> Result<Vec<IMAGE_DEBUG_DIRECTORY>> {
        if debug_size == 0 {
            return Ok(Vec::new());
        }

        let entry_size = size_of::<IMAGE_DEBUG_DIRECTORY>();
        if !(debug_size as usize).is_multiple_of(entry_size) {
            return Err(Error::DebugInfo(format!(
                "debug directory size {:#x} is not a multiple of {}",
                debug_size, entry_size
            )));
        }

        let mut bytes = vec![0u8; debug_size as usize];
        memory.read_bytes(base_address + debug_rva as u64, &mut bytes)?;

        let mut entries = Vec::new();
        for chunk in bytes.chunks_exact(entry_size) {
            let entry =
                unsafe { ptr::read_unaligned(chunk.as_ptr() as *const IMAGE_DEBUG_DIRECTORY) };
            entries.push(entry);
        }

        Ok(entries)
    }

    fn read_codeview_from_memory<B: MemoryOps<PhysAddr>>(
        memory: &memory::AddressSpace<'_, B>,
        base_address: VirtAddr,
        entry: &IMAGE_DEBUG_DIRECTORY,
    ) -> Result<(String, Option<(DownloadJob, u128)>)> {
        if entry.AddressOfRawData == 0 || entry.SizeOfData < 4 {
            return Err(Error::DebugInfo(
                "codeview entry is missing raw data".to_string(),
            ));
        }

        let mut bytes = vec![0u8; entry.SizeOfData as usize];
        memory.read_bytes(base_address + entry.AddressOfRawData as u64, &mut bytes)?;
        let signature = bytes
            .get(..4)
            .ok_or_else(|| Error::DebugInfo("codeview entry truncated".to_string()))?;

        match signature {
            b"RSDS" => {
                if bytes.len() < size_of::<IMAGE_DEBUG_CV_INFO_PDB70>() {
                    return Err(Error::DebugInfo("RSDS entry truncated".to_string()));
                }

                let image = unsafe {
                    ptr::read_unaligned(bytes.as_ptr() as *const IMAGE_DEBUG_CV_INFO_PDB70)
                };
                let path =
                    Self::read_c_string_lossy(&bytes[size_of::<IMAGE_DEBUG_CV_INFO_PDB70>()..]);
                let summary = format!("CodeView RSDS age={} path={}", image.Age, path);
                let job = Self::build_download_job(&path, image.Signature, image.Age)?;
                Ok((summary, Some(job)))
            }
            b"NB10" => {
                if bytes.len() < 16 {
                    return Err(Error::DebugInfo("NB10 entry truncated".to_string()));
                }
                let age = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
                let path = Self::read_c_string_lossy(&bytes[16..]);
                Ok((format!("CodeView NB10 age={} path={}", age, path), None))
            }
            _ => Err(Error::DebugInfo("unknown magic number".to_string())),
        }
    }

    fn read_c_string_lossy(bytes: &[u8]) -> String {
        let nul = bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bytes.len());
        String::from_utf8_lossy(&bytes[..nul]).into_owned()
    }

    fn build_download_job(
        pdb_file_name: &str,
        guid: GUID,
        age: u32,
    ) -> Result<(DownloadJob, u128)> {
        let server_name = Self::symbol_server_file_name(pdb_file_name);
        let guid_str = format!(
            "{:08X}{:04X}{:04X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            guid.Data1,
            guid.Data2,
            guid.Data3,
            guid.Data4[0],
            guid.Data4[1],
            guid.Data4[2],
            guid.Data4[3],
            guid.Data4[4],
            guid.Data4[5],
            guid.Data4[6],
            guid.Data4[7],
        );

        let url = format!(
            "https://msdl.microsoft.com/download/symbols/{}/{}{:X}/{}",
            server_name, guid_str, age, server_name
        );

        let stem = server_name
            .rsplit_once('.')
            .map(|(stem, _)| stem)
            .unwrap_or(server_name);

        let filename = format!("{}.{}{:X}.pdb", stem, guid_str, age);
        let storage_dir = get_symbols_directory().ok_or(Error::StorageNotFound)?;
        let path = storage_dir.join(&filename);

        let guid = guid_to_u128(guid);
        let job = DownloadJob {
            url,
            path,
            filename: format!("{}.pdb", stem),
        };

        Ok((job, guid))
    }

    fn build_image_download_job(
        image_file_name: &str,
        time_date_stamp: u32,
        size_of_image: u32,
    ) -> Result<DownloadJob> {
        let server_name = Self::symbol_server_file_name(image_file_name);
        let image_id = format!("{time_date_stamp:08X}{size_of_image:X}");
        let url = format!(
            "https://msdl.microsoft.com/download/symbols/{}/{}/{}",
            server_name, image_id, server_name
        );
        let storage_dir = get_images_directory().ok_or(Error::StorageNotFound)?;
        let path = storage_dir.join(format!("{}.{}", image_id, server_name));

        Ok(DownloadJob {
            url,
            path,
            filename: server_name.to_string(),
        })
    }

    fn symbol_server_file_name(path: &str) -> &str {
        path.rsplit(['\\', '/']).next().unwrap_or(path)
    }

    // TODO (everywhere) use MemoryOps, not KvmHandle...
    // TODO (everywhere) propagate errors with format!
    // NOTE dont check for more than 1 CV entry, there shouldn't be more than 1
    pub fn load_from_binary(
        &self,
        kvm: &KvmHandle,
        object: &mut WinObject,
    ) -> Result<Option<u128>> {
        let view = object.view(kvm).ok_or(Error::ViewFailed)?;
        let debug = view.debug()?;

        if let Some((job, guid)) = Self::download_job_from_debug(&debug)? {
            download_job(&job, ProgressBar::new(0))?;
            self.ensure_pdb_loaded(guid, &job.path)?;

            return Ok(Some(guid));
        }

        Ok(None)
    }

    pub fn has_guid(&self, guid: u128) -> bool {
        self.pdbs.contains_key(&guid)
    }

    pub fn extract_download_job<B: MemoryOps<PhysAddr>>(
        backend: &B,
        dtb: Dtb,
        module_name: &str,
        base_address: VirtAddr,
    ) -> Result<ModuleSymbolDiscovery> {
        let addr_space = memory::AddressSpace::new(backend, dtb);
        match Self::extract_download_job_from_memory(&addr_space, base_address) {
            Ok(Some((job, guid))) => Ok(ModuleSymbolDiscovery::Ready {
                job,
                guid,
                source: ModuleSymbolSource::Memory,
            }),
            Ok(None) => Self::plan_image_fallback(&addr_space, module_name, base_address),
            Err(Error::BadVirtualAddress(_))
            | Err(Error::PartialRead(_))
            | Err(Error::DebugInfo(_)) => {
                Self::plan_image_fallback(&addr_space, module_name, base_address)
            }
            Err(err) => Err(err),
        }
    }

    pub fn load_downloaded_pdb(&self, load: &ModuleSymbolLoad) -> Result<()> {
        let module_key = Self::module_key(load.dtb, load.module.base_address);
        if let Some(existing) = self.modules.get(&module_key) {
            debug_assert_eq!(existing.guid, load.guid);
            self.set_module_symbol_status(
                load.dtb,
                load.module.base_address,
                ModuleSymbolStatus::Loaded,
            );
            self.set_module_symbol_source(load.dtb, load.module.base_address, load.source.clone());
            return Ok(());
        }

        self.ensure_pdb_loaded(load.guid, &load.job.path)?;
        self.modules.insert(module_key, load.loaded_module());
        self.set_module_symbol_status(
            load.dtb,
            load.module.base_address,
            ModuleSymbolStatus::Loaded,
        );
        self.set_module_symbol_source(load.dtb, load.module.base_address, load.source.clone());

        Ok(())
    }

    pub fn load_local_pdb_for_module(
        &self,
        dtb: Dtb,
        module: ModuleInfo,
        guid: u128,
        pdb_path: &Path,
    ) -> Result<()> {
        let mut pdb = pdb2::PDB::open(File::open(pdb_path)?)?;
        let pdb_info = pdb.pdb_information()?;
        if pdb_info.guid.as_u128() != guid {
            return Err(Error::DebugInfo(format!(
                "PDB GUID mismatch for {}: expected {:032x}, got {}",
                pdb_path.display(),
                guid,
                pdb_info.guid
            )));
        }

        let load = ModuleSymbolLoad::new(
            DownloadJob {
                url: String::new(),
                path: pdb_path.to_path_buf(),
                filename: pdb_path
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_else(|| pdb_path.display().to_string()),
            },
            guid,
            ModuleSymbolSource::Local,
            module,
            dtb,
        );
        self.load_downloaded_pdb(&load)
    }

    fn download_job_from_debug<'a, P>(
        debug: &pelite::pe64::debug::Debug<'a, P>,
    ) -> Result<Option<(DownloadJob, u128)>>
    where
        P: pelite::pe64::Pe<'a>,
    {
        let mut first_error = None;

        for dir in debug.iter() {
            match dir.entry() {
                Ok(entry) => {
                    if let Some(CodeView::Cv70 {
                        image,
                        pdb_file_name,
                    }) = entry.as_code_view()
                    {
                        let pdb_path = pdb_file_name.to_string();
                        let (job, guid) =
                            Self::build_download_job(&pdb_path, image.Signature, image.Age)?;
                        return Ok(Some((job, guid)));
                    }
                }
                Err(err) => {
                    if first_error.is_none() {
                        first_error = Some(err);
                    }
                }
            }
        }

        if let Some(err) = first_error {
            return Err(err.into());
        }

        Ok(None)
    }

    fn extract_download_job_from_memory<B: MemoryOps<PhysAddr>>(
        memory: &memory::AddressSpace<'_, B>,
        base_address: VirtAddr,
    ) -> Result<Option<(DownloadJob, u128)>> {
        let Some((debug_rva, debug_size)) =
            Self::read_debug_directory_location(memory, base_address)?
        else {
            return Ok(None);
        };

        for entry in
            Self::read_debug_directory_entries(memory, base_address, debug_rva, debug_size)?
        {
            if entry.Type != IMAGE_DEBUG_TYPE_CODEVIEW {
                continue;
            }

            let (_, job) = Self::read_codeview_from_memory(memory, base_address, &entry)?;
            if let Some(job) = job {
                return Ok(Some(job));
            }
        }

        Ok(None)
    }

    fn plan_image_fallback<B: MemoryOps<PhysAddr>>(
        memory: &memory::AddressSpace<'_, B>,
        module_name: &str,
        base_address: VirtAddr,
    ) -> Result<ModuleSymbolDiscovery> {
        let (time_date_stamp, size_of_image) = Self::read_image_lookup_info(memory, base_address)?;
        let image_job =
            Self::build_image_download_job(module_name, time_date_stamp, size_of_image)?;
        Ok(ModuleSymbolDiscovery::NeedsImage { image_job })
    }

    pub fn extract_download_job_from_image_file(
        image_path: &std::path::Path,
    ) -> Result<Option<(DownloadJob, u128)>> {
        let file = File::open(image_path)?;
        let mmap = unsafe { Mmap::map(&file)? };
        let pe = pelite::pe64::PeFile::from_bytes(&mmap[..])?;
        let debug = pe.debug()?;
        Self::download_job_from_debug(&debug)
    }

    fn read_image_lookup_info<B: MemoryOps<PhysAddr>>(
        memory: &memory::AddressSpace<'_, B>,
        base_address: VirtAddr,
    ) -> Result<(u32, u32)> {
        let mut header_buf = [0u8; 0x1000];
        memory.read_bytes(base_address, &mut header_buf)?;
        let view = pelite::pe64::PeView::from_bytes(&header_buf)?;
        Ok((
            view.file_header().TimeDateStamp,
            view.optional_header().SizeOfImage,
        ))
    }

    fn ensure_pdb_loaded(&self, guid: u128, path: &Path) -> Result<()> {
        if self.pdbs.contains_key(&guid) {
            return Ok(());
        }

        if !path.exists() {
            return Err(Error::PdbNotFound(path.to_path_buf()));
        }

        let file = File::open(path)?;
        let mmap = unsafe { Mmap::map(&file)? };
        let mmap = Arc::new(mmap);
        let mmap_slice: &[u8] = &mmap;

        let static_slice: &'static [u8] = unsafe { std::mem::transmute(mmap_slice) };
        let cursor = Cursor::new(static_slice);
        let pdb = pdb2::PDB::open(cursor)?;

        self.mmaps.insert(guid, mmap);
        self.pdbs.insert(guid, pdb.into());
        self.build_index(guid);

        Ok(())
    }

    pub fn merged_symbol_index(&self, dtb: Option<Dtb>) -> SymbolIndex {
        let total_modules = self
            .modules
            .iter()
            .filter(|module| dtb.is_none_or(|filter_dtb| module.dtb == filter_dtb))
            .count();
        let progress = ProgressBar::new((total_modules + 1) as u64);
        progress.set_style(task_progress_style());
        progress.set_message("Building symbol completions");

        let mut all_strings: Vec<String> = Vec::new();

        for module in self.modules.iter() {
            if let Some(filter_dtb) = dtb
                && module.dtb != filter_dtb
            {
                continue;
            }

            if let Some(index) = self.index.get(&module.guid) {
                let mut stream = index.set.stream();
                while let Some(key) = stream.next() {
                    if let Ok(s) = String::from_utf8(key.to_vec()) {
                        all_strings.push(s);
                    }
                }
            }

            progress.inc(1);
        }

        all_strings.sort();
        all_strings.dedup();

        let mut build = SetBuilder::memory();
        for symbol in all_strings {
            let _ = build.insert(&symbol);
        }

        let bytes = build.into_inner().unwrap_or_default();
        let set = Set::new(bytes).unwrap_or_default();
        progress.inc(1);
        progress.finish_and_clear();

        SymbolIndex { set }
    }

    pub fn merged_types_index(&self, dtb: Option<Dtb>) -> SymbolIndex {
        let total_modules = self
            .modules
            .iter()
            .filter(|module| dtb.is_none_or(|filter_dtb| module.dtb == filter_dtb))
            .count();
        let progress = ProgressBar::new((total_modules + 1) as u64);
        progress.set_style(task_progress_style());
        progress.set_message("Building type completions");

        let mut all_strings: Vec<String> = Vec::new();

        for module in self.modules.iter() {
            if let Some(filter_dtb) = dtb
                && module.dtb != filter_dtb
            {
                continue;
            }

            if let Some(index) = self.index_types.get(&module.guid) {
                let mut stream = index.set.stream();
                while let Some(key) = stream.next() {
                    if let Ok(s) = String::from_utf8(key.to_vec()) {
                        all_strings.push(s);
                    }
                }
            }

            progress.inc(1);
        }

        all_strings.sort();
        all_strings.dedup();

        let mut build = SetBuilder::memory();
        for symbol in all_strings {
            let _ = build.insert(&symbol);
        }

        let bytes = build.into_inner().unwrap_or_default();
        let set = Set::new(bytes).unwrap_or_default();
        progress.inc(1);
        progress.finish_and_clear();

        SymbolIndex { set }
    }

    pub fn find_type_across_modules(&self, dtb: Dtb, type_name: &str) -> Option<TypeInfo> {
        for module in self.modules.iter() {
            if module.dtb != dtb {
                continue;
            }
            if let Some(type_info) = self.dump_struct_with_types(module.guid, type_name) {
                return Some(type_info);
            }
        }
        None
    }

    pub fn find_symbol_across_modules(&self, dtb: Dtb, symbol_name: &str) -> Option<VirtAddr> {
        for module in self.modules.iter() {
            if module.dtb != dtb {
                continue;
            }
            if let Some(rva) = self.get_rva_of_symbol(module.guid, symbol_name) {
                return Some(module.base_address + rva as u64);
            }
        }
        None
    }

    pub fn find_closest_symbol_for_address(
        &self,
        dtb: Dtb,
        address: VirtAddr,
    ) -> Option<(String, String, u32)> {
        for module in self.modules.iter() {
            if module.dtb != dtb {
                continue;
            }

            if module.contains_address(address)
                && let Some((sym_name, offset)) =
                    self.get_address_of_closest_symbol(module.guid, module.base_address, address)
            {
                let short_name = ModuleInfo::derive_short_name(&module.name);
                return Some((short_name, sym_name, offset));
            }
        }
        None
    }

    pub fn find_module_for_address(&self, dtb: Dtb, address: VirtAddr) -> Option<LoadedModule> {
        self.modules
            .iter()
            .find(|module| module.dtb == dtb && module.contains_address(address))
            .map(|module| module.clone())
    }

    fn build_index(&self, guid: u128) -> Option<()> {
        let pdb = self.pdbs.get_mut(&guid)?;
        let mut pdb_lock = pdb.lock();
        let symbol_table = pdb_lock.global_symbols().ok()?;
        let mut symbols = symbol_table.iter();

        let mut strings: Vec<String> = Vec::new();

        while let Some(symbol) = symbols.next().ok()? {
            if let Ok(pdb2::SymbolData::Public(data)) = symbol.parse() {
                strings.push(data.name.to_string().into());
            }
        }

        strings.sort();
        strings.dedup();

        let mut build = SetBuilder::memory();
        for symbol in strings {
            let _ = build.insert(&symbol);
        }

        let bytes = build.into_inner().unwrap();
        let set = Set::new(bytes).unwrap();

        self.index.insert(guid, SymbolIndex { set });

        // NOW FOR TYPES!
        let mut strings: Vec<String> = Vec::new();

        let type_information = pdb_lock.type_information().ok()?;
        let mut type_finder = type_information.finder();
        let mut iter = type_information.iter();

        while let Some(typ) = iter.next().ok()? {
            type_finder.update(&iter);

            if let Ok(TypeData::Class(class)) = typ.parse()
                && !class.properties.forward_reference()
                && class.name.to_string() != "<anonymous-tag>"
            {
                strings.push(class.name.to_string().into());
            }
        }

        strings.sort();
        strings.dedup();

        let mut build = SetBuilder::memory();
        for symbol in strings {
            let _ = build.insert(&symbol);
        }

        let bytes = build.into_inner().unwrap();
        let set = Set::new(bytes).unwrap();

        self.index_types.insert(guid, SymbolIndex { set });

        Some(())
    }

    // pub fn symbol_index(&self, guid: u128) -> Option<Arc<SymbolIndex>> {
    //     self.index.get(&guid).map(|v| Arc::new(v.clone()))
    // }

    // pub fn types_index(&self, guid: u128) -> Option<Arc<SymbolIndex>> {
    //     self.index_types.get(&guid).map(|v| Arc::new(v.clone()))
    // }

    pub fn get_rva_of_symbol<S>(&self, guid: u128, symbol_name: S) -> Option<u32>
    where
        S: AsRef<str>,
    {
        let symbol_name = symbol_name.as_ref();

        let pdb = self.pdbs.get_mut(&guid)?;
        let mut pdb_lock = pdb.lock();
        let symbol_table = pdb_lock.global_symbols().ok()?;
        let address_map = pdb_lock.address_map().ok()?;
        let mut symbols = symbol_table.iter();

        while let Some(symbol) = symbols.next().ok()? {
            match symbol.parse() {
                Ok(pdb2::SymbolData::Public(data)) => {
                    if data.name.to_string() == symbol_name {
                        return Some(data.offset.to_rva(&address_map).unwrap_or_default().0);
                    }
                }
                Ok(pdb2::SymbolData::Data(_data)) => {
                    // TODO does this need to also be checked?
                }
                _ => {}
            }
        }

        None
    }

    pub fn get_address_of_closest_symbol(
        &self,
        guid: u128,
        base_address: VirtAddr,
        address: VirtAddr,
    ) -> Option<(String, u32)> {
        let pdb = self.pdbs.get_mut(&guid)?;
        let mut pdb_lock = pdb.lock();
        let symbol_table = pdb_lock.global_symbols().ok()?;
        let address_map = pdb_lock.address_map().ok()?;
        let mut symbols = symbol_table.iter();

        let mut closest: Option<(String, u32)> = None;
        let max_offset = 8192u32;

        while let Some(symbol) = symbols.next().ok()? {
            if let Ok(pdb2::SymbolData::Public(data)) = symbol.parse()
                && let Some(rva) = data.offset.to_rva(&address_map)
            {
                let symbol_address = base_address + rva.0 as u64;
                if address.0 >= symbol_address.0 {
                    let offset = (address.0 - symbol_address.0) as u32;
                    if offset <= max_offset {
                        if let Some((_, best_offset)) = closest {
                            if offset < best_offset {
                                closest = Some((data.name.to_string().into(), offset));
                            }
                        } else {
                            closest = Some((data.name.to_string().into(), offset));
                        }
                    }
                }
            }
        }

        closest
    }

    fn get_type_size<'p>(
        &self,
        finder: &pdb2::TypeFinder<'p>,
        index: pdb2::TypeIndex,
        ptr_size: u64,
    ) -> pdb2::Result<u64> {
        let item = finder.find(index)?;
        match item.parse()? {
            pdb2::TypeData::Primitive(data) => {
                if data.indirection.is_some() {
                    return Ok(ptr_size);
                }

                match data.kind {
                    pdb2::PrimitiveKind::Void => Ok(0),

                    pdb2::PrimitiveKind::Char
                    | pdb2::PrimitiveKind::RChar
                    | pdb2::PrimitiveKind::UChar
                    | pdb2::PrimitiveKind::I8
                    | pdb2::PrimitiveKind::U8
                    | pdb2::PrimitiveKind::Bool8 => Ok(1),

                    pdb2::PrimitiveKind::WChar
                    | pdb2::PrimitiveKind::RChar16
                    | pdb2::PrimitiveKind::Short
                    | pdb2::PrimitiveKind::UShort
                    | pdb2::PrimitiveKind::I16
                    | pdb2::PrimitiveKind::U16 => Ok(2),

                    pdb2::PrimitiveKind::Long
                    | pdb2::PrimitiveKind::ULong
                    | pdb2::PrimitiveKind::I32
                    | pdb2::PrimitiveKind::U32
                    | pdb2::PrimitiveKind::Bool32
                    | pdb2::PrimitiveKind::F32
                    | pdb2::PrimitiveKind::RChar32 => Ok(4),

                    pdb2::PrimitiveKind::Quad
                    | pdb2::PrimitiveKind::UQuad
                    | pdb2::PrimitiveKind::I64
                    | pdb2::PrimitiveKind::U64
                    | pdb2::PrimitiveKind::F64 => Ok(8),

                    pdb2::PrimitiveKind::Octa | pdb2::PrimitiveKind::UOcta => Ok(16),

                    _ => Ok(0),
                }
            }
            pdb2::TypeData::Class(data) => Ok(data.size), // NOTE this might (probably will) return 0
            pdb2::TypeData::Union(data) => Ok(data.size), // FIXME possibly? ^^
            pdb2::TypeData::Pointer(_) => Ok(ptr_size),
            pdb2::TypeData::Modifier(data) => {
                self.get_type_size(finder, data.underlying_type, ptr_size)
            }
            pdb2::TypeData::Enumeration(data) => {
                self.get_type_size(finder, data.underlying_type, ptr_size)
            }
            pdb2::TypeData::Array(data) => {
                Ok(data.dimensions.iter().fold(0, |acc, &x| acc + x as u64))
            }
            pdb2::TypeData::Bitfield(data) => {
                self.get_type_size(finder, data.underlying_type, ptr_size)
            }
            pdb2::TypeData::Procedure(_) => Ok(ptr_size),
            _ => Ok(0),
        }
    }

    fn resolve_type<'p>(
        &self,
        finder: &TypeFinder<'p>,
        index: TypeIndex,
    ) -> pdb2::Result<ParsedType> {
        let item = finder.find(index)?;
        let parsed = item.parse()?;

        match parsed {
            pdb2::TypeData::Primitive(data) => {
                let name = match data.kind {
                    PrimitiveKind::Void => "void",
                    PrimitiveKind::Char | PrimitiveKind::I8 => "CHAR",
                    PrimitiveKind::UChar | PrimitiveKind::U8 => "UCHAR",
                    PrimitiveKind::RChar => "CHAR",
                    PrimitiveKind::WChar => "WCHAR",
                    PrimitiveKind::RChar16 => "char16_t",
                    PrimitiveKind::RChar32 => "char32_t",
                    PrimitiveKind::Short | PrimitiveKind::I16 => "SHORT",
                    PrimitiveKind::UShort | PrimitiveKind::U16 => "USHORT",
                    PrimitiveKind::Long | PrimitiveKind::I32 => "LONG",
                    PrimitiveKind::ULong | PrimitiveKind::U32 => "ULONG",
                    PrimitiveKind::Quad | PrimitiveKind::I64 => "LONGLONG",
                    PrimitiveKind::UQuad | PrimitiveKind::U64 => "ULONGLONG",
                    PrimitiveKind::Octa => "INT128",
                    PrimitiveKind::UOcta => "UINT128",
                    PrimitiveKind::F32 => "float",
                    PrimitiveKind::F64 => "double",
                    PrimitiveKind::Bool8 | PrimitiveKind::Bool32 => "bool",
                    _ => "__unknown_t",
                };
                let primitive = ParsedType::Primitive(name.to_string());
                if data.indirection.is_some() {
                    Ok(ParsedType::Pointer(Box::new(primitive)))
                } else {
                    Ok(primitive)
                }
            }

            TypeData::Class(data) => Ok(ParsedType::Struct(data.name.to_string().into_owned())),
            TypeData::Union(data) => Ok(ParsedType::Union(data.name.to_string().into_owned())),
            TypeData::Enumeration(data) => Ok(ParsedType::Enum(data.name.to_string().into_owned())),

            TypeData::Pointer(data) => {
                let inner = self.resolve_type(finder, data.underlying_type)?;
                Ok(ParsedType::Pointer(Box::new(inner)))
            }

            TypeData::Array(data) => {
                let inner = self.resolve_type(finder, data.element_type)?;
                let count = data.dimensions.first().unwrap_or(&0);
                let mut sizeof_type = self.get_type_size(finder, data.element_type, 8)? as u32;
                if sizeof_type == 0 {
                    sizeof_type = 1;
                }

                Ok(ParsedType::Array(Box::new(inner), count / sizeof_type))
            }

            TypeData::Modifier(data) => self.resolve_type(finder, data.underlying_type),
            TypeData::Bitfield(data) => {
                let inner = self.resolve_type(finder, data.underlying_type)?;

                Ok(ParsedType::Bitfield {
                    underlying: Box::new(inner),
                    pos: data.position,
                    len: data.length,
                })
            }

            pdb2::TypeData::Procedure(data) => {
                let return_type = if let Some(idx) = data.return_type {
                    self.resolve_type(finder, idx)?
                } else {
                    ParsedType::Primitive("void".to_string())
                };

                let mut args = Vec::new();
                if let Ok(arg_item) = finder.find(data.argument_list)
                    && let Ok(pdb2::TypeData::ArgumentList(list)) = arg_item.parse()
                {
                    for arg_idx in list.arguments {
                        let arg_type = self.resolve_type(finder, arg_idx)?;
                        args.push(arg_type);
                    }
                }

                Ok(ParsedType::Function(Box::new(return_type), args))
            }

            _ => Ok(ParsedType::Unknown),
        }
    }

    fn process_field_list<'p>(
        &self,
        type_finder: &pdb2::TypeFinder<'p>,
        field_index: pdb2::TypeIndex,
        fields_map: &mut HashMap<String, FieldInfo>,
    ) -> pdb2::Result<()> {
        let field_item = type_finder.find(field_index)?;

        if let Ok(TypeData::FieldList(list)) = field_item.parse() {
            for field in list.fields {
                if let TypeData::Member(member) = field {
                    let name = member.name.to_string().into_owned();
                    let offset = member.offset;

                    let type_info = self.resolve_type(type_finder, member.field_type)?;

                    fields_map.insert(
                        name,
                        FieldInfo {
                            offset: offset as u32,
                            size: self.get_type_size(type_finder, member.field_type, 8)?,
                            type_data: type_info,
                        },
                    );
                }
            }

            if let Some(more_fields) = list.continuation {
                self.process_field_list(type_finder, more_fields, fields_map)?;
            }
        }
        Ok(())
    }

    pub fn dump_struct_with_types<S>(&self, guid: u128, struct_name: S) -> Option<TypeInfo>
    where
        S: Into<String> + AsRef<str>,
    {
        let pdb = self.pdbs.get_mut(&guid)?;
        let mut pdb_lock = pdb.lock();
        let type_information = pdb_lock.type_information().ok()?;
        let mut type_finder = type_information.finder();
        let mut iter = type_information.iter();

        while let Some(typ) = iter.next().ok()? {
            type_finder.update(&iter);

            if let Ok(TypeData::Class(class)) = typ.parse()
                && class.name.to_string() == struct_name.as_ref()
                && !class.properties.forward_reference()
            {
                let mut fields_map: HashMap<String, FieldInfo> = HashMap::new();
                if let Some(field_index) = class.fields {
                    self.process_field_list(&type_finder, field_index, &mut fields_map)
                        .ok()?;
                }

                return Some(TypeInfo {
                    name: struct_name.into(),
                    size: class.size as usize,
                    fields: fields_map,
                });
            }
        }

        None
    }
}

impl SymbolIndex {
    pub fn search(&self, prefix: &str, limit: usize) -> Vec<String> {
        let matcher = Str::new(prefix).starts_with();
        let mut stream = self.set.search(matcher).into_stream();
        let mut results = Vec::new();

        while let Some(key) = stream.next() {
            if let Ok(s) = String::from_utf8(key.to_vec()) {
                results.push(s);
            }

            if results.len() >= limit {
                break;
            }
        }

        results
    }
}
