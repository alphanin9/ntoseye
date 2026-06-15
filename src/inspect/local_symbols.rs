//! Shared local-PDB symbol loading from a host directory.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::guest::{ModuleInfo, ModuleSymbolLoadReport};
use crate::symbols::{ModuleSymbolDiscovery, SymbolStore};
use crate::target::Target;
use crate::types::Dtb;

fn find_file_case_insensitive(dir: &Path, filename: &str) -> Option<PathBuf> {
    let wanted = filename.to_lowercase();
    std::fs::read_dir(dir)
        .ok()?
        .filter_map(|entry| entry.ok())
        .find_map(|entry| {
            let path = entry.path();
            let name = path.file_name()?.to_string_lossy().to_lowercase();
            if name == wanted { Some(path) } else { None }
        })
}

fn local_symbol_plan_for_module(
    debugger: &Target,
    dir: &Path,
    dtb: Dtb,
    module: &ModuleInfo,
) -> Result<Option<(PathBuf, u128)>> {
    match SymbolStore::extract_download_job(&debugger.kvm, dtb, &module.name, module.base_address)?
    {
        ModuleSymbolDiscovery::Ready { job, guid, .. } => {
            Ok(find_file_case_insensitive(dir, &job.filename).map(|path| (path, guid)))
        }
        ModuleSymbolDiscovery::NeedsImage { image_job } => {
            let Some(image_path) = find_file_case_insensitive(dir, &image_job.filename) else {
                return Ok(None);
            };
            let Some((job, guid)) = SymbolStore::extract_download_job_from_image_file(&image_path)?
            else {
                return Ok(None);
            };
            Ok(find_file_case_insensitive(dir, &job.filename).map(|path| (path, guid)))
        }
    }
}

pub fn load_symbols_from_directory(
    debugger: &Target,
    dir: &Path,
    filter: Option<&str>,
) -> Result<ModuleSymbolLoadReport> {
    if !dir.is_dir() {
        return Err(Error::InvalidExpression(format!(
            "not a directory: {}",
            dir.display()
        )));
    }
    let (modules, dtb) = if let Some(process_info) = &debugger.current_process_info {
        (
            debugger.guest.process_modules(process_info)?,
            process_info.dtb,
        )
    } else {
        (
            debugger.guest.kernel_modules()?,
            debugger.guest.ntoskrnl.dtb(),
        )
    };
    let filter = filter.map(str::to_lowercase);
    let selected: Vec<ModuleInfo> = modules
        .into_iter()
        .filter(|module| {
            filter.as_ref().is_none_or(|filter| {
                module.short_name.to_lowercase().contains(filter)
                    || module.name.to_lowercase().contains(filter)
            })
        })
        .collect();
    let mut report = ModuleSymbolLoadReport {
        total: selected.len(),
        ..ModuleSymbolLoadReport::default()
    };
    for module in selected {
        match local_symbol_plan_for_module(debugger, dir, dtb, &module) {
            Ok(Some((pdb_path, guid))) => {
                match debugger
                    .symbols
                    .load_local_pdb_for_module(dtb, module, guid, &pdb_path)
                {
                    Ok(()) => report.loaded += 1,
                    Err(_) => report.failed += 1,
                }
            }
            Ok(None) => report.no_pdb += 1,
            Err(_) => report.failed += 1,
        }
    }
    Ok(report)
}
