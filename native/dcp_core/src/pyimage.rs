//! The original binary as Python reads it (config.Project.image, the tests): the core's PE32 reader (pe.rs) over one
//! file's bytes.

use crate::pe::Image;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use sha2::{Digest, Sha256};
use std::sync::{Arc, OnceLock};

#[pyclass(frozen)]
pub struct PeImage {
    img: Arc<Image>,
    sha: OnceLock<String>,
}

type Header = (u32, u32, bool, u16, u32, (u8, u8), u16, u32, u32, u16);
type Ranges = Vec<(String, Vec<(u32, u32)>)>;

fn ranges(m: std::collections::HashMap<&'static str, Vec<(u32, u32)>>) -> Ranges {
    let mut v: Ranges = m.into_iter().map(|(k, r)| (k.to_string(), r)).collect();
    v.sort();
    v
}

#[pymethods]
impl PeImage {
    /// (base, entry, is_dll, machine, timestamp, linker version, subsystem, headers size, image size, file
    /// characteristics).
    fn header(&self) -> Header {
        let i = &self.img;
        (i.base, i.entry, i.is_dll, i.machine, i.timestamp, i.linker_version, i.subsystem, i.headers_size, i.image_size, i.file_chars)
    }

    /// [(index, name, va, vsize, raw_off, raw_size, chars)].
    fn sections(&self) -> Vec<(usize, String, u32, u32, u32, u32, u32)> {
        self.img.sections.iter().map(|s| (s.index, s.name.clone(), s.va, s.vsize, s.raw_off, s.raw_size, s.chars)).collect()
    }

    /// [(index, name, va, size)].
    fn directories(&self) -> Vec<(usize, String, u32, u32)> {
        self.img.directories.iter().map(|d| (d.index, d.name.to_string(), d.va, d.size)).collect()
    }

    /// The image format's key.
    #[getter]
    fn key(&self) -> &'static str {
        "pe32"
    }

    #[getter]
    fn base(&self) -> u32 {
        self.img.base
    }

    #[getter]
    fn entry(&self) -> u32 {
        self.img.entry
    }

    #[getter]
    fn is_dll(&self) -> bool {
        self.img.is_dll
    }

    /// One past the image's last byte.
    #[getter]
    fn end(&self) -> u32 {
        self.img.end()
    }

    /// The instruction set the machine type implies (None: unknown machine).
    #[getter]
    pub fn default_isa(&self) -> Option<&'static str> {
        self.img.default_isa()
    }

    #[getter]
    pub fn sha256(&self) -> String {
        self.sha.get_or_init(|| crate::fsmemo::hex(&Sha256::digest(&self.img.data))).clone()
    }

    fn data<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.img.data)
    }

    /// n bytes at va (zero where the file holds none).
    fn read<'py>(&self, py: Python<'py>, va: u32, n: usize) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.img.read(va, n))
    }

    /// The file offset of va, None outside every section and the headers.
    fn off(&self, va: u32) -> Option<usize> {
        self.img.off(va).map(|x| x.0)
    }

    /// The raw data of the section of this index.
    fn section_data<'py>(&self, py: Python<'py>, index: usize) -> Bound<'py, PyBytes> {
        let s = self.img.sections.iter().find(|s| s.index == index);
        PyBytes::new(py, s.map(|s| self.img.section_data(s)).unwrap_or(&[]))
    }

    #[pyo3(signature = (va, limit=4096))]
    fn cstr<'py>(&self, py: Python<'py>, va: u32, limit: usize) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.img.cstr_n(va, limit))
    }

    fn kind(&self) -> &'static str {
        self.img.kind()
    }

    /// [(dll, name, ordinal, slot, hint)].
    fn imports(&self) -> Vec<(String, Option<String>, Option<u32>, u32, Option<u16>)> {
        self.img.imports().into_iter().map(|i| (i.dll, i.name, i.ordinal, i.slot, i.hint)).collect()
    }

    /// [(ordinal, name, va, forwarder)].
    fn exports(&self) -> Vec<(u32, Option<String>, u32, Option<String>)> {
        self.img.exports().into_iter().map(|e| (e.ordinal, e.name, e.va, e.forwarder)).collect()
    }

    fn relocations(&self) -> Vec<u32> {
        self.img.relocations()
    }

    fn rich(&self) -> Vec<(u32, u32, u32)> {
        self.img.rich()
    }

    fn rich_range(&self) -> Option<(u32, u32)> {
        self.img.rich_range()
    }

    fn reloc_range(&self) -> Option<(u32, u32)> {
        self.img.directory("basereloc").map(|d| (d.va, d.va + d.size))
    }

    fn header_regions(&self) -> Vec<(String, u32, u32)> {
        self.img.header_regions()
    }

    fn directory_regions(&self) -> Vec<(String, u32, u32)> {
        self.img.directory_regions()
    }

    fn import_regions(&self) -> Vec<(String, u32, u32)> {
        self.img.import_regions()
    }

    fn export_regions(&self) -> Vec<(String, u32, u32)> {
        self.img.export_regions()
    }

    fn import_ranges<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        for (k, v) in ranges(self.img.import_ranges()) {
            d.set_item(k, v)?;
        }
        Ok(d)
    }

    fn export_ranges<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        for (k, v) in ranges(self.img.export_ranges()) {
            d.set_item(k, v)?;
        }
        Ok(d)
    }
}

/// The PE32 image of a file; ValueError for a file that is none.
#[pyfunction]
pub fn pe_open(path: &str) -> PyResult<PeImage> {
    let data = std::fs::read(path).map_err(|e| PyValueError::new_err(format!("{path}: {e}")))?;
    let img = Image::parse(data).map_err(PyValueError::new_err)?;
    Ok(PeImage { img: Arc::new(img), sha: OnceLock::new() })
}
