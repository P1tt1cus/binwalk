//! Rust library for identifying, and optionally extracting, files embedded inside other files.
//!
//! ## Example
//!
//!```no_run
//! use binwalk::Binwalk;
//!
//! // Create a new Binwalk instance
//! let binwalker = Binwalk::new();
//!
//! // Read in the data you want to analyze
//! let file_data = std::fs::read("/tmp/firmware.bin").expect("Failed to read from file");
//!
//! // Scan the file data and print the results
//! for result in binwalker.scan(&file_data) {
//!    println!("{:#?}", result);
//! }
//! ```
mod binwalk;
pub mod common;
pub mod extractors;
mod magic;
pub mod signatures;
pub mod structures;
pub use binwalk::{AnalysisResults, Binwalk, BinwalkError};

// For Python bindings
use pyo3::prelude::*;
use pyo3::exceptions::PyRuntimeError;
use std::collections::HashMap;
use std::path::Path;


/// Extracts data from a file using Binwalk.
///
/// ## Arguments
///
/// * `file_path` - The path to the file to be analyzed.
/// * `output_path` - The directory where extracted files will be saved.
/// * `include` - Optional list of signatures to include in the analysis.
/// * `exclude` - Optional list of signatures to exclude from the analysis.
/// * `full_search` - Optional flag to enable full search mode.
///
/// ## Returns
///
/// A vector of hash maps containing the extraction results.
///
/// ## Example
///
/// ```python
/// from your_project_name import extract
///
/// results = extract("path/to/file", "output/directory", None, None, False)
/// for result in results:
///     print(result)
/// ```
#[pyfunction]
#[pyo3(signature = (file_path, output_path=None, include=None, exclude=None, full_search=None))]
fn extract(
    file_path: String,
    output_path: Option<String>,
    include: Option<Vec<String>>,
    exclude: Option<Vec<String>>,
    full_search: Option<bool>,
) -> PyResult<Vec<HashMap<String, String>>> {

    // Check if input file exists
    if !Path::new(&file_path).exists() {
        return Err(PyRuntimeError::new_err("Input file does not exist"));
    }

    // Initialize binwalk
    let binwalker = Binwalk::configure(
        Some(file_path.clone()),
        output_path,
        include,
        exclude,
        None,
        full_search.unwrap_or(false),
    ).map_err(|e| PyRuntimeError::new_err(e.message.to_string()))?;

    // Read the file data so we can pass it to the scan function and extract results
    let file_data = std::fs::read(&binwalker.base_target_file)
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

    let scan_results = binwalker.scan(&file_data);

    // The previous scan results can now be passed to the extract function to extract the data
    let extraction_results = binwalker.extract(
        &file_data,
        &binwalker.base_target_file,
        &scan_results,
    );

    // Convert the extraction results to a format that can be returned to Python
    let mut results = Vec::new();
    for (key, value) in extraction_results.iter() {
        let mut result_map = HashMap::new();
        result_map.insert("key".to_string(), key.clone());
        let size_str = value.size.map_or("Unknown".to_string(), |s| s.to_string());
        result_map.insert("size".to_string(), size_str);
        result_map.insert("success".to_string(), value.success.to_string());
        result_map.insert("extractor".to_string(), value.extractor.clone());
        result_map.insert("output_directory".to_string(), value.output_directory.clone());
        results.push(result_map);
    }

    Ok(results)

}


/// Scans a file for signatures using Binwalk.
///
/// ## Arguments
///
/// * `file_path` - The path to the file to be scanned.
///
/// ## Returns
///
/// A vector of hash maps containing the scan results.
///
/// ## Example
///
/// ```python
/// from your_project_name import scan_file
///
/// results = scan_file("path/to/file")
/// for result in results:
///     print(result)
/// ```
#[pyfunction]
fn scan_file(file_path: &str) -> PyResult<Vec<HashMap<String, String>>> {

    // Check to see whether the input file exists before proceeding
    let file_data = std::fs::read(&Path::new(file_path)).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

    // Create a new Binwalk instance
    let binwalker = Binwalk::new();

    // Define a vector to store the results of the scan
    let mut results = Vec::new();

    // Convert the extraction results to a format that can be returned to Python
    for result in binwalker.scan(&file_data) {
        let mut result_map = HashMap::new();
        result_map.insert("description".to_string(), result.description.clone());
        result_map.insert("id".to_string(), result.id.clone());
        result_map.insert("name".to_string(), result.name.clone());
        result_map.insert("confidence".to_string(), result.confidence.clone().to_string());
        result_map.insert("offset".to_string(), result.offset.to_string());
        result_map.insert("size".to_string(), result.size.to_string());
        results.push(result_map);
    }
    Ok(results)
}

#[pymodule]
fn binwalkpy(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(scan_file, m)?)?;
    m.add_function(wrap_pyfunction!(extract, m)?)?;
    Ok(())
}