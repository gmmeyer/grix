fn main() {
    // macOS: Python's symbols are looked up when the module loads.
    pyo3_build_config::add_extension_module_link_args();
}
