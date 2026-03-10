// ============================================================================
// /proc/self/maps parsing
// ============================================================================

/// Parse /proc/self/maps to find the libart.so address range and file path.
pub(crate) fn probe_libart_range() -> (u64, u64) {
    let maps = match super::util::read_proc_self_maps() {
        Some(s) => s,
        None => return (0, 0),
    };
    let summary = summarize_matching_paths(&maps, |path| path.contains("libart.so"));
    let found_path = summary.as_ref().map(|summary| summary.first_path.clone());

    let _ = LIBART_PATH.set(found_path.clone());

    if let Some(summary) = summary {
        output_message(&format!(
            "[module] libart.so range: {:#x}-{:#x}, path: {:?}",
            summary.base, summary.end, found_path
        ));
        (summary.base, summary.end)
    } else {
        (0, 0)
    }
}

/// 通过 /proc/self/maps 获取指定模块的地址范围 (start, end)。
/// 返回 (0, 0) 表示未找到。
pub(crate) fn probe_module_range(module_name: &str) -> (u64, u64) {
    let maps = match super::util::read_proc_self_maps() {
        Some(s) => s,
        None => return (0, 0),
    };

    summarize_matching_paths(&maps, |path| matches_exact_module_name(path, module_name))
        .map(|summary| (summary.base, summary.end))
        .unwrap_or((0, 0))
}

/// Parse /proc/self/maps to find a module's base address.
fn find_module_base(module_name: &str) -> u64 {
    let maps = match super::util::read_proc_self_maps() {
        Some(s) => s,
        None => return 0,
    };

    find_first_matching_path_start(&maps, |path| matches_module_lookup_name(path, module_name))
        .unwrap_or(0)
}

/// Module info from /proc/self/maps
#[derive(Clone, Debug, PartialEq, Eq)]
struct ModuleInfo {
    name: String,
    base: u64,
    size: u64,
    path: String,
}

impl ModuleInfo {
    fn from_path_range(path: String, base: u64, end: u64) -> Self {
        let name = module_basename(&path).to_string();
        Self {
            name,
            base,
            size: end - base,
            path,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ModuleMapEntry {
    start: u64,
    end: u64,
    path: String,
}

impl ModuleMapEntry {
    fn from_proc_map_entry(entry: crate::jsapi::util::ProcMapEntry<'_>) -> Option<Self> {
        let path = entry.path?;
        if path.starts_with('[') || !path.contains('/') {
            return None;
        }

        Some(Self {
            start: entry.start,
            end: entry.end,
            path: path.to_string(),
        })
    }

    fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }

    fn path_score(&self) -> u8 {
        if self.path.starts_with("/dev/") {
            1
        } else {
            0
        }
    }
}

struct AggregatedModuleRange {
    path: String,
    base: u64,
    end: u64,
}

impl AggregatedModuleRange {
    fn from_entry(entry: &ModuleMapEntry) -> Self {
        Self {
            path: entry.path.clone(),
            base: entry.start,
            end: entry.end,
        }
    }

    fn include(&mut self, entry: &ModuleMapEntry) {
        if entry.start < self.base {
            self.base = entry.start;
        }
        if entry.end > self.end {
            self.end = entry.end;
        }
    }

    fn into_module_info(self) -> ModuleInfo {
        ModuleInfo::from_path_range(self.path, self.base, self.end)
    }
}

/// Parse file-backed VMAs from /proc/self/maps without merging gaps.
fn parse_module_map_entries(maps: &str) -> Vec<ModuleMapEntry> {
    crate::jsapi::util::proc_maps_entries(maps)
        .filter_map(ModuleMapEntry::from_proc_map_entry)
        .collect()
}

fn enumerate_module_map_entries() -> Vec<ModuleMapEntry> {
    let maps = match super::util::read_proc_self_maps() {
        Some(s) => s,
        None => return Vec::new(),
    };

    parse_module_map_entries(&maps)
}

fn aggregate_modules(entries: impl IntoIterator<Item = ModuleMapEntry>) -> Vec<ModuleInfo> {
    let entries: Vec<_> = entries.into_iter().collect();
    collect_module_ranges(entries.iter())
        .into_iter()
        .map(AggregatedModuleRange::into_module_info)
        .collect()
}

fn aggregate_module_for_path(entries: &[ModuleMapEntry], path: &str) -> Option<ModuleInfo> {
    collect_module_ranges(entries.iter())
        .into_iter()
        .find(|module| module.path == path)
        .map(AggregatedModuleRange::into_module_info)
}

/// Parse /proc/self/maps and aggregate VMAs per unique path.
fn enumerate_modules_from_maps() -> Vec<ModuleInfo> {
    aggregate_modules(enumerate_module_map_entries())
}

fn find_module_by_address_in_entries(
    entries: impl IntoIterator<Item = ModuleMapEntry>,
    addr: u64,
) -> Option<ModuleInfo> {
    let entries: Vec<_> = entries.into_iter().collect();
    let path = entries
        .iter()
        .filter(|entry| entry.contains(addr))
        .min_by(|a, b| {
            a.path_score()
                .cmp(&b.path_score())
                .then_with(|| (a.end - a.start).cmp(&(b.end - b.start)))
                .then_with(|| b.start.cmp(&a.start))
        })
        .map(|entry| entry.path.clone())?;

    aggregate_module_for_path(&entries, &path)
}

/// Find the module containing `addr` and return the module-wide aggregated range.
fn find_module_by_address(addr: u64) -> Option<ModuleInfo> {
    find_module_by_address_in_entries(enumerate_module_map_entries(), addr)
}

fn collect_module_ranges<'a>(
    entries: impl IntoIterator<Item = &'a ModuleMapEntry>,
) -> Vec<AggregatedModuleRange> {
    let mut modules: Vec<AggregatedModuleRange> = Vec::new();

    for entry in entries {
        if let Some(module) = modules.iter_mut().find(|module| module.path == entry.path) {
            module.include(entry);
        } else {
            modules.push(AggregatedModuleRange::from_entry(entry));
        }
    }

    modules
}

fn module_basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn matches_exact_module_name(path: &str, module_name: &str) -> bool {
    path.contains(module_name) && module_basename(path) == module_name
}

fn matches_module_lookup_name(path: &str, module_name: &str) -> bool {
    if !path.contains(module_name) {
        return false;
    }

    let basename = module_basename(path);
    basename == module_name
        || basename.starts_with(&format!("{}.", module_name))
        || path.ends_with(module_name)
}

struct PathMapSummary {
    base: u64,
    end: u64,
    first_path: String,
}

fn summarize_matching_paths(
    maps: &str,
    mut matches_path: impl FnMut(&str) -> bool,
) -> Option<PathMapSummary> {
    let mut base = u64::MAX;
    let mut end = 0;
    let mut first_path = None;

    for entry in crate::jsapi::util::proc_maps_entries(maps) {
        let Some(path) = entry.path else {
            continue;
        };
        if !matches_path(path) {
            continue;
        }

        if entry.start < base {
            base = entry.start;
        }
        if entry.end > end {
            end = entry.end;
        }
        if first_path.is_none() {
            first_path = Some(path.to_string());
        }
    }

    first_path.map(|first_path| PathMapSummary {
        base,
        end,
        first_path,
    })
}

fn find_first_matching_path_start(
    maps: &str,
    mut matches_path: impl FnMut(&str) -> bool,
) -> Option<u64> {
    crate::jsapi::util::proc_maps_entries(maps).find_map(|entry| {
        let path = entry.path?;
        matches_path(path).then_some(entry.start)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_by_address_returns_the_aggregated_module_range() {
        let maps = "\
1000-2000 r-xp 00000000 00:00 0 /tmp/libfoo.so
2000-3000 r--p 00001000 00:00 0 /tmp/libfoo.so
9000-a000 r-xp 00000000 00:00 0 /tmp/libfoo.so
a000-b000 r--p 00001000 00:00 0 /tmp/libfoo.so
";

        let module = find_module_by_address_in_entries(parse_module_map_entries(maps), 0x9500)
            .expect("expected matching module");

        assert_eq!(
            module,
            ModuleInfo {
                name: "libfoo.so".to_string(),
                base: 0x1000,
                size: 0xa000,
                path: "/tmp/libfoo.so".to_string(),
            }
        );
    }

    #[test]
    fn enumerate_modules_still_aggregates_by_path() {
        let maps = "\
1000-2000 r-xp 00000000 00:00 0 /tmp/libfoo.so
2000-2800 r--p 00001000 00:00 0 /tmp/libfoo.so
";

        let modules = aggregate_modules(parse_module_map_entries(maps));

        assert_eq!(
            modules,
            vec![ModuleInfo {
                name: "libfoo.so".to_string(),
                base: 0x1000,
                size: 0x1800,
                path: "/tmp/libfoo.so".to_string(),
            }]
        );
    }
}
