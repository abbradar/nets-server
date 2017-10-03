use std::fs;
use std::io::{Write, Result};
use std::path::Path;
use tempfile::NamedTempFile;

pub fn maildir_deliver(rootdir: &Path, data: &str) -> Result<()> {
  let utmp = rootdir.join("tmp");
  let unew = rootdir.join("new");
  
  try!(fs::create_dir_all(&utmp));
  let mut tmp = try!(NamedTempFile::new_in(&utmp));
  try!(tmp.write_all(data.as_bytes()));
  try!(tmp.sync_data());
  
  let topath = unew.join(tmp.path().file_name().unwrap());
  try!(fs::create_dir_all(&unew));
  let file = try!(tmp.persist_noclobber(topath));
  Ok(())
}
