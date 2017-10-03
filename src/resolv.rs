use std::ffi::CString;
use std::io::{Result, Error, ErrorKind};
use std::mem;
use std::ptr;
use libc::{c_char, c_int, c_uchar};
use nix::Errno;
use nix::errno::ErrnoSentinel;

mod ffi {
  use std::ffi::CStr;
  pub use libc::{c_char, c_int, c_uchar, c_void};

  const NS_S_MAX: usize = 4;

  #[repr(C)]
  pub struct CNSMsg {
    _msg: *const c_uchar,
    _eom: *const c_uchar,
    _id: u16,
    _flags: u16,
    _counts: [u16; NS_S_MAX],
    _sections: [*const c_uchar; NS_S_MAX],
    _sect: c_int,
    _rrnum: c_int,
    _msg_ptr: *const c_uchar,
  }
  
  const NS_MAXDNAME: usize = 1025;
  
  #[repr(C)]
  pub struct CNSRr {
    name: [c_char; NS_MAXDNAME],
    _type: u16,
    rr_class: u16,
    ttl: u16,
    rdlength: u16,
    rdata: *const c_uchar
  }

  #[link(name="resolv")]
  extern "C" {
    pub fn __res_search(dname: *const c_char,
                      class: c_int,
                      rtype: c_int,
                      answer: *mut c_uchar,
                      anslen: c_int) -> c_int;

    pub fn ns_initparse(buf: *const c_uchar,
                        msglen: c_int,
                        handle: *mut CNSMsg) -> c_int;

    pub fn ns_parserr(msg: *mut CNSMsg,
                      ns_sect: c_int,
                      rrnum: c_int,
                      rr: *mut CNSRr) -> c_int;

    pub fn ns_sprintrr(handle: *const CNSMsg,
                       rr: *const CNSRr,
                       name_ctx: *const c_char,
                       origin: *const c_char,
                       buf: *mut c_char,
                       buflen: usize) -> c_int;
  }

  impl CNSMsg {
    pub fn msg_count(&self, section: usize) -> u16 {
      self._counts[section]
    }
  }
  
  impl CNSRr {
    pub fn name(&self) -> &CStr {
      unsafe { CStr::from_ptr(self.name.as_ptr()) }
    }
  }
}

// Helper function to get a Result
fn result<S: ErrnoSentinel + PartialEq<S>>(value: S) -> Result<S> {
  Errno::result(value).map_err(|x| Error::from(x))
}

pub struct NSMsg {
  c: ffi::CNSMsg,
}

pub struct NSRr {
  c: ffi::CNSRr,
}

pub enum ResClass {
  In = 1
}

pub enum ResType {
  A = 1,
  NS = 2,
  MD = 3,
  MF = 4,
  CNAME = 5,
  SOA = 6,
  MB = 7,
  MG = 8,
  MR = 9,
  NULL = 10,
  WKS = 11,
  PTR = 12,
  HINFO = 13,
  MINFO = 14,
  MX = 15,
  TXT = 16,
  RP = 17,
  AFSDB = 18,
  X25 = 19,
  ISDN = 20,
  RT = 21,
  NSAP = 22,
  SIG = 24,
  KEY = 25,
  PX = 26,
  GPOS = 27,
  AAAA = 28,
  LOC = 29,
  NXT = 30,
  EID = 31,
  NIMLOC = 32,
  SRV = 33,
  ATMA = 34,
  NAPTR = 35,
  KX = 36,
  CERT = 37,
  DNAME = 39,
  SINK = 40,
  OPT = 41,
  APL = 42,
  TKEY = 249,
  TSIG = 250,
  IXFR = 251,
  AXFR = 252,
  MAILB = 253,
  MAILA = 254,
  Any = 255,
}

pub enum NSSect {
  QD_ZN = 0, // Question / Zone
  AN_PR = 1, // Answer / Prerequisites
  NS_UD = 2, // Name servers / Update
  AR = 3, // Additional records
}

pub fn res_search(dname: &CString, class: ResClass, rtype: ResType) -> Result<Vec<u8>> {
  const PACKETSZ: usize = 512;
  let buf = [0 as u8; PACKETSZ];
  let res = unsafe {
    ffi::__res_search(dname.as_ptr(),
                      class as c_int,
                      rtype as c_int,
                      buf.as_ptr() as *mut c_uchar,
                      PACKETSZ as c_int
                      )
  };
  result(res).map(|len| { Vec::from(&buf[..len as usize]) })
}

impl NSMsg {
  pub fn initparse(msg: &[u8]) -> Result<NSMsg> {
    let mut nsmsg = unsafe { mem::uninitialized() };
    let res = unsafe {
      ffi::ns_initparse(msg.as_ptr(), msg.len() as c_int, &mut nsmsg as *mut ffi::CNSMsg)
    };
    result(res).map(|_| NSMsg { c: nsmsg })
  }
  
  pub fn msg_count(&self, section: NSSect) -> u16 {
    self.c.msg_count(section as usize)
  }
  
  pub fn parserr(&mut self, section: NSSect, rrnum: u16) -> Result<NSRr> {
    let mut rr = unsafe { mem::uninitialized() };
    let res = unsafe {
      ffi::ns_parserr(&mut self.c as *mut ffi::CNSMsg, section as c_int, rrnum as c_int, &mut rr as *mut ffi::CNSRr)
    };
    result(res).map(|_| NSRr { c: rr })
  }
}

impl NSRr {
  pub fn name(&self) -> &str {
    self.c.name().to_str().unwrap()
  }
}

pub fn print(msg: &NSMsg, rr: &NSRr, name_ctx: Option<&CString>, origin: Option<&CString>) -> Result<String> {
  let mut buf = [0 as u8; 4096];
  let res = unsafe {
    ffi::ns_sprintrr(&msg.c as *const ffi::CNSMsg, &rr.c as *const ffi::CNSRr,
                     name_ctx.map(|x| x.as_ptr()).unwrap_or(ptr::null()),
                     origin.map(|x| x.as_ptr()).unwrap_or(ptr::null()),
                     buf.as_mut_ptr() as *mut c_char, buf.len())
  };

  result(res).and_then(|n| {
    let vec = Vec::from(&buf[0..n as usize]);
    String::from_utf8(vec).map_err(|x| Error::new(ErrorKind::Other, "Cannot decode DNS entry into string"))
  })
}
