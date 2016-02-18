extern crate nix;
extern crate libc;
extern crate regex;
#[macro_use]
extern crate lazy_static;
extern crate time;
extern crate tempfile;
extern crate tempdir;
extern crate rustc_serialize;

mod smtp;
mod logger;
mod util;
mod resolv;

use std::{env, mem, fs, thread};
use std::fs::File;
use std::cmp::max;
use std::io::{Read, Write};
use std::os::unix::io::{RawFd, AsRawFd};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::iter::FromIterator;
use std::path::PathBuf;
use std::ffi::CString;
use std::sync::atomic;
use std::sync::atomic::AtomicBool;
use libc::{uid_t, gid_t, c_long, timespec};
use nix::{unistd, mqueue};
use nix::mqueue::MqAttr;
use nix::{Error, Errno};
use nix::sys::select::FdSet;
use nix::sys::{select, socket, sendfile, stat};
use nix::sys::socket::{SockAddr, SockFlag, AddressFamily, SockType, InetAddr, IpAddr};
use nix::sys::timerfd::ITimerSpec;
use nix::sys::signal;
use nix::sys::signal::{SigAction, SigSet, SigHandler};
use rustc_serialize::json;
use tempfile::NamedTempFile;
use smtp::{Session, Destination};
use logger::Logger;

#[derive(Eq, PartialEq, Clone, Debug, RustcDecodable)]
struct Settings {
  deliverydir: String,
  queuedir: String,
  tmpdir: String,
  origin: String,
  timeout: u32,
  user: Option<uid_t>,
  group: Option<gid_t>,
  nthreads: u32,
  port: u16,
  queues_len: usize,
}

#[derive(Debug)]
struct ProcessResult {
  fd: RawFd,
  timerfd: RawFd,
  result: bool,
}

lazy_static! {
  static ref SIGNAL_GOT: AtomicBool = AtomicBool::new(false);
}

extern fn handle_signal(signum: signal::SigNum) {
  println!("Got signal {}, exiting...", signum);
  SIGNAL_GOT.store(true, atomic::Ordering::Relaxed);
}

fn process(req_r: RawFd, back_w: RawFd, settings: Arc<Settings>, tmpdir: Arc<PathBuf>, sessions: Arc<Mutex<BTreeMap<RawFd, Box<smtp::Session>>>>) {
  loop {
    // Rust doesn't support static sizeof()'s yet -- see #1144
    let mut fdbuf = Vec::new();
    fdbuf.resize(mem::size_of::<RawFd>(), 0);
    let len = mqueue::mq_receive(req_r, &mut fdbuf, 0).unwrap();
    if len == 0 {
      break;
    }
    assert!(len == mem::size_of::<RawFd>());
    let fd = unsafe {
      let fdp: *mut RawFd = mem::transmute(fdbuf.as_ptr());
      *fdp
    };
    
    let mut buf = [0u8; 4096];
    let sz = unistd::read(fd, &mut buf).unwrap();

    let session = sessions.lock().unwrap().remove(&fd).unwrap();
    let timerfd = session.timerfd;
    // For now, we fail loudly on any internal errors (timerfd ones, for example). This might be a bad behaviour
    // and is completely avoidable (match on the result), but it feels nice to have it fail in such way.
    let (msgs, mnsession) = session.message_step(&buf[0..sz])
      .unwrap_or_else(|x| panic!(format!("Internal error: {}", x)));
    for m in msgs {
      let fname = m.tmpfile.path().file_name().unwrap().to_str().unwrap().to_string();
      let from = match m.from {
        Some(ref x) => &x[..],
        None => ""
      };

      for rcpt in m.tos {
        match rcpt {
          Destination::Local(user) => {
            let unew = format!("{}/{}/new", settings.deliverydir, user);
            fs::create_dir_all(&unew).unwrap();
            // Panic on crazy paths. Should not happen, ever.
            let npath = format!("{}/{}", unew, &fname);
            let tmp = NamedTempFile::new_in(&*tmpdir).unwrap();
            let data_len = m.tmpfile.metadata().unwrap().len() as usize;
            assert!(sendfile::sendfile(tmp.as_raw_fd(), m.tmpfile.as_raw_fd(), Some(&mut 0), data_len).unwrap() == data_len);
            tmp.persist_noclobber(&npath).unwrap();
          },
          Destination::Remote(address) => {
            let path = format!("{}/{}", settings.queuedir, fname);
            // We also fail when we are not able to create temporary file. Something like 451 might be better,
            // but again, if it happens we are likely screwed enough anyway.
            let mut tmp = NamedTempFile::new_in(&*tmpdir).unwrap();
            write!(&mut tmp, "MAIL FROM: <{}>\n", from).unwrap();
            write!(&mut tmp, "RCPT TO: <{}>\n", address).unwrap();
            write!(&mut tmp, "DATA\n").unwrap();
            // Fail also if we are not able to get temporary file' length.
            let data_len = m.tmpfile.metadata().unwrap().len() as usize;
            assert!(sendfile::sendfile(tmp.as_raw_fd(), m.tmpfile.as_raw_fd(), Some(&mut 0), data_len).unwrap() == data_len);
            tmp.persist_noclobber(path).unwrap();
          },
        }
      }
    }

    let stat = match mnsession {
      Some(nsession) => {
        // FIXME: we re-create Box here, but I feel there's a better way.
        // Ask on IRC: suppose I have a Box and I want to transfer ownership
        // of an object inside to somewhere which returns `Option<Object>`.
        // If I got the result, I want current Box to be mutated into it without
        // re-allocation.
        // The key there is "transfer ownership" -- I can always use `&mut self`,
        // but this feels inelegant...
        assert!(sessions.lock().unwrap().insert(fd, Box::new(nsession)).is_none());
        true
      },
      None => false
    };

    let mut resbuf = Vec::new();
    resbuf.resize(mem::size_of::<ProcessResult>(), 0);
    unsafe {
      let resp: *mut ProcessResult = mem::transmute(resbuf.as_mut_ptr());
      *resp = ProcessResult {
        fd: fd,
        timerfd: timerfd,
        result: stat,
      }
    }
    mqueue::mq_send(back_w, &resbuf, 0).unwrap();
  }
}

fn main() {
  if env::args().count() != 2 {
    panic!(format!("Usage: {} config-file.json", env::args().nth(0).unwrap()));
  }

  unsafe {
    let action = SigAction::new(SigHandler::Handler(handle_signal), signal::SockFlag::empty(), SigSet::empty());
    let _ = signal::sigaction(signal::SIGINT, &action).unwrap();
    let _ = signal::sigaction(signal::SIGTERM, &action).unwrap();
  }

  let config: Arc<Settings> = {
    let path = env::args().nth(1).unwrap();
    let mut f = File::open(path).unwrap();
    let mut s = String::new();
    f.read_to_string(&mut s).unwrap();
    Arc::new(json::decode(&s).unwrap())
  };
  let origin = Arc::new(config.origin.clone());
  let logger = Arc::new(Logger::new(config.queues_len).unwrap());
  let tmpdir = Arc::new(PathBuf::from(config.tmpdir.clone()));
  let timeout = {
    let total_nsecs = (config.timeout as u64) * 1000000;
    Arc::new(ITimerSpec {
      it_interval: timespec {
        tv_sec: 0,
        tv_nsec: 0,
      },
      it_value: timespec {
        tv_sec: (total_nsecs / 1000000000) as i64,
        tv_nsec: (total_nsecs % 1000000000) as i64,
      },
    })
  };

  fs::create_dir_all(&config.deliverydir).unwrap();
  unistd::chown(&config.deliverydir[..], config.user, config.group).unwrap();
  fs::create_dir_all(&config.queuedir).unwrap();
  unistd::chown(&config.queuedir[..], config.user, config.group).unwrap();
  fs::create_dir_all(&config.tmpdir).unwrap();
  unistd::chown(&config.tmpdir[..], config.user, config.group).unwrap();

  let sock = socket::socket(AddressFamily::Inet6, SockType::Stream, SockFlag::empty(), 0).unwrap();
  socket::bind(sock, &SockAddr::new_inet(InetAddr::new(IpAddr::new_v6(0, 0, 0, 0, 0, 0, 0, 0), config.port))).unwrap();

  match config.group {
    Some(gid) => unistd::setgid(gid).unwrap(),
    None => {}
  }
  match config.user {
    Some(uid) => unistd::setuid(uid).unwrap(),
    None => {}
  }
  
  let req_attr = MqAttr::new(0, config.queues_len as c_long, mem::size_of::<RawFd>() as c_long, 0);
  let req_qname = CString::new(format!("/{}_request", unistd::getpid())).unwrap();
  let req_w = mqueue::mq_open(&req_qname, mqueue::O_CREAT | mqueue::O_EXCL | mqueue::O_WRONLY, stat::S_IRWXU, Some(&req_attr)).unwrap();

  let back_attr = MqAttr::new(0, config.queues_len as c_long, mem::size_of::<ProcessResult>() as c_long, 0);
  let back_qname = CString::new(format!("/{}_feedback", unistd::getpid())).unwrap();
  let back_r = mqueue::mq_open(&back_qname, mqueue::O_CREAT | mqueue::O_EXCL | mqueue::O_RDONLY, stat::S_IRWXU, Some(&back_attr)).unwrap();

  let sessions = Arc::new(Mutex::new(BTreeMap::new()));

  let threads = {
    let req_r = mqueue::mq_open(&req_qname, mqueue::O_RDONLY, stat::S_IRWXU, None).unwrap();
    let back_w = mqueue::mq_open(&back_qname, mqueue::O_WRONLY, stat::S_IRWXU, None).unwrap();
    Vec::from_iter((0..config.nthreads).map(|_| {
      // FIXME: is there a better way?
      let config_cp = config.clone();
      let tmpdir_cp = tmpdir.clone();
      let sessions_cp = sessions.clone();
      thread::spawn(move || { process(req_r.clone(), back_w.clone(), config_cp, tmpdir_cp, sessions_cp) })
    }))
  };

  mqueue::mq_unlink(&req_qname).unwrap();
  mqueue::mq_unlink(&back_qname).unwrap();

  socket::listen(sock, 0).unwrap();

  let mut fds = BTreeSet::new();
  let mut timer_fds = BTreeMap::new();
  let mut rev_timer_fds = BTreeMap::new();
  let mut afds = FdSet::new();
  afds.insert(sock);
  afds.insert(back_r);
  let mut tfds = FdSet::new();
  tfds.insert(back_r);

  while !SIGNAL_GOT.load(atomic::Ordering::Relaxed) {
    let mut cafds = afds.clone();

    let nfds = {
      let smax = max(sock, back_r);
      // FIXME: see #31690
      let fmax = fds.iter().max().map_or(smax, |x| max(smax, *x));
      let tmax = timer_fds.iter().max().map_or(fmax, |(k, _)| max(fmax, *k));
      tmax + 1
    };
    
    match select::pselect(nfds, Some(&mut cafds), None, None, None, None) {
      Ok(_) => {},
      Err(Error::Sys(Errno::EINTR)) => continue,
      Err(e) => panic!("Error on select: {}", e),
    }

    let fired = Vec::from_iter(fds.iter().filter(|&&fd| cafds.contains(fd)).map(|&fd| fd));
    for fd in fired {
      if cafds.contains(fd) {
        let mut fdbuf = Vec::new();
        fdbuf.resize(mem::size_of::<RawFd>(), 0);
        unsafe {
          let fdp: *mut RawFd = mem::transmute(fdbuf.as_mut_ptr());
          *fdp= fd;
        };
        mqueue::mq_send(req_w, &fdbuf, 0).unwrap();
        // XXX: Notice that we don't remove rev_timer_fds here -- we can cleanup
        // it later if really needed.
        let timerfd = rev_timer_fds[&fd];
        // TODO: ICE on assert! here
        assert!(fds.remove(&fd));
        afds.remove(fd);
        assert!(timer_fds.remove(&timerfd).is_some());
        afds.remove(timerfd);
      }
    }

    let timeouted = Vec::from_iter(timer_fds.iter().filter(|&(&timerfd, _)| cafds.contains(timerfd)).map(|(&timerfd, &fd)| (timerfd, fd)));
    for (timerfd, fd) in timeouted {
      if cafds.contains(timerfd) {
        let session = sessions.lock().unwrap().remove(&fd).unwrap();
        session.timeouted();
        assert!(fds.remove(&fd));
        afds.remove(fd);
        assert!(timer_fds.remove(&timerfd).is_some());
        afds.remove(timerfd);
        assert!(rev_timer_fds.remove(&fd).is_some());
      }
    }

    if cafds.contains(back_r) {
      // See issue #322 -- not nice!
      let mut resbuf = Vec::new();
      resbuf.resize(mem::size_of::<ProcessResult>(), 0);
      // As usual, panic on syscall errors.
      let sz = mqueue::mq_receive(back_r, &mut resbuf, 0).unwrap();
      assert!(sz == mem::size_of::<ProcessResult>());
      let res = unsafe {
        let resp: *mut ProcessResult = mem::transmute(resbuf.as_ptr());
        &*resp
      };
      if res.result {
        assert!(fds.insert(res.fd));
        afds.insert(res.fd);
        assert!(timer_fds.insert(res.timerfd, res.fd).is_none());
        afds.insert(res.timerfd);
      } else {
        assert!(rev_timer_fds.remove(&res.fd).is_some());
      }
    }

    if cafds.contains(sock) {
      let nfd = socket::accept(sock).unwrap();
      match Session::new(nfd, tmpdir.clone(), logger.clone(), origin.clone(), timeout.clone()) {
        Ok(nsession) => {
          if nsession.fd >= select::FD_SETSIZE || nsession.timerfd >= select::FD_SETSIZE {
            nsession.not_ready();
          }
          else {
            match nsession.ready() {
              Some(rsession) => {
                assert!(fds.insert(rsession.fd));
                afds.insert(rsession.fd);
                assert!(timer_fds.insert(rsession.timerfd, rsession.fd).is_none());
                afds.insert(rsession.timerfd);
                assert!(rev_timer_fds.insert(rsession.fd, rsession.timerfd).is_none());
                sessions.lock().unwrap().insert(nfd, Box::new(rsession));
              },
              None => {},
            }
          }
        },
        Err(err) => {
          logger.error(&format!("Cannot create new session: {}", err)).unwrap();
          unistd::close(nfd).unwrap();
        }
      };
    }
  }

  unistd::close(sock).unwrap();

  mqueue::mq_close(back_r).unwrap();
  for _ in &threads {
    mqueue::mq_send(req_w, &[], 0).unwrap();
  }
  mqueue::mq_close(req_w).unwrap();

  for thread in threads {
    let _ = thread.join();
  }
}
