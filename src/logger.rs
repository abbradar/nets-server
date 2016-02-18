use std::ffi::CString;
use std::process;
use std::io;
use std::cmp;
use std::io::{Result, Write};
use libc::c_long;
use time;
use nix::{unistd, mqueue};
use nix::mqueue::MqAttr;
use nix::unistd::Fork;
use nix::sys::stat;
use nix::sys::stat::Mode;

const MSGSIZE: usize = 1024;
    
pub struct Logger {
  queue: mqueue::MQd,
}

impl Logger {
  pub fn new(queue_len: usize) -> Result<Logger> {
    let name = CString::new(format!("/{}_logger", unistd::getpid())).unwrap();
    let attr = MqAttr::new(0, queue_len as c_long, MSGSIZE as c_long, 0);
    let queue_wr = try!(mqueue::mq_open(&name, mqueue::O_CREAT | mqueue::O_EXCL | mqueue::O_WRONLY,
                                        stat::S_IRUSR | stat::S_IWUSR, Some(&attr)));
    match try!(unistd::fork()) {
      Fork::Parent(_) => {
        let logger = Logger {
          queue: queue_wr,
        };
        Ok(logger)
      }

      Fork::Child => {
        try!(mqueue::mq_close(queue_wr));
        let queue_rd = try!(mqueue::mq_open(&name, mqueue::O_RDONLY, Mode::empty(), None));
        try!(mqueue::mq_unlink(&name));

        let mut buf = Vec::new();
        buf.resize(MSGSIZE, 0);
        let mut fd = io::stderr();
        loop {
          let sz = mqueue::mq_receive(queue_rd, &mut buf, 0).unwrap();
          if sz == 0 {
            process::exit(0);
          }
          fd.write(&buf[..sz]).unwrap();
        }
      }
    }
  }

  // TODO: convert this to non-recursive, since Rust doesn't have TCO (maybe LLVM will kick in?).
  fn raw_write(&self, msg: &[u8]) -> Result<()> {
    try!(mqueue::mq_send(self.queue, &msg[..cmp::min(MSGSIZE, msg.len())], 0));
    if msg.len() > MSGSIZE {
      self.raw_write(&msg[MSGSIZE..])
    } else {
      Ok(())
    }
  }

  pub fn log(&self, level: char, msg: &str) -> Result<()> {
    let time = time::at(time::get_time());
    let rmsg = format!("{level} {time}: {msg}\n", level=level, time=time::strftime("%F %T", &time).unwrap(), msg=msg);
    self.raw_write(rmsg.as_bytes())
  }

  pub fn info(&self, msg: &str) -> Result<()> {
    self.log('I', msg)
  }

  pub fn warning(&self, msg: &str) -> Result<()> {
    self.log('W', msg)
  }

  pub fn error(&self, msg: &str) -> Result<()> {
    self.log('E', msg)
  }
}

impl Drop for Logger {
  fn drop(&mut self) {
    self.raw_write(&[]).unwrap();
    mqueue::mq_close(self.queue).unwrap();
  }
}
