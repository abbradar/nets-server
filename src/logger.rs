use std::ffi::CString;
use std::process;
use std::io;
use std::io::{Result, Write, Error, ErrorKind};
use time::SteadyTime;
use nix::{unistd, mqueue};
use nix::unistd::Fork;
use nix::sys::stat;
use nix::sys::stat::Mode;

pub struct Logger {
  queue: mqueue::MQd,
}

impl Logger {
  pub fn new() -> Result<Logger> {
    let name = CString::new(format!("/{}_logger", unistd::getpid())).unwrap();
    let queue_wr = try!(mqueue::mq_open(&name, mqueue::O_CREAT | mqueue::O_EXCL | mqueue::O_WRONLY, stat::S_IRWXU, None));
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

        let mut buf = Vec::with_capacity(1024);
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

  fn raw_write(&self, msg: &str) -> Result<()> {
    let sz = try!(mqueue::mq_send(self.queue, msg.as_bytes(), 0));
    if sz != msg.len() {
      Err(Error::new(ErrorKind::Other, "Message has not been sent completely"))
    } else {
      Ok(())
    }
  }

  pub fn log(&self, level: char, msg: &str) -> Result<()> {
    let time = SteadyTime::now();
    let rmsg = format!("{level} {time}: {msg}\n", level=level, time=time, msg=msg);
    self.raw_write(&rmsg)
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
    self.raw_write("").unwrap();
    mqueue::mq_close(self.queue).unwrap();
  }
}
