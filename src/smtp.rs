use std::io::{Write, Result};
use std::borrow::Cow;
use std::os::unix::io::RawFd;
use std::sync::Arc;
use std::path::PathBuf;
use std::str;
use std::mem;
use std::ffi::CString;
use regex::Regex;
use nix::unistd;
use nix::sys::timerfd;
use nix::sys::timerfd::{ITimerSpec, ClockId, TfFlag, TfTimerFlag};
use nix::sys::socket;
use nix::sys::socket::{SockAddr, InetAddr};
use tempfile::NamedTempFile;
use logger::Logger;
use resolv;
use resolv::{ResClass, ResType, NSMsg, NSSect};

#[derive(Debug)]
pub enum SMTPCommand<'t> {
  Helo(&'t str),
  Ehlo(&'t str),
  MailFrom(Option<&'t str>),
  RcptTo(&'t str),
  Data,
  Rset,
  Quit,
  Vrfy(&'t str),
}

#[derive(Eq, PartialEq, Clone, Copy, Debug)]
enum ReplyCode {
  ServiceReady = 220,
  ServiceClose = 221,
  Complete = 250,
  StartInput = 354,
  InternalError = 451,
  CmdSyntax = 500,
  ArgSyntax = 501,
  BadSequence = 503,
  Undeliverable = 554,
  Unavailable = 550,
}

// Most of those things can be done compile-time with a compile-time format!. Pity we don't have one...
lazy_static! {
  static ref LOCAL_PART_RREGEX: String = {
    // Raw e-mails (And no, we are not fully compliant here too. Want to parse the whole goodness?
    // Don't force your regexes on me!).
    let atom = r"[a-zA-Z0-9_-]+";
    let quoted_part = r#""(?:\.|[^"])*""#;
    let local_literal = format!(r"(?:{atom}|{quoted})", atom=atom, quoted=quoted_part);

    format!(r"(?:{literal}\.)*{literal}", literal=local_literal)
  };

  static ref IPV4_ADDR_RREGEX: String = {
    let snum = r"[0-9]{1,3}";

    format!(r"(?:{snum}\.){times}{snum}", snum=snum, times=r"{3}")
  };

  static ref ADDR_TAG_RREGEX: String = {
    r"[a-zA-Z0-9]+".to_string()
  };

  static ref ADDR_CONTENT_RREGEX: String = {
    r"[a-zA-Z0-9_:.-]+".to_string()
  };

  static ref DOMAIN_RREGEX: String = {
    // Domains (We are not fully RFC 3696-compliant here, nor we implement 5890/5892/5893).
    // I want to keep my sanity by *not* implementing those correctly as regular expressions!
    let domain_literal = r"[a-zA-Z0-9][a-zA-Z0-9_-]*";

    format!(r"(?:{literal}\.)*{literal}", literal=domain_literal)
  };

  static ref CMD_REGEX: Regex = {
    // IP addresses. Ugh.
    let ip_addr = format!(r"(?:{ipv4_addr}|{tag}:{dcontent})",
                          ipv4_addr=*IPV4_ADDR_RREGEX,
                          tag=*ADDR_TAG_RREGEX,
                          dcontent=*ADDR_CONTENT_RREGEX);
    let addr_domain = format!(r"(?:{domain}|\[{ip_addr}\])", domain=*DOMAIN_RREGEX, ip_addr=ip_addr);
    let address = format!(r"{local}@{addr_domain}", local=*LOCAL_PART_RREGEX, addr_domain=addr_domain);

    // Mailboxes. We don't support relay paths and other not-so-popular things. Because no.
    let to_address = format!(r"(?:(?i:postmaster)|{address})", address=address);

    // Actual SMTP commands. Some of them.
    let helo_cmd = format!(r"(?P<helo>(?i)HELO) (?P<helo_domain>{domain})", domain=*DOMAIN_RREGEX);
    let ehlo_cmd = format!(r"(?P<ehlo>(?i)EHLO) (?P<ehlo_domain>{domain})", domain=*DOMAIN_RREGEX);
    let mail_cmd = format!(r"(?P<mail>(?i)MAIL FROM):<(?P<from_address>{from_address})?>", from_address=address);
    let rcpt_cmd = format!(r"(?P<rcpt>(?i)RCPT TO):<(?P<to_address>{to_address})>", to_address=to_address);
    let data_cmd = r"(?P<data>(?i)DATA)";
    let rset_cmd = r"(?P<rset>(?i)RSET)";
    let quit_cmd = r"(?P<quit>(?i)QUIT)";
    let vrfy_cmd = r"(?P<vrfy>(?i)VRFY) (?P<vrfy_string>.+)";

    // Bringing them together and compiling.
    let cmds: &[&str] = &[&helo_cmd, &ehlo_cmd, &mail_cmd, &rcpt_cmd, data_cmd, rset_cmd, quit_cmd, vrfy_cmd];
    // Would be nice to have a `foldr1`...
    let open_regex = {
      let mut re = cmds[0].to_string();
      for cmd in cmds.iter().skip(1) {
        re = format!(r"{}|{}", re, cmd);
      }
      re
    };
    // Finally!...
    let regex = format!(r"^(?:{})$", open_regex);

    Regex::new(&regex).unwrap()
  };

  static ref ADDR_REGEX: Regex = {
    let ip_addr = format!(r"(?:(?P<ipv4>{ipv4_addr})|(?P<tag>{tag}):(?P<dcontent>{dcontent}))",
                          ipv4_addr=*IPV4_ADDR_RREGEX,
                          tag=*ADDR_TAG_RREGEX,
                          dcontent=*ADDR_CONTENT_RREGEX);
    let addr_domain = format!(r"(?:(?P<domain>{domain})|\[{ip_addr}\])", domain=*DOMAIN_RREGEX, ip_addr=ip_addr);
    let address = format!(r"^(?P<local>{local})@{addr_domain}$", local=*LOCAL_PART_RREGEX, addr_domain=addr_domain);

    Regex::new(&address).unwrap()
  };

  static ref EXTS_STRING: String = {
    const EXTS: &'static [&'static str] = &[ "PIPELINING", "SMTPUTF8" ]; // By design
    let mut res = String::new();
    for e in EXTS {
      res.push('\n');
      res.push_str(e);
    }

    return res;
  };
}

impl<'t> SMTPCommand<'t> {
  pub fn parse(cmd: &'t str) -> Option<SMTPCommand<'t>> {
    CMD_REGEX.captures(cmd).map(|res| {
      if res.name("helo").is_some() {
        let domain = res.name("helo_domain").unwrap();
        SMTPCommand::Helo(domain)
      } else if res.name("ehlo").is_some() {
        let domain = res.name("ehlo_domain").unwrap();
        SMTPCommand::Ehlo(domain)
      } else if res.name("mail").is_some() {
        let address = res.name("from_address");
        SMTPCommand::MailFrom(address)
      } else if res.name("rcpt").is_some() {
        let address = res.name("to_address").unwrap();
        SMTPCommand::RcptTo(address)
      } else if res.name("data").is_some() {
        SMTPCommand::Data
      } else if res.name("rset").is_some() {
        SMTPCommand::Rset
      } else if res.name("quit").is_some() {
        SMTPCommand::Quit
      } else if res.name("vrfy").is_some() {
        let string = res.name("vrfy_string").unwrap();
        SMTPCommand::Vrfy(string)
      } else {
        unreachable!()
      }
    })
  }
}

#[derive(Eq, PartialEq, Clone, Debug)]
enum Status {
  Accepted,
  Connected,
  Greeted,
  InSession,
  ReceivingData,
}

enum Origin<'t> {
  Domain(&'t str),
  IPv4(&'t str),
  General(&'t str, &'t str),
}

struct Address<'t> {
  local: &'t str,
  origin: Origin<'t>,
}

pub enum Destination {
  Local(String),
  Remote(String),
}

impl<'t> Address<'t> {
  pub fn parse(addr: &'t str) -> Option<Address<'t>> {
    ADDR_REGEX.captures(addr).map(|res| {
      let origin =
        if let Some(domain) = res.name("domain") {
          Origin::Domain(domain)
        } else if let Some(ipv4) = res.name("ipv4") {
          Origin::IPv4(ipv4)
        } else if let Some(tag) = res.name("tag") {
          let dcontent = res.name("dcontent").unwrap();
          Origin::General(tag, dcontent)
        } else {
          unreachable!()
        };
      let local = res.name("local").unwrap();
      Address {
        local: local,
        origin: origin,
      }
    })
  }
}

pub struct Message {
  pub from: Option<String>,
  pub tos: Vec<Destination>,
  pub tmpfile: NamedTempFile,
}

type Reply = (ReplyCode, Cow<'static, str>);
type StepResult = (bool, Vec<Message>);
type CommandResult = (bool, Option<Message>);

pub struct Session {
  pub fd: RawFd,
  tmpdir: Arc<PathBuf>,
  origin: Arc<String>,
  logger: Arc<Logger>,
  timeout: Arc<ITimerSpec>,
  pub timerfd: RawFd,
  status: Status,
  domain: Option<String>,
  from: Option<String>,
  tos: Vec<Destination>,
  tmpfile: Option<NamedTempFile>,
  buffer: String,
}

impl Drop for Session {
  fn drop(&mut self) {
    unistd::close(self.fd).unwrap();
    unistd::close(self.timerfd).unwrap();
  }
}

impl Session {
  pub fn new(fd: RawFd, tmpdir: Arc<PathBuf>, logger: Arc<Logger>, origin: Arc<String>, timeout: Arc<ITimerSpec>) -> Result<Session> {
    let timerfd = try!(timerfd::timerfd_create(ClockId::Monotonic, TfFlag::empty()));
    let mut s = Session {
      fd: fd,
      tmpdir: tmpdir,
      origin: origin,
      logger: logger,
      timeout: timeout,
      timerfd: timerfd,
      status: Status::Accepted,
      domain: None,
      from: None,
      tos: Vec::new(),
      tmpfile: None,
      buffer: String::new(),
    };
    try!(s.rearm_timeout());
    Ok(s)
  }

  pub fn ready(mut self) -> Option<Self> {
    if self.status != Status::Accepted {
      panic!("This session has already started");
    }
    if !self.send_reply(ReplyCode::ServiceReady, "Service ready") {
      return None;
    }

    self.status = Status::Connected;
    Some(self)
  }

  pub fn not_ready(mut self) {
    if self.status != Status::Accepted {
      panic!("This session has already started");
    }
    // XXX: This is not fully RFC-compliant -- in fact, there is no defined way
    // to just "end" the connection. But I think "some" message is better than
    // plain FIN.
    let _ = self.send_reply(ReplyCode::Undeliverable, "Not accepting new connections");
  }

  pub fn timeouted(mut self) {
    match self.status {
      Status::Accepted => panic!("Timeout before connection is accepted"),
      _ => {
        let _ = self.send_reply(ReplyCode::Undeliverable, "Timeout");
      }
    }
  }

  fn rearm_timeout(&mut self) -> Result<()> {
    try!(timerfd::timerfd_settime(self.timerfd, TfTimerFlag::empty(), &*self.timeout, None));
    Ok(())
  }

  pub fn message_step(mut self, buf: &[u8]) -> Result<(Vec<Message>, Option<Self>)> {
    match self.status {
      // Close on premature sends
      Status::Accepted => {
        self.log('E', &format!("Premature send"));
        Ok((Vec::new(), None))
      },
      _ => {
        try!(self.rearm_timeout());
        // We now drop the connection immediately on receiving invalid UTF-8 sequence.
        // This may be suboptimal, but oh well...
        match str::from_utf8(buf) {
          Ok(sbuf) => {
            self.buffer.push_str(sbuf);
            // TODO: this should be optimal (String::new just clears pointers), but better
            // check later.
            let mut buf = String::new();
            mem::swap(&mut self.buffer, &mut buf);
            let ((still_connected, msgs), taken) = self.buffer_step(&buf);

            buf.drain(0..taken);
            self.buffer = buf;
            let ret = if still_connected { Some(self) } else { None };
            Ok((msgs, ret))
          },
          Err(err) => {
            self.log('E', &format!("UTF-8 decoding error: {}", err));
            Ok((Vec::new(), None))
          }
        }
      }
    }
  }

  fn log(&self, level: char, s: &str) {
    // XXX: We better crash loudly if there's something wrong with the logging
    self.logger.log(level, s).unwrap()
  }

  fn send_reply(&mut self, code: ReplyCode, msg: &str) -> bool {
    self.log('I', &format!("Sending reply {:?}: {}\n", code, msg));
    let try_send = || -> Result<()> {
      let mut mmsg = msg;
      while let Some(pos) = mmsg.find('\n') {
        let (curr, next) = mmsg.split_at(pos);
        let send = format!("{}-{}\r\n", code as u16, curr).into_bytes();
        assert!(try!(unistd::write(self.fd, &send)) == send.len());
        mmsg = &next[1..];
      }
      let send = format!("{} {}\r\n", code as u16, mmsg).into_bytes();
      assert!(try!(unistd::write(self.fd, &send)) == send.len());
      Ok(())
    };

    match (try_send)() {
      Ok(()) => true,
      Err(err) => {
        self.log('E', &format!("Failed to send reply: {:?}", err));
        false
      }
    }
  }

  fn clear_session(&mut self) {
    self.status = Status::Greeted;
    self.from = None;
    self.tos.clear();
    self.tmpfile = None;
  }

  fn helo(&mut self, domain: &str, ehlo: bool) -> Reply {
    let SockAddr::Inet(addr) = socket::getpeername(self.fd).unwrap();
    let domain = match addr {
      InetAddr::V4(v4) => {
        const offsets: &'static [u32] = &[0, 8, 16, 24];
        let mut s = String::new();
        for off in offsets.iter().rev() {
          let oct = (v4.sin_addr.s_addr >> off) & 0xFF;
          s = format!("{}{}.", s, oct);
        }
        s.push_str("in-addr.arpa");
        s
      },
      InetAddr::V6(v6) => {
        let mut s = String::new();
        for oct in v6.sin6_addr.s6_addr.iter().rev() {
          s = format!("{}{}.{}", s, oct >> 8, oct & 0xF);
        }
        s.push_str("ip6.arpa");
        s
      },
    };
    let raw_res_r = resolv::res_search(&CString::new(domain).unwrap(), ResClass::In, ResType::PTR);
    match raw_res_r {
      Ok(raw_res) => {
        // XXX: We shouldn't fail here, so let's crash if we do.
        let msg = NSMsg::initparse(&raw_res[..]).unwrap();
        //for i in 0..msg.msg_count(NSSect::AN_PR) {
        //  let rr = msg.parserr(NSSect::AN_PR, i).unwrap();
        //  println!("PTR answer: {}", resolv::print(&msg, &rr, None, None).unwrap());
        //}
      },
      Err(e) => {
        //self.log('E', &format!("Cannot resolve DNS PTR hostname: {}", e));
      }
    }
    self.domain = Some(domain.to_owned());
    self.clear_session();

    let mut resp = format!("{} greets {}", self.origin, domain);
    if ehlo {
      resp.push_str(&EXTS_STRING);
    }
    (ReplyCode::Complete, Cow::Owned(resp))
  }

  fn command_step<'tt>(&mut self, cmd: &SMTPCommand<'tt>) -> Result<(Reply, CommandResult)> {
    self.log('I', &format!("input message: {:?}", cmd));
    match *cmd {
      SMTPCommand::Helo(domain) => {
        Ok((self.helo(domain, false), (true, None)))
      },
      SMTPCommand::Ehlo(domain) => {
        Ok((self.helo(domain, true), (true, None)))
      },
      SMTPCommand::MailFrom(from) if self.status == Status::Greeted => {
        self.from = from.map(|x| x.to_owned());
        self.status = Status::InSession;
        Ok(((ReplyCode::Complete, Cow::Borrowed("OK")), (true, None)))
      },
      SMTPCommand::RcptTo(to) if self.status == Status::InSession => {
        // FIXME: handle our local IP address
        let dest = match Address::parse(to) {
          None => return Ok(((ReplyCode::ArgSyntax, Cow::Borrowed("Invalid e-mail address")), (true, None))),
          Some(addr) => match addr.origin {
            Origin::Domain(domain) if domain == *self.origin => Destination::Local(addr.local.to_owned()),
            _ => Destination::Remote(to.to_owned()),
          }
        };
        self.tos.push(dest);
        Ok(((ReplyCode::Complete, Cow::Borrowed("OK")), (true, None)))
      },
      SMTPCommand::Data if self.status == Status::InSession && self.tos.len() > 0 => {
        self.tmpfile = Some(try!(NamedTempFile::new_in(&*self.tmpdir)));
        self.status = Status::ReceivingData;
        Ok(((ReplyCode::StartInput, Cow::Borrowed("Start mail input; end with <CRLF>.<CRLF>")), (true, None)))
      },
      SMTPCommand::Rset if self.status != Status::Connected => {
        self.clear_session();
        Ok(((ReplyCode::Complete, Cow::Borrowed("OK")), (true, None)))
      },
      SMTPCommand::Quit => {
        Ok(((ReplyCode::ServiceClose, Cow::Borrowed("Bye bye")), (false, None)))
      },
      SMTPCommand::Vrfy(_) if self.status != Status::Connected => {
        Ok(((ReplyCode::Unavailable, Cow::Borrowed("Access denied")), (true, None)))
      },
      _ => {
        Ok(((ReplyCode::BadSequence, Cow::Borrowed("Bad command sequence")), (true, None)))
      },
    }
  }

  fn chunk_step(&mut self, chunk: &str) -> CommandResult {
    let ((code, reply), (connected, msg)) = match SMTPCommand::parse(chunk) {
      None => {
        ((ReplyCode::CmdSyntax, Cow::Borrowed("Invalid command")), (true, None))
      }

      Some(cmd) => {
        match self.command_step(&cmd) {
          Ok(cmd_ret) => cmd_ret,
          Err(err) => {
            self.log('E', &format!("Internal error: {}", err));
            ((ReplyCode::InternalError, Cow::Borrowed("Internal error")), (true, None))
          },
        }
      }
    };

    let rsuccess = self.send_reply(code, &*reply);
    (connected && rsuccess, msg)
  }

  fn write_data(&mut self, buf: &str) -> bool {
    let ret = match self.tmpfile.as_mut().unwrap().write_all(buf.as_bytes()) {
      Ok(()) => true,
      Err(err) => {
        self.log('E', &format!("Internal error while writing a file: {}", err));
        false
      }
    };

    if !ret {
      self.clear_session();
      if !self.send_reply(ReplyCode::InternalError, "Internal error") {
        return false;
      }
    }

    return true;
  }

  // FIXME: we shouldn't use &str here, really -- this is right for commands, but wrong for DATA.
  fn buffer_step(&mut self, buf: &str) -> (StepResult, usize) {
    const CMD_STOP: &'static str = "\r\n";
    const DATA_STOP: &'static str = "\r\n.\r\n";

    if buf.is_empty() {
      return ((true, Vec::new()), 0)
    }

    if self.status == Status::ReceivingData {
      match buf.find(DATA_STOP) {
        Some(pos) => {
          let taken = pos + DATA_STOP.len();
          let wres = self.write_data(&buf[..pos]);

          if wres {
            // This looks this way for atomiticity -- even if something goes wrong,
            // Drop instance of Session should get consistent state. In the presence
            // of panics, we can't guarantee this without swaps.
            let mut ofrom = None;
            let mut otos = Vec::new();
            let mut otmpfile = None;

            mem::swap(&mut ofrom, &mut self.from);
            mem::swap(&mut otos, &mut self.tos);
            mem::swap(&mut otmpfile, &mut self.tmpfile);

            let msg = Message {
              from: ofrom,
              tos: otos,
              tmpfile: otmpfile.unwrap(),
            };

            self.status = Status::Greeted;

            // FIXME: This is a little lie -- we haven't yet _fully_ processed the message.
            if !self.send_reply(ReplyCode::Complete, "OK") {
              ((false, vec!(msg)), taken)
            } else {
              let ((res, mut nmsgs), ntaken) = self.buffer_step(&buf[taken..]);
              nmsgs.push(msg);
              ((res, nmsgs), taken + ntaken)
            }
          } else {
            ((false, Vec::new()), taken)
          }
        },

        None => {
          // XXX: this is a hack to not skip actual "\r\n.\r\n" sequence -- we leave several
          // characters from an end in the buffer.
          let taken = if buf.len() >= DATA_STOP.len() - 1 { buf.len() - (DATA_STOP.len() - 1) } else { 0 };
          let conn = self.write_data(&buf[..taken]);
          ((conn, Vec::new()), taken)
        },
      }
    } else {
      match buf.find(CMD_STOP) {
        Some(pos) => {
          let chunk = &buf[..pos];
          let (res, mmsg) = self.chunk_step(chunk);
          let taken = pos + CMD_STOP.len();
          if res {
            let ((res, mut nmsgs), ntaken) = self.buffer_step(&buf[taken..]);
            match mmsg {
              Some(msg) => nmsgs.push(msg),
              None => {},
            };
            ((res, nmsgs), taken + ntaken)
          } else {
            let msgs = match mmsg {
              Some(msg) => vec!(msg),
              None => Vec::new(),
            };
            ((res, msgs), taken)
          }
        },
      
        None => {
          ((true, Vec::new()), 0)
        },
      }
    }
  }

}
