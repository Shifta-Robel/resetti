use slog::{Drain, Record, LevelFilter, Logger, o};
use slog_term::{PlainDecorator, TermDecorator, FullFormat, CompactFormat};
use slog_scope::{set_global_logger, GlobalLoggerGuard};

use crate::configs::LogConfig;

pub fn init_logger(log_conf: LogConfig) -> GlobalLoggerGuard {
    let drain = match log_conf.log_file{
        Some(file) => {
            let decorator = PlainDecorator::new(file);
            let drain = FullFormat::new(decorator).build().fuse();
            slog_async::Async::new(drain).build().fuse()
        },
        None =>{
            let decorator = TermDecorator::new().build();
            let drain = CompactFormat::new(decorator).build().fuse();
            slog_async::Async::new(drain).build().fuse()
        }
    };

    println!("log-level: {:?}",log_conf.log_level);
    let logger = match log_conf.log_level{
        Some(l) => {
            let drain = LevelFilter::new(drain, l).fuse();
            Logger::root(drain, o!())
        },
        None => {
            let drain = drain.filter(|_: &Record| false).fuse();
            Logger::root(drain, o!())
        }
    };

    set_global_logger(logger)
}
