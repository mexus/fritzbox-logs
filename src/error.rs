use chrono;
use std::io;
use std::num::ParseIntError;

quick_error! {
    #[derive(Debug)]
    pub enum Error {
         /// IO error.
         Io(err: io::Error){
             from()
             cause(err)
         }
         /// Formatting error.
         RegexFormat(line: String, descr: String) {
             display("While parsing {} regex has failed ({})", line, descr)
         }
         /// Internal error in the regex engine.
         RegexInternal(descr: String) {
             display("Internal regex error has happened: {}", descr)
         }
         /// An error from the `chrono` crate.
         ChronoParse(err: chrono::ParseError) {
             from()
             cause(err)
         }
         /// Parse error (integer).
         ParseInt(err: ParseIntError) {
             from()
             cause(err)
         }
    }
}
