use winrt_notification::{Toast, Sound, Duration};
use std::env;

fn main() {
    for argument in env::args() {
        println!("arg {}", argument);
    }
    let arguments: Vec<String> = env::args().collect();
    if env::args().len() > 2 {
    Toast::new(Toast::POWERSHELL_APP_ID)
        .title(&arguments[1])
        .text1(&arguments[2])
        .sound(Some(Sound::SMS))
        .duration(Duration::Short)
        .show()
        .expect("unable to toast");
    } else {
        println!("bad number of args");
    }

}
