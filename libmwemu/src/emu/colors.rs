#[derive(Clone)]
pub struct Colors {
    pub black: String,
    pub red: String,
    pub green: String,
    pub orange: String,
    pub blue: String,
    pub purple: String,
    pub cyan: String,
    pub light_gray: String,
    pub dark_gray: String,
    pub light_red: String,
    pub light_green: String,
    pub yellow: String,
    pub light_blue: String,
    pub light_purple: String,
    pub light_cyan: String,
    pub white: String,
    pub nc: String, // no_color
    pub clear_screen: String,
}

impl Colors {
    pub fn new() -> Colors {
        Colors {
            black: "\x1b[0;30m".to_string(),
            red: "\x1b[0;31m".to_string(),
            green: "\x1b[0;32m".to_string(),
            orange: "\x1b[0;33m".to_string(),
            blue: "\x1b[0;34m".to_string(),
            purple: "\x1b[0;35m".to_string(),
            cyan: "\x1b[0;36m".to_string(),
            light_gray: "\x1b[0;37m".to_string(),
            dark_gray: "\x1b[1;30m".to_string(),
            light_red: "\x1b[1;31m".to_string(),
            light_green: "\x1b[1;32m".to_string(),
            yellow: "\x1b[1;33m".to_string(),
            light_blue: "\x1b[1;34m".to_string(),
            light_purple: "\x1b[1;35m".to_string(),
            light_cyan: "\x1b[1;36m".to_string(),
            white: "\x1b[1;37m".to_string(),
            nc: "\x1b[0m".to_string(), // no_color
            clear_screen: "\x1bc".to_string(),
        }
    }

    pub fn disable(&mut self) {
        self.black = "".to_string();
        self.red = "".to_string();
        self.green = "".to_string();
        self.orange = "".to_string();
        self.blue = "".to_string();
        self.purple = "".to_string();
        self.cyan = "".to_string();
        self.light_gray = "".to_string();
        self.dark_gray = "".to_string();
        self.light_red = "".to_string();
        self.light_green = "".to_string();
        self.yellow = "".to_string();
        self.light_blue = "".to_string();
        self.light_purple = "".to_string();
        self.light_cyan = "".to_string();
        self.white = "".to_string();
        self.nc = "".to_string();
    }
}
